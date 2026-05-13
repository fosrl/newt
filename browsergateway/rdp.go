package browsergateway

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/coder/websocket"
)

// HandleRDP is an http.HandlerFunc for RDP-over-WebSocket connections.
func (g *Gateway) HandleRDP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true, // any-origin: minimal dev proxy with no auth
		Subprotocols:       []string{"binary"},
	})
	if err != nil {
		log.Printf("websocket upgrade failed: %v", err)
		return
	}
	// Disable per-message read size cap (default is 32 KiB which would break
	// large RDP graphics messages).
	ws.SetReadLimit(-1)
	defer ws.CloseNow() //nolint:errcheck

	if err := g.serveSession(ctx, ws); err != nil {
		log.Printf("session error: %v", err)
	}
}

func (g *Gateway) serveSession(ctx context.Context, ws *websocket.Conn) error {
	// Expose the WebSocket as a streaming net.Conn. Binary messages are
	// concatenated into a byte stream and writes become single binary frames.
	// This is a thin wrapper with no per-message goroutine, unlike Gorilla.
	stream := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	defer stream.Close() //nolint:errcheck

	// -- Read the initial RDCleanPath request from the client --
	pdu, err := readCleanPath(stream)
	if err != nil {
		return fmt.Errorf("read RDCleanPath: %w", err)
	}

	if pdu.Destination == "" {
		return errors.New("RDCleanPath missing destination")
	}
	if len(pdu.X224) == 0 {
		return errors.New("RDCleanPath missing X224 connection PDU")
	}

	// Constant-time comparison to avoid leaking the expected token via timing.
	if subtle.ConstantTimeCompare([]byte(pdu.ProxyAuth), []byte(g.authToken)) != 1 {
		return errors.New("RDCleanPath ProxyAuth token mismatch")
	}

	target := pdu.Destination
	// Default port for RDP if not specified.
	if _, _, splitErr := net.SplitHostPort(target); splitErr != nil {
		target = net.JoinHostPort(target, "3389")
	}

	// Validate destination against the registered target allowlist.
	rdpHost, rdpPortStr, _ := net.SplitHostPort(target)
	rdpPort, _ := strconv.Atoi(rdpPortStr)
	if !g.isAllowed("rdp", rdpHost, rdpPort) {
		return fmt.Errorf("RDP destination %s is not in the allowed target list", target)
	}

	log.Printf("Connecting to RDP server %s", target)

	// -- Open TCP connection to the destination RDP server --
	serverTCP, err := net.DialTimeout("tcp", target, 15*time.Second)
	if err != nil {
		return fmt.Errorf("dial %s: %w", target, err)
	}
	defer serverTCP.Close()
	if tcp, ok := serverTCP.(*net.TCPConn); ok {
		// NoDelay is Go's default; set explicitly. RDP wants low latency for
		// input echo, and the bulk path is naturally chunked by TLS records.
		_ = tcp.SetNoDelay(true)
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(30 * time.Second)
		_ = tcp.SetReadBuffer(forwardBufSize)
		_ = tcp.SetWriteBuffer(forwardBufSize)
	}
	serverAddr := serverTCP.RemoteAddr().String()

	// Forward the optional pre-connection blob, then the X.224 connection request.
	if pdu.PreconnectionBlob != "" {
		if _, err := serverTCP.Write([]byte(pdu.PreconnectionBlob)); err != nil {
			return fmt.Errorf("send PCB: %w", err)
		}
	}
	if _, err := serverTCP.Write(pdu.X224); err != nil {
		return fmt.Errorf("send X224: %w", err)
	}

	// -- Read the X.224 connection confirm from the server --
	x224Rsp, err := readX224(serverTCP)
	if err != nil {
		return fmt.Errorf("read X224 response: %w", err)
	}
	logX224Negotiation(x224Rsp)

	// -- Upgrade the server connection to TLS (skip verification) --
	//
	// Windows RDP hosts are picky: only set SNI when the target is a hostname
	// (Go would skip SNI for IP literals anyway, but be explicit), and accept
	// the full range of TLS versions / ciphers since some servers only
	// negotiate TLS 1.0 or legacy suites.
	host, _, _ := net.SplitHostPort(target)
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // proxy intentionally skips verification
		MinVersion:         tls.VersionTLS10,
		// Cap at TLS 1.2: Windows RDP servers commonly send a TLS "internal_error"
		// alert when CredSSP/NLA is layered on top of a TLS 1.3 session.
		MaxVersion: tls.VersionTLS12,
	}
	if net.ParseIP(host) == nil {
		tlsCfg.ServerName = host
	}
	tlsConn := tls.Client(serverTCP, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		return fmt.Errorf("TLS handshake with server: %w", err)
	}
	log.Printf("Server TLS handshake OK (version=0x%04x cipher=0x%04x)",
		tlsConn.ConnectionState().Version, tlsConn.ConnectionState().CipherSuite)

	// Collect the raw DER server certificate chain to return to the client.
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return errors.New("server did not present any certificates")
	}
	chain := make([][]byte, 0, len(state.PeerCertificates))
	for _, c := range state.PeerCertificates {
		chain = append(chain, c.Raw)
	}

	// -- Send the RDCleanPath response back to the client --
	rsp, err := encodeRDCleanPathResponse(serverAddr, x224Rsp, chain)
	if err != nil {
		return fmt.Errorf("encode RDCleanPath response: %w", err)
	}
	if _, err := stream.Write(rsp); err != nil {
		return fmt.Errorf("write RDCleanPath response: %w", err)
	}

	log.Printf("RDCleanPath handshake complete, forwarding traffic to %s", serverAddr)

	// -- Two-way blind forwarding of the (now TLS-encrypted) RDP stream --
	return forward(stream, tlsConn)
}

// readCleanPath buffers bytes from the stream until a full RDCleanPath PDU has
// been received, then decodes it.
func readCleanPath(r io.Reader) (*rdCleanPathPdu, error) {
	buf := make([]byte, 0, 1024)
	tmp := make([]byte, 1024)
	for {
		total := detectRDCleanPathLength(buf)
		switch {
		case total == -2:
			return nil, errors.New("invalid RDCleanPath PDU")
		case total > 0 && len(buf) >= total:
			return decodeRDCleanPathRequest(buf[:total])
		}
		n, err := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			return nil, err
		}
	}
}

// readX224 reads exactly one TPKT-framed X.224 PDU from the server.
//
// The TPKT header is 4 bytes: version (0x03), reserved (0x00), and a u16
// big-endian total length that includes the header itself.
func readX224(r io.Reader) ([]byte, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	if hdr[0] != 0x03 {
		return nil, fmt.Errorf("unexpected TPKT version 0x%02x", hdr[0])
	}
	total := int(binary.BigEndian.Uint16(hdr[2:4]))
	if total < 4 || total > 4096 {
		return nil, fmt.Errorf("unreasonable TPKT length %d", total)
	}
	out := make([]byte, total)
	copy(out, hdr)
	if _, err := io.ReadFull(r, out[4:]); err != nil {
		return nil, err
	}
	return out, nil
}

// logX224Negotiation prints which RDP security protocol the server selected
// (or the failure code), to help diagnose handshake issues such as the server
// requiring NLA/CredSSP.
//
// X.224 Connection Confirm layout (RFC 1006 / [MS-RDPBCGR]):
//
//	bytes 0..3   TPKT header (03 00 LL LL)
//	byte  4      X.224 length indicator
//	byte  5      X.224 code (0xD0 = CC)
//	bytes 6..10  DST-REF, SRC-REF, class
//	byte  11     optional RDP Negotiation type (0x02 = response, 0x03 = failure)
//	byte  12     flags
//	bytes 13..14 length (little-endian, =8)
//	bytes 15..18 selected protocol / failure code (u32 little-endian)
func logX224Negotiation(pdu []byte) {
	if len(pdu) < 19 {
		log.Printf("X.224 response too short (%d bytes) to contain RDP negotiation", len(pdu))
		return
	}
	switch pdu[11] {
	case 0x02:
		proto := uint32(pdu[15]) | uint32(pdu[16])<<8 | uint32(pdu[17])<<16 | uint32(pdu[18])<<24
		name := "unknown"
		switch proto {
		case 0:
			name = "RDP (standard)"
		case 1:
			name = "SSL/TLS"
		case 2:
			name = "HYBRID (CredSSP/NLA)"
		case 8:
			name = "HYBRID_EX"
		}
		log.Printf("Server selected RDP protocol 0x%x (%s)", proto, name)
	case 0x03:
		code := uint32(pdu[15]) | uint32(pdu[16])<<8 | uint32(pdu[17])<<16 | uint32(pdu[18])<<24
		log.Printf("Server returned RDP negotiation failure code 0x%x", code)
	default:
		log.Printf("X.224 response has no RDP negotiation block (type=0x%02x)", pdu[11])
	}
}

// forward shuttles bytes between the two streams until either side closes.
func forward(a, b io.ReadWriteCloser) error {
	errc := make(chan error, 2)
	go func() {
		buf := make([]byte, forwardBufSize)
		_, err := io.CopyBuffer(a, b, buf)
		_ = a.Close()
		_ = b.Close()
		errc <- err
	}()
	go func() {
		buf := make([]byte, forwardBufSize)
		_, err := io.CopyBuffer(b, a, buf)
		_ = a.Close()
		_ = b.Close()
		errc <- err
	}()
	// Wait for one side to finish, then return.
	err := <-errc
	if errors.Is(err, io.EOF) || err == nil {
		return nil
	}
	return err
}
