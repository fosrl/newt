package browsergateway

import (
	"context"
	"crypto/subtle"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/coder/websocket"
)

const (
	vncDialTimeout    = 10 * time.Second
	vncKeepAlive      = 30 * time.Second
	vncForwardBufSize = 32 * 1024
)

// handleVNC proxies a noVNC WebSocket connection to a raw TCP VNC backend.
// It follows the same auth-token-in-query-param pattern as handleSSH.
//
// Query parameters:
//
//	authToken – shared secret matching the -auth-token flag
//	host      – VNC backend hostname or IP
//	port      – VNC backend port (default: 5900)
func (g *Gateway) handleVNC(w http.ResponseWriter, r *http.Request) {
	if subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("authToken")), []byte(g.authToken)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	host := r.URL.Query().Get("host")
	port := r.URL.Query().Get("port")
	if host == "" {
		http.Error(w, "missing host", http.StatusBadRequest)
		return
	}
	if port == "" {
		port = "5900"
	}
	vncPort, _ := strconv.Atoi(port)
	if !g.isAllowed("vnc", host, vncPort) {
		http.Error(w, "destination not allowed", http.StatusForbidden)
		return
	}
	target := net.JoinHostPort(host, port)

	// Accept the WebSocket. noVNC negotiates the "binary" subprotocol;
	// fall back gracefully when the client sends "base64" as well.
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
		Subprotocols:       []string{"binary", "base64"},
	})
	if err != nil {
		log.Printf("vnc: websocket upgrade failed: %v", err)
		return
	}
	ws.SetReadLimit(-1)
	defer ws.CloseNow() //nolint:errcheck

	ctx := r.Context()
	if err := serveVNC(ctx, ws, target); err != nil {
		log.Printf("vnc: session error (%s): %v", target, err)
	}
}

func serveVNC(ctx context.Context, ws *websocket.Conn, target string) error {
	// Dial the VNC backend TCP server.
	dialer := &net.Dialer{
		Timeout:   vncDialTimeout,
		KeepAlive: vncKeepAlive,
	}
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return err
	}
	defer conn.Close() //nolint:errcheck

	// Expose the WebSocket as a plain net.Conn byte stream (binary frames).
	stream := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	defer stream.Close() //nolint:errcheck

	// Proxy bidirectionally: VNC backend <-> browser.
	errc := make(chan error, 2)
	go func() {
		buf := make([]byte, vncForwardBufSize)
		_, err := io.CopyBuffer(conn, stream, buf)
		errc <- err
	}()
	go func() {
		buf := make([]byte, vncForwardBufSize)
		_, err := io.CopyBuffer(stream, conn, buf)
		errc <- err
	}()

	// Return when either direction closes.
	err = <-errc
	return err
}
