package netstack2

import (
	"context"
	"io"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// Both stacks of a netstack with proxying, the main one and the proxy's, must
// have SACK on and RACK off.
func TestNetstacksUseSACKWithoutRACK(t *testing.T) {
	dev, _, err := CreateNetTUN([]netip.Addr{netip.MustParseAddr("100.90.0.1")}, nil, 1280)
	if err != nil {
		t.Fatalf("CreateNetTUN: %v", err)
	}
	tn := dev.(*netTun)
	defer tn.Close()

	for name, s := range map[string]*stack.Stack{"main": tn.stack, "proxy": tn.proxyHandler.proxyStack} {
		var sack tcpip.TCPSACKEnabled
		if err := s.TransportProtocolOption(tcp.ProtocolNumber, &sack); err != nil {
			t.Fatalf("%s stack: read SACK option: %v", name, err)
		}
		if !sack {
			t.Errorf("%s stack: SACK is off, want on", name)
		}
		var recovery tcpip.TCPRecovery
		if err := s.TransportProtocolOption(tcp.ProtocolNumber, &recovery); err != nil {
			t.Fatalf("%s stack: read recovery option: %v", name, err)
		}
		if recovery != 0 {
			t.Errorf("%s stack: TCPRecovery is %#x, want 0 (RACK off)", name, recovery)
		}
	}
}

// A burst of losses that takes out everything in flight must cost about one
// retransmission timeout. With gVisor's RACK on, the sender here recovers
// only a few segments per timeout: the transfer needs about 50 timeouts and
// takes about 11 s instead of 0.25 s.
func TestTCPRecoversFromTailLoss(t *testing.T) {
	const (
		size      = 600_000          // about 490 data packets at MTU 1280
		keepFirst = 100              // data packets delivered before the burst
		delay     = time.Millisecond // each way
		// The burst costs one timeout; allow a little slack for slow or
		// loaded machines, as under the race detector.
		maxTimeouts = 3
		limit       = 60 * time.Second
	)
	serverAddr := netip.MustParseAddr("100.90.0.1")
	clientAddr := netip.MustParseAddr("100.90.0.2")
	serverDev, serverNet, err := CreateNetTUNWithOptions([]netip.Addr{serverAddr}, nil, 1280, NetTunOptions{})
	if err != nil {
		t.Fatalf("CreateNetTUNWithOptions: %v", err)
	}
	defer serverDev.Close()
	clientDev, clientNet, err := CreateNetTUNWithOptions([]netip.Addr{clientAddr}, nil, 1280, NetTunOptions{})
	if err != nil {
		t.Fatalf("CreateNetTUNWithOptions: %v", err)
	}
	defer clientDev.Close()

	// After keepFirst, every data packet is dropped, any loss probe included,
	// until the sender resends the first dropped one, which only its
	// retransmission timer makes it do: nothing above the hole arrives, so
	// there is nothing to SACK. Only the server-to-client link drops, so only
	// its goroutine uses holeStart, dropping and done; the counters are also
	// read at the end.
	var dataPackets, dropped atomic.Int64
	var holeStart uint32
	var dropping, done bool
	drop := func(pkt []byte) bool {
		seq, size := tcpData(pkt)
		if size == 0 {
			return false
		}
		if dataPackets.Add(1) <= keepFirst || done {
			return false
		}
		if !dropping {
			dropping, holeStart = true, seq
		} else if seq == holeStart {
			done = true
			return false
		}
		dropped.Add(1)
		return true
	}
	go link(serverDev, clientDev, delay, drop)
	go link(clientDev, serverDev, delay, nil)

	ln, err := serverNet.ListenTCPAddrPort(netip.AddrPortFrom(serverAddr, 8080))
	if err != nil {
		t.Fatalf("ListenTCPAddrPort: %v", err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.Write(make([]byte, size))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	conn, err := clientNet.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(serverAddr, 8080))
	if err != nil {
		t.Fatalf("DialContextTCPAddrPort: %v", err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(limit))
	start := time.Now()
	n, err := io.Copy(io.Discard, conn)
	if err != nil {
		t.Fatalf("after %v, read %d of %d bytes: %v", time.Since(start).Round(time.Millisecond), n, size, err)
	}
	if n != size {
		t.Fatalf("read %d bytes, want %d", n, size)
	}
	if dropped.Load() == 0 {
		t.Fatalf("no data packet was dropped")
	}
	timeouts := serverDev.(*netTun).stack.Stats().TCP.Timeouts.Value()
	t.Logf("%d bytes in %v, %d data packets, %d dropped, %d retransmission timeouts",
		n, time.Since(start).Round(time.Millisecond), dataPackets.Load(), dropped.Load(), timeouts)
	if timeouts > maxTimeouts {
		t.Errorf("the sender needed %d retransmission timeouts, want at most %d", timeouts, maxTimeouts)
	}
}

// link copies packets from one device to the other, each delay later and in
// order, leaving out those drop returns true for.
func link(from, to tun.Device, delay time.Duration, drop func([]byte) bool) {
	type packet struct {
		due time.Time
		b   []byte
	}
	queue := make(chan packet, 4096)
	defer close(queue)
	go func() {
		for p := range queue {
			time.Sleep(time.Until(p.due))
			if _, err := to.Write([][]byte{p.b}, 0); err != nil {
				return
			}
		}
	}()
	bufs, sizes := [][]byte{make([]byte, 2048)}, []int{0}
	for {
		if _, err := from.Read(bufs, sizes, 0); err != nil {
			return
		}
		b := append([]byte(nil), bufs[0][:sizes[0]]...)
		if drop != nil && drop(b) {
			continue
		}
		queue <- packet{due: time.Now().Add(delay), b: b}
	}
}

// tcpData returns the sequence number and payload size of an IPv4 TCP
// packet; the size is 0 for any other packet.
func tcpData(b []byte) (seq uint32, size int) {
	ip := header.IPv4(b)
	if !ip.IsValid(len(b)) || ip.TransportProtocol() != header.TCPProtocolNumber {
		return 0, 0
	}
	payload := ip.Payload()
	if len(payload) < header.TCPMinimumSize {
		return 0, 0
	}
	tcpHdr := header.TCP(payload)
	return tcpHdr.SequenceNumber(), len(payload) - int(tcpHdr.DataOffset())
}
