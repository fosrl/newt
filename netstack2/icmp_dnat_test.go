package netstack2

import (
	"bytes"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fosrl/newt/logger"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// buildICMPEchoRequest builds a minimal, checksummed IPv4 ICMP echo request
// packet from src to dst.
func buildICMPEchoRequest(t *testing.T, src, dst netip.Addr) []byte {
	t.Helper()

	const icmpSize = header.ICMPv4MinimumSize
	totalLen := header.IPv4MinimumSize + icmpSize
	pkt := make([]byte, totalLen)

	ip := header.IPv4(pkt)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(totalLen),
		TTL:         64,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4(src.As4()),
		DstAddr:     tcpip.AddrFrom4(dst.As4()),
	})
	ip.SetChecksum(0)
	ip.SetChecksum(^ip.CalculateChecksum())

	icmp := header.ICMPv4(pkt[header.IPv4MinimumSize:])
	icmp.SetType(header.ICMPv4Echo)
	icmp.SetCode(0)
	icmp.SetIdent(1)
	icmp.SetSequence(1)
	icmp.SetChecksum(0)
	icmp.SetChecksum(header.ICMPv4Checksum(icmp, checksum.Checksum(icmp.Payload(), 0)))

	return pkt
}

// noopNotification is a no-op channel.Notification for tests that don't
// care about read-availability notifications.
type noopNotification struct{}

func (noopNotification) WriteNotify() {}

// captureLogOutput redirects the package logger to a pipe for the duration
// of fn, and returns everything written to it. Needed here because
// ICMPHandler.handleICMPPacket runs on its own goroutine off of
// HandleIncomingPacket and reports its outcome only via log lines.
func captureLogOutput(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}

	logger.SetOutput(w)
	defer logger.SetOutput(os.Stdout)

	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		done <- buf.String()
	}()

	fn()

	// handleICMPPacket runs asynchronously (go h.proxyPing(...)); give it a
	// moment to log its outcome before we stop capturing.
	time.Sleep(200 * time.Millisecond)

	w.Close()
	return <-done
}

// A DNAT target whose RewriteTo isn't independently reachable as its own
// destination (e.g. a resolved domain name, or - as here - just an IP with
// no mirrored direct subnet rule) used to make ICMP echo requests get
// silently dropped: the old ICMPHandler re-derived the DNAT target by
// running a fresh SubnetLookup.Match() against whatever address the packet
// carried by the time it reached the handler, which for a non-loopback
// rewrite is already the post-DNAT address - and no rule exists for that
// address on its own. The fix resolves the real target via
// destRewriteTable (LookupDestinationRewrite) instead, exactly like the
// TCP/UDP handlers already did, so this no longer depends on a mirrored
// direct rule existing for the rewritten address.
func TestICMPHandleIncomingPacket_DNATWithoutMirroredDirectRule(t *testing.T) {
	ph, err := NewProxyHandler(ProxyHandlerOptions{EnableICMP: true, MTU: 1500})
	if err != nil {
		t.Fatalf("NewProxyHandler: %v", err)
	}
	if err := ph.Initialize(noopNotification{}); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	defer ph.Close()

	srcAddr := netip.MustParseAddr("10.0.0.5")
	aliasAddr := netip.MustParseAddr("10.20.20.9")
	realAddr := netip.MustParseAddr("203.0.113.50")

	ph.AddSubnetRule(SubnetRule{
		SourcePrefix: netip.MustParsePrefix("10.0.0.0/24"),
		DestPrefix:   netip.PrefixFrom(aliasAddr, 32),
		RewriteTo:    realAddr.String() + "/32",
	})

	pkt := buildICMPEchoRequest(t, srcAddr, aliasAddr)

	var injected bool
	logs := captureLogOutput(t, func() {
		injected = ph.HandleIncomingPacket(pkt)
	})

	if !injected {
		t.Fatal("expected ICMP echo request to be matched and injected")
	}

	// destRewriteTable is populated by HandleIncomingPacket itself, so this
	// much holds regardless of the bug - included here to pin the mechanism
	// the fix relies on.
	got, ok := ph.LookupDestinationRewrite(srcAddr.String(), aliasAddr.String(), 0, uint8(header.ICMPv4ProtocolNumber))
	if !ok {
		t.Fatal("expected destRewriteTable to have an entry for this ICMP flow")
	}
	if got != realAddr {
		t.Fatalf("expected rewritten destination %s, got %s", realAddr, got)
	}

	// This is the actual regression check: with the bug, handleICMPPacket
	// re-matches on the already-rewritten address, finds no rule for it,
	// and drops the echo request before ever attempting to proxy it.
	if strings.Contains(logs, "No matching subnet rule") {
		t.Errorf("ICMP handler dropped the echo request instead of proxying it; logs:\n%s", logs)
	}
	if !strings.Contains(logs, "Proxying ping from") {
		t.Errorf("expected ICMP handler to proxy the ping to the rewritten destination; logs:\n%s", logs)
	}
	if !strings.Contains(logs, realAddr.String()) {
		t.Errorf("expected logs to reference the rewritten destination %s; logs:\n%s", realAddr, logs)
	}
}

// With a non-loopback DNAT target the ICMP handler used to see the packet
// only after its destination had been rewritten, so it had no way to know
// which address the client actually pinged and answered from the DNAT
// target. HandleIncomingPacket now leaves ICMP packets unrewritten, so the
// handler must see the original (alias) destination and resolve the real
// target via destRewriteTable.
func TestICMPHandleIncomingPacket_DNATHandlerSeesOriginalDestination(t *testing.T) {
	ph, err := NewProxyHandler(ProxyHandlerOptions{EnableICMP: true, MTU: 1500})
	if err != nil {
		t.Fatalf("NewProxyHandler: %v", err)
	}
	if err := ph.Initialize(noopNotification{}); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	defer ph.Close()

	srcAddr := netip.MustParseAddr("10.0.0.5")
	aliasAddr := netip.MustParseAddr("10.20.20.9")
	realAddr := netip.MustParseAddr("203.0.113.50")

	ph.AddSubnetRule(SubnetRule{
		SourcePrefix: netip.MustParsePrefix("10.0.0.0/24"),
		DestPrefix:   netip.PrefixFrom(aliasAddr, 32),
		RewriteTo:    realAddr.String() + "/32",
	})

	pkt := buildICMPEchoRequest(t, srcAddr, aliasAddr)

	var injected bool
	logs := captureLogOutput(t, func() {
		injected = ph.HandleIncomingPacket(pkt)
	})

	if !injected {
		t.Fatal("expected ICMP echo request to be matched and injected")
	}

	wantRequest := "Echo Request from " + srcAddr.String() + " to " + aliasAddr.String() + " "
	if !strings.Contains(logs, wantRequest) {
		t.Errorf("expected ICMP handler to see the original destination %s; logs:\n%s", aliasAddr, logs)
	}
	wantRewrite := "Using rewritten destination " + realAddr.String() + " (original: " + aliasAddr.String() + ")"
	if !strings.Contains(logs, wantRewrite) {
		t.Errorf("expected ICMP handler to resolve %s via the rewrite table; logs:\n%s", realAddr, logs)
	}
}

// localNonLoopbackIPv4 returns an IPv4 address of this machine that is not a
// loopback address, i.e. a DNAT target that answers pings but still takes the
// non-loopback path in HandleIncomingPacket.
func localNonLoopbackIPv4(t *testing.T) (netip.Addr, bool) {
	t.Helper()

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return netip.Addr{}, false
	}
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipNet.IP.To4()
		if ip4 == nil || !ipNet.IP.IsGlobalUnicast() {
			continue
		}
		return netip.AddrFrom4([4]byte(ip4)), true
	}
	return netip.Addr{}, false
}

// The echo reply for a DNAT'd echo request has to come from the address the
// client pinged, not from the DNAT target: a client matches replies against
// the address it sent the request to (ping prints "DIFFERENT ADDRESS",
// check_icmp drops the reply and reports 100% packet loss).
func TestICMPEchoReply_DNATSourceIsOriginalDestination(t *testing.T) {
	realAddr, ok := localNonLoopbackIPv4(t)
	if !ok {
		t.Skip("no non-loopback IPv4 address available to ping")
	}

	ph, err := NewProxyHandler(ProxyHandlerOptions{EnableICMP: true, MTU: 1500})
	if err != nil {
		t.Fatalf("NewProxyHandler: %v", err)
	}
	if err := ph.Initialize(noopNotification{}); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	defer ph.Close()

	srcAddr := netip.MustParseAddr("10.0.0.5")
	aliasAddr := netip.MustParseAddr("10.20.20.9")

	ph.AddSubnetRule(SubnetRule{
		SourcePrefix: netip.MustParsePrefix("10.0.0.0/24"),
		DestPrefix:   netip.PrefixFrom(aliasAddr, 32),
		RewriteTo:    realAddr.String() + "/32",
	})

	if !ph.HandleIncomingPacket(buildICMPEchoRequest(t, srcAddr, aliasAddr)) {
		t.Fatal("expected ICMP echo request to be matched and injected")
	}

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		view := ph.ReadOutgoingPacket()
		if view == nil {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		reply := view.AsSlice()
		if len(reply) < header.IPv4MinimumSize+header.ICMPv4MinimumSize {
			continue
		}
		ip := header.IPv4(reply)
		if ip.TransportProtocol() != header.ICMPv4ProtocolNumber {
			continue
		}
		if header.ICMPv4(reply[ip.HeaderLength():]).Type() != header.ICMPv4EchoReply {
			continue
		}

		if got := netip.AddrFrom4(ip.SourceAddress().As4()); got != aliasAddr {
			t.Errorf("echo reply source = %s, want the original destination %s (DNAT target is %s)", got, aliasAddr, realAddr)
		}
		if got := netip.AddrFrom4(ip.DestinationAddress().As4()); got != srcAddr {
			t.Errorf("echo reply destination = %s, want %s", got, srcAddr)
		}
		return
	}

	t.Skipf("no echo reply from %s; pinging is not possible in this environment", realAddr)
}
