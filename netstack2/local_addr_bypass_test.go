package netstack2

import (
	"net/netip"
	"testing"
)

// With an exit-node rule (0.0.0.0/0) installed, traffic addressed to newt's own
// tunnel IP - e.g. olm's connection-status probe to the wgtester - must be left
// for the main stack rather than matched by the catch-all and proxied out.
func TestHandleIncomingPacket_LocalTunnelAddressBypassesCatchAll(t *testing.T) {
	ph, err := NewProxyHandler(ProxyHandlerOptions{EnableICMP: true, MTU: 1500})
	if err != nil {
		t.Fatalf("NewProxyHandler: %v", err)
	}
	if err := ph.Initialize(noopNotification{}); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	defer ph.Close()

	tunnelIP := netip.MustParseAddr("100.90.128.1")
	clientIP := netip.MustParseAddr("100.90.128.5")
	internetIP := netip.MustParseAddr("203.0.113.50")

	ph.SetLocalAddresses([]netip.Addr{tunnelIP})
	ph.AddSubnetRule(SubnetRule{
		SourcePrefix: netip.MustParsePrefix("100.90.128.0/24"),
		DestPrefix:   netip.MustParsePrefix("0.0.0.0/0"),
	})

	if ph.HandleIncomingPacket(buildICMPEchoRequest(t, clientIP, tunnelIP)) {
		t.Error("packet to the local tunnel IP was proxied; expected it to be left for the main stack")
	}
	if !ph.HandleIncomingPacket(buildICMPEchoRequest(t, clientIP, internetIP)) {
		t.Error("packet to an internet address should still match the exit-node rule")
	}
}
