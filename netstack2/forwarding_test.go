package netstack2

import (
	"net/netip"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

// Only a netstack with a proxy forwards IPv4. Without one, as in the main
// tunnel, forwarding stays off, as in wireguard-go's netstack.
func TestIPv4ForwardingOnlyWithProxy(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts NetTunOptions
		want bool
	}{
		{"no proxy", NetTunOptions{}, false},
		{"proxy", NetTunOptions{EnableTCPProxy: true, EnableUDPProxy: true, EnableICMPProxy: true}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dev, _, err := CreateNetTUNWithOptions([]netip.Addr{netip.MustParseAddr("100.90.0.1")}, nil, 1280, tc.opts)
			if err != nil {
				t.Fatalf("CreateNetTUNWithOptions: %v", err)
			}
			tn := dev.(*netTun)
			defer tn.Close()
			got, tcpipErr := tn.stack.NICForwarding(1, ipv4.ProtocolNumber)
			if tcpipErr != nil {
				t.Fatalf("NICForwarding: %v", tcpipErr)
			}
			if got != tc.want {
				t.Errorf("IPv4 forwarding is %t, want %t", got, tc.want)
			}
		})
	}
}
