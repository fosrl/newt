package clients

import (
	"fmt"
	"net/netip"
)

// normalizeInterfaceAddress accepts the address shape emitted by Pangolin's
// site configuration. Older Pangolin versions can send a bare host address;
// the client WireGuard interface needs an address/prefix pair, so treat a
// bare IPv4 address as /32 and a bare IPv6 address as /128.
func normalizeInterfaceAddress(raw string) (string, netip.Addr, error) {
	if prefix, err := netip.ParsePrefix(raw); err == nil {
		return prefix.String(), prefix.Addr(), nil
	}

	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return "", netip.Addr{}, fmt.Errorf("invalid IP address format: %s", raw)
	}

	return netip.PrefixFrom(addr, addr.BitLen()).String(), addr, nil
}
