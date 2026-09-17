package newt

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"time"

	"github.com/fosrl/newt/internal/kernelwg"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func mainAllowedIPs(serverIP string, subnets []string) ([]netip.Prefix, error) {
	server, err := netip.ParseAddr(serverIP)
	if err != nil || !server.Is4() {
		return nil, fmt.Errorf("invalid main tunnel server IPv4 address %q", serverIP)
	}
	prefixes := []netip.Prefix{netip.PrefixFrom(server, 32)}
	seen := map[netip.Prefix]bool{prefixes[0]: true}
	for _, subnet := range subnets {
		prefix, err := netip.ParsePrefix(subnet)
		if err != nil || !prefix.Addr().Is4() {
			return nil, fmt.Errorf("kernel main tunnel requires IPv4 subnet prefixes, got %q", subnet)
		}
		prefix = prefix.Masked()
		if !seen[prefix] {
			prefixes = append(prefixes, prefix)
			seen[prefix] = true
		}
	}
	return prefixes, nil
}

func (n *Newt) openKernelMain(ctx context.Context, endpoint string) error {
	address, err := netip.ParseAddr(n.wgData.TunnelIP)
	if err != nil || !address.Is4() {
		return fmt.Errorf("invalid main tunnel IPv4 address %q", n.wgData.TunnelIP)
	}
	peerKey, err := wgtypes.ParseKey(n.wgData.PublicKey)
	if err != nil {
		return fmt.Errorf("invalid main tunnel peer key: %w", err)
	}
	remote, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return fmt.Errorf("resolve WireGuard endpoint: %w", err)
	}
	allowed, err := mainAllowedIPs(n.wgData.ServerIP, n.wgData.RemoteExitNodeSubnets)
	if err != nil {
		return err
	}
	protected, err := resolveControlEndpoint(ctx, n.config.Endpoint)
	if err != nil {
		return err
	}
	device, err := kernelwg.Open(kernelwg.Config{
		Name:          n.config.NativeMainInterfaceName,
		Owner:         n.config.ID,
		PrivateKey:    n.privateKey,
		PeerPublicKey: peerKey,
		Endpoint:      remote,
		Address:       netip.PrefixFrom(address, 32),
		AllowedIPs:    allowed,
		ProtectedIPs:  protected,
		MTU:           n.config.MTU,
	})
	if err != nil {
		return err
	}
	n.kernelMain = device
	n.activeRemoteSubnets = append([]string(nil), n.wgData.RemoteExitNodeSubnets...)
	return nil
}

// Protect the control connection as well as the WireGuard UDP endpoint from
// accidental capture by site-to-cloud routes. Re-resolved on every reconnect.
func resolveControlEndpoint(ctx context.Context, endpoint string) ([]netip.Addr, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("invalid Pangolin control endpoint %q", endpoint)
	}
	if address, err := netip.ParseAddr(u.Hostname()); err == nil {
		return []netip.Addr{address.Unmap()}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", u.Hostname())
	if err != nil {
		return nil, fmt.Errorf("resolve Pangolin control endpoint: %w", err)
	}
	return addresses, nil
}

func (n *Newt) hasMainTunnel() bool {
	return n.dev != nil || n.kernelMain != nil
}
