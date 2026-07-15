package network

import (
	"fmt"
	"net"
	"syscall"
)

const (
	linuxDefaultTunnelRouteMetric = 50   // NetworkManager VPN route priority
	linuxOverlapTunnelRouteMetric = 1025 // above typical LAN (100/600) and systemd-networkd (1024)
)

func subnetsOverlap(a, b *net.IPNet) bool {
	a4, b4 := a.IP.To4(), b.IP.To4()
	if a4 == nil || b4 == nil {
		return false
	}
	onesA, bitsA := a.Mask.Size()
	onesB, bitsB := b.Mask.Size()
	if bitsA != 32 || bitsB != 32 {
		return false
	}
	minOnes := onesA
	if onesB < minOnes {
		minOnes = onesB
	}
	mask := net.CIDRMask(minOnes, 32)
	return a4.Mask(mask).Equal(b4.Mask(mask))
}

func linuxTunnelRouteMetric(remoteSubnet, excludeIface string) (int, bool, error) {
	localNets, err := localIPv4Subnets(excludeIface)
	if err != nil {
		return linuxDefaultTunnelRouteMetric, false, err
	}
	return metricForRemoteSubnet(remoteSubnet, localNets)
}

func metricForRemoteSubnet(remoteSubnet string, localSubnets []*net.IPNet) (int, bool, error) {
	_, remoteNet, err := net.ParseCIDR(remoteSubnet)
	if err != nil {
		return 0, false, fmt.Errorf("invalid remote subnet %s: %w", remoteSubnet, err)
	}
	for _, localNet := range localSubnets {
		if subnetsOverlap(remoteNet, localNet) {
			return linuxOverlapTunnelRouteMetric, true, nil
		}
	}
	return linuxDefaultTunnelRouteMetric, false, nil
}

func linuxRouteFamily(ipNet *net.IPNet) int {
	if ipNet.IP.To4() == nil {
		return syscall.AF_INET6
	}
	return syscall.AF_INET
}

func localIPv4Subnets(excludeIface string) ([]*net.IPNet, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var subnets []*net.IPNet
	for _, iface := range ifaces {
		if iface.Name == excludeIface || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.To4() == nil {
				continue
			}
			subnets = append(subnets, ipNet)
		}
	}
	return subnets, nil
}
