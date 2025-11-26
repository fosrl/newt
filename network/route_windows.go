//go:build windows

package network

import (
	"fmt"
	"net"
	"net/netip"
	"runtime"

	"github.com/fosrl/newt/logger"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func WindowsAddRoute(destination string, gateway string, interfaceName string) error {
	if runtime.GOOS != "windows" {
		return nil
	}

	// Parse destination CIDR
	_, ipNet, err := net.ParseCIDR(destination)
	if err != nil {
		return fmt.Errorf("invalid destination address: %v", err)
	}

	// Convert to netip.Prefix
	maskBits, _ := ipNet.Mask.Size()

	// Ensure we convert to the correct IP version (IPv4 vs IPv6)
	var addr netip.Addr
	if ip4 := ipNet.IP.To4(); ip4 != nil {
		// IPv4 address
		addr, _ = netip.AddrFromSlice(ip4)
	} else {
		// IPv6 address
		addr, _ = netip.AddrFromSlice(ipNet.IP)
	}
	if !addr.IsValid() {
		return fmt.Errorf("failed to convert destination IP")
	}
	prefix := netip.PrefixFrom(addr, maskBits)

	var luid winipcfg.LUID
	var nextHop netip.Addr

	if interfaceName != "" {
		// Get the interface LUID - needed for both gateway and interface-only routes
		iface, err := net.InterfaceByName(interfaceName)
		if err != nil {
			return fmt.Errorf("failed to get interface %s: %v", interfaceName, err)
		}

		luid, err = winipcfg.LUIDFromIndex(uint32(iface.Index))
		if err != nil {
			return fmt.Errorf("failed to get LUID for interface %s: %v", interfaceName, err)
		}
	}

	if gateway != "" {
		// Route with specific gateway
		gwIP := net.ParseIP(gateway)
		if gwIP == nil {
			return fmt.Errorf("invalid gateway address: %s", gateway)
		}
		// Convert to correct IP version
		if ip4 := gwIP.To4(); ip4 != nil {
			nextHop, _ = netip.AddrFromSlice(ip4)
		} else {
			nextHop, _ = netip.AddrFromSlice(gwIP)
		}
		if !nextHop.IsValid() {
			return fmt.Errorf("failed to convert gateway IP")
		}
		logger.Info("Adding route to %s via gateway %s on interface %s", destination, gateway, interfaceName)
	} else if interfaceName != "" {
		// Route via interface only
		if addr.Is4() {
			nextHop = netip.IPv4Unspecified()
		} else {
			nextHop = netip.IPv6Unspecified()
		}
		logger.Info("Adding route to %s via interface %s", destination, interfaceName)
	} else {
		return fmt.Errorf("either gateway or interface must be specified")
	}

	// Add the route using winipcfg
	err = luid.AddRoute(prefix, nextHop, 1)
	if err != nil {
		return fmt.Errorf("failed to add route: %v", err)
	}

	return nil
}

func WindowsRemoveRoute(destination string) error {
	// Parse destination CIDR
	_, ipNet, err := net.ParseCIDR(destination)
	if err != nil {
		return fmt.Errorf("invalid destination address: %v", err)
	}

	// Convert to netip.Prefix
	maskBits, _ := ipNet.Mask.Size()

	// Ensure we convert to the correct IP version (IPv4 vs IPv6)
	var addr netip.Addr
	if ip4 := ipNet.IP.To4(); ip4 != nil {
		// IPv4 address
		addr, _ = netip.AddrFromSlice(ip4)
	} else {
		// IPv6 address
		addr, _ = netip.AddrFromSlice(ipNet.IP)
	}
	if !addr.IsValid() {
		return fmt.Errorf("failed to convert destination IP")
	}
	prefix := netip.PrefixFrom(addr, maskBits)

	// Get all routes and find the one to delete
	// We need to get the LUID from the existing route
	var family winipcfg.AddressFamily
	if addr.Is4() {
		family = 2 // AF_INET
	} else {
		family = 23 // AF_INET6
	}

	routes, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		return fmt.Errorf("failed to get route table: %v", err)
	}

	// Find and delete matching route
	for _, route := range routes {
		routePrefix := route.DestinationPrefix.Prefix()
		if routePrefix == prefix {
			logger.Info("Removing route to %s", destination)
			err = route.Delete()
			if err != nil {
				return fmt.Errorf("failed to delete route: %v", err)
			}
			return nil
		}
	}

	return fmt.Errorf("route to %s not found", destination)
}
