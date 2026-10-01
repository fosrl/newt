//go:build windows

package network

import (
	"fmt"
	"net"
	"net/netip"
	"runtime"

	"github.com/fosrl/newt/logger"
	"golang.org/x/sys/windows"
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

	// Add the route using winipcfg. When PreferLocalRoutes is enabled,
	// metric is set explicitly (rather than a low value like 1, which would
	// nearly always outrank local routes) so that an overlapping local/
	// connected route is preferred over this VPN route - see VPNRouteMetric.
	var metric uint32
	if PreferLocalRoutes {
		metric = VPNRouteMetric
	}
	err = luid.AddRoute(prefix, nextHop, metric)
	if err != nil {
		return fmt.Errorf("failed to add route: %v", err)
	}

	return nil
}

// WindowsAddBypassRoute adds an explicit /32 host route for destIP via
// whatever gateway/interface the OS routing table currently uses to reach
// it, so a broader route added afterward (e.g. a gateway/full-tunnel default
// route) can never capture this destination - see
// network.AddBypassRouteForDestination. Routes on tunnelInterface are ignored
// when picking that path, so a bypass route added while a gateway route
// (0.0.0.0/1 + 128.0.0.0/1 on the tunnel) is installed still resolves to the
// physical default route rather than back into the tunnel.
func WindowsAddBypassRoute(destIP string, tunnelInterface string) error {
	_, err := windowsEnsureBypassRoute(destIP, tunnelInterface)
	return err
}

// windowsEnsureBypassRoute makes the /32 route to destIP match the current
// physical path (see windowsBypassNextHop), adding it if missing and
// replacing it if it points somewhere else. Returns whether the routing table
// was changed.
func windowsEnsureBypassRoute(destIP string, tunnelInterface string) (bool, error) {
	addr, err := netip.ParseAddr(destIP)
	if err != nil || !addr.Is4() {
		return false, fmt.Errorf("invalid IPv4 destination address: %s", destIP)
	}
	host := netip.PrefixFrom(addr, addr.BitLen())

	routes, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return false, fmt.Errorf("failed to get route table: %v", err)
	}

	best, err := windowsBypassNextHop(routes, addr, tunnelInterface)
	if err != nil {
		return false, err
	}

	var existing *winipcfg.MibIPforwardRow2
	for i := range routes {
		if routes[i].DestinationPrefix.Prefix() == host {
			existing = &routes[i]
			break
		}
	}
	if existing != nil {
		if existing.InterfaceLUID == best.InterfaceLUID && existing.NextHop.Addr() == best.NextHop.Addr() {
			return false, nil
		}
		if err := existing.Delete(); err != nil {
			return false, fmt.Errorf("failed to remove stale bypass route to %s: %v", destIP, err)
		}
	}

	logger.Info("Setting bypass route to %s via %s (interface LUID %v)", destIP, best.NextHop.Addr(), best.InterfaceLUID)

	if err := best.InterfaceLUID.AddRoute(host, best.NextHop.Addr(), 0); err != nil {
		return false, fmt.Errorf("failed to add bypass route: %v", err)
	}

	return true, nil
}

// windowsBypassNextHop picks the route Windows would use to reach addr if
// neither the tunnel nor our own bypass route existed: the longest prefix
// containing addr, lowest effective metric (route + interface metric) first,
// skipping routes on tunnelInterface, on disconnected interfaces, and the /32
// route to addr itself.
func windowsBypassNextHop(routes []winipcfg.MibIPforwardRow2, addr netip.Addr, tunnelInterface string) (*winipcfg.MibIPforwardRow2, error) {
	var tunnelLUID winipcfg.LUID
	hasTunnelLUID := false
	if tunnelInterface != "" {
		if iface, err := net.InterfaceByName(tunnelInterface); err == nil {
			if luid, err := winipcfg.LUIDFromIndex(uint32(iface.Index)); err == nil {
				tunnelLUID, hasTunnelLUID = luid, true
			}
		}
	}

	var best *winipcfg.MibIPforwardRow2
	bestBits := -1
	var bestMetric uint32
	for i := range routes {
		route := &routes[i]
		prefix := route.DestinationPrefix.Prefix()
		if !prefix.Contains(addr) || prefix.Bits() == addr.BitLen() {
			continue
		}
		if hasTunnelLUID && route.InterfaceLUID == tunnelLUID {
			continue
		}
		iface, err := route.InterfaceLUID.IPInterface(windows.AF_INET)
		if err != nil || !iface.Connected {
			continue
		}
		metric := route.Metric + iface.Metric
		if prefix.Bits() > bestBits || (prefix.Bits() == bestBits && metric < bestMetric) {
			best, bestBits, bestMetric = route, prefix.Bits(), metric
		}
	}
	if best == nil {
		return nil, fmt.Errorf("%w: %s", ErrNoPhysicalRoute, addr)
	}
	return best, nil
}

// WindowsRemoveBypassRoute removes a route previously added by
// WindowsAddBypassRoute. It deliberately does not re-derive the route via a
// longest-prefix-match lookup - by the time this runs, our own /32 bypass
// route is the most specific match for destIP and the lookup would just find
// itself - so it instead deletes by exact destination prefix alone.
func WindowsRemoveBypassRoute(destIP string) error {
	addr, err := netip.ParseAddr(destIP)
	if err != nil {
		return fmt.Errorf("invalid destination address: %v", err)
	}
	prefix := netip.PrefixFrom(addr, addr.BitLen())

	var family winipcfg.AddressFamily
	if addr.Is4() {
		family = 2
	} else {
		family = 23
	}

	routes, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		return fmt.Errorf("failed to get route table: %v", err)
	}

	for _, route := range routes {
		if route.DestinationPrefix.Prefix() != prefix {
			continue
		}
		logger.Info("Removing bypass route to %s on interface LUID %v", destIP, route.InterfaceLUID)
		if err := route.Delete(); err != nil {
			return fmt.Errorf("failed to delete bypass route: %v", err)
		}
		return nil
	}

	return fmt.Errorf("bypass route to %s not found", destIP)
}

func WindowsRemoveRoute(destination string, interfaceName string) error {
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

	// Resolve the LUID of the interface we added the route on, so we only
	// ever delete the route we own rather than any route matching the
	// destination - a local/native route to the same destination on a
	// different interface must never be touched.
	var luid winipcfg.LUID
	var haveLuid bool
	if interfaceName != "" {
		iface, err := net.InterfaceByName(interfaceName)
		if err != nil {
			return fmt.Errorf("failed to get interface %s: %v", interfaceName, err)
		}
		luid, err = winipcfg.LUIDFromIndex(uint32(iface.Index))
		if err != nil {
			return fmt.Errorf("failed to get LUID for interface %s: %v", interfaceName, err)
		}
		haveLuid = true
	}

	// Get all routes and find the one to delete
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

	// Find and delete matching route. When we know which interface we added
	// the route on, only delete the entry on that interface with the metric
	// we added it with (see PreferLocalRoutes) so we never remove an
	// unrelated local/native route to the same destination.
	var wantMetric uint32
	if PreferLocalRoutes {
		wantMetric = VPNRouteMetric
	}
	for _, route := range routes {
		routePrefix := route.DestinationPrefix.Prefix()
		if routePrefix != prefix {
			continue
		}
		if haveLuid && (route.InterfaceLUID != luid || route.Metric != wantMetric) {
			continue
		}
		logger.Info("Removing route to %s on interface %s", destination, interfaceName)
		if err := route.Delete(); err != nil {
			return fmt.Errorf("failed to delete route: %v", err)
		}
		return nil
	}

	return fmt.Errorf("route to %s not found", destination)
}
