package network

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"

	"github.com/fosrl/newt/logger"
	"github.com/vishvananda/netlink"
)

// VPNRouteMetric is the route metric/priority assigned to routes we add for
// the tunnel, so that an overlapping local/connected route is always
// preferred over the VPN route to the same destination rather than the two
// silently racing based on insertion order. It needs to be higher than any
// metric a local route is realistically going to have: on Linux, automatic
// metrics assigned by NetworkManager (which also apply to the connected
// subnet route, not just the default route) go up to 600 for Wi-Fi; on
// Windows, automatic interface metrics plus route metric rarely exceed a few
// hundred. 9999 comfortably clears both without needing to query the local
// routing table at add-time.
const VPNRouteMetric = 9999

// PreferLocalRoutes controls whether routes added by AddRoutes are given the
// explicit high VPNRouteMetric priority, so that an overlapping local/
// connected route always takes precedence over the VPN route to the same
// destination. Defaults to false (routes are added with the OS default
// metric/priority, matching behavior prior to the introduction of
// VPNRouteMetric); callers that want local routes to win opt in by setting
// this to true (e.g. from a config value) before routes are added.
var PreferLocalRoutes = false

// NativeConfigDisabled, when true, skips the raw `ifconfig`/`route` subprocess
// calls this package otherwise makes on darwin (configureDarwin,
// removeDarwinAddress, DarwinAddRouteWithSource, DarwinRemoveRoute) while still
// populating the JSON-facing NetworkSettings state. This must be set when the
// TUN device's addresses/routes are instead owned by an external mechanism
// that reconciles them independently - namely Apple's NetworkExtension
// (NEPacketTunnelProvider.setTunnelNetworkSettings), which is the sole
// sanctioned way to configure that virtual interface. Running our own
// ifconfig/route commands in addition to NE applying its own settings was
// observed to install two competing routes to the same destination (one via
// NE's gatewayAddress-based route, one via our own `-ifa` route), so the two
// mechanisms must be mutually exclusive rather than layered.
var NativeConfigDisabled = false

// DarwinAddRoute adds a route via the BSD routing table. Unlike Linux/Windows,
// BSD's routing table has no per-route metric - preference between an
// overlapping local route and this VPN route is instead resolved by
// longest-prefix-match, and `route add` (as opposed to `route change`) fails
// rather than replacing an existing route to the same destination, so a local
// route is never displaced by one we add here.
func DarwinAddRoute(destination string, gateway string, interfaceName string) error {
	return DarwinAddRouteWithSource(destination, gateway, interfaceName, "")
}

// DarwinAddRouteWithSource is DarwinAddRoute with an explicit source address
// (route(8) `-ifa`). This is required when the interface carries more than
// one address (e.g. an exit node's secondary tunnel address alongside the
// site tunnel's primary address): without `-ifa`, BSD picks a source address
// for the route on its own - typically the interface's primary address - and
// WireGuard's own reverse-path filtering on the remote end will silently drop
// packets whose source doesn't match the peer's configured AllowedIPs, even
// though the tunnel/handshake itself stays up.
func DarwinAddRouteWithSource(destination string, gateway string, interfaceName string, sourceIP string) error {
	if runtime.GOOS != "darwin" {
		return nil
	}
	if NativeConfigDisabled {
		return nil
	}

	var args []string

	if gateway != "" {
		// Route with specific gateway
		args = []string{"-q", "-n", "add", "-inet", destination, "-gateway", gateway}
	} else if interfaceName != "" {
		// Route via interface
		args = []string{"-q", "-n", "add", "-inet", destination, "-interface", interfaceName}
	} else {
		return fmt.Errorf("either gateway or interface must be specified")
	}

	if sourceIP != "" {
		args = append(args, "-ifa", sourceIP)
	}

	cmd := exec.Command("route", args...)

	logger.Info("Running command: %v", cmd)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("route command failed: %v, output: %s", err, out)
	}

	return nil
}

func DarwinRemoveRoute(destination string) error {
	if runtime.GOOS != "darwin" {
		return nil
	}
	if NativeConfigDisabled {
		return nil
	}

	cmd := exec.Command("route", "-q", "-n", "delete", "-inet", destination)
	logger.Info("Running command: %v", cmd)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("route delete command failed: %v, output: %s", err, out)
	}

	return nil
}

func LinuxAddRoute(destination string, gateway string, interfaceName string) error {
	if runtime.GOOS != "linux" {
		return nil
	}

	// Parse destination CIDR
	_, ipNet, err := net.ParseCIDR(destination)
	if err != nil {
		return fmt.Errorf("invalid destination address: %v", err)
	}

	// Create route. When PreferLocalRoutes is enabled, Priority is set
	// explicitly (rather than left at the default of 0) so that this route
	// never outranks a local/connected route to the same destination - see
	// VPNRouteMetric.
	route := &netlink.Route{
		Dst: ipNet,
	}
	if PreferLocalRoutes {
		route.Priority = VPNRouteMetric
	}

	if gateway != "" {
		// Route with specific gateway
		gw := net.ParseIP(gateway)
		if gw == nil {
			return fmt.Errorf("invalid gateway address: %s", gateway)
		}
		route.Gw = gw
		logger.Info("Adding route to %s via gateway %s", destination, gateway)
	} else if interfaceName != "" {
		// Route via interface
		link, err := netlink.LinkByName(interfaceName)
		if err != nil {
			return fmt.Errorf("failed to get interface %s: %v", interfaceName, err)
		}
		route.LinkIndex = link.Attrs().Index
		logger.Info("Adding route to %s via interface %s", destination, interfaceName)
	} else {
		return fmt.Errorf("either gateway or interface must be specified")
	}

	// Add the route
	if err := netlink.RouteAdd(route); err != nil {
		return fmt.Errorf("failed to add route: %v", err)
	}

	return nil
}

func LinuxRemoveRoute(destination string, interfaceName string) error {
	if runtime.GOOS != "linux" {
		return nil
	}

	// Parse destination CIDR
	_, ipNet, err := net.ParseCIDR(destination)
	if err != nil {
		return fmt.Errorf("invalid destination address: %v", err)
	}

	// Create route to delete. LinkIndex and Priority are set to match the
	// route we added exactly, so this only ever deletes the route we own -
	// a local/native route to the same destination on a different
	// interface (or with a different metric) must never be touched.
	route := &netlink.Route{
		Dst: ipNet,
	}
	if PreferLocalRoutes {
		route.Priority = VPNRouteMetric
	}

	if interfaceName != "" {
		link, err := netlink.LinkByName(interfaceName)
		if err != nil {
			return fmt.Errorf("failed to get interface %s: %v", interfaceName, err)
		}
		route.LinkIndex = link.Attrs().Index
	}

	logger.Info("Removing route to %s via interface %s", destination, interfaceName)

	// Delete the route
	if err := netlink.RouteDel(route); err != nil {
		return fmt.Errorf("failed to delete route: %v", err)
	}

	return nil
}

// LinuxAddBypassRoute adds an explicit /32 host route for destIP via
// whatever gateway/interface the kernel currently uses to reach it, so a
// broader route added afterward (e.g. a gateway/full-tunnel default route)
// can never capture this destination - see AddBypassRouteForDestination.
func LinuxAddBypassRoute(destIP string) error {
	if runtime.GOOS != "linux" {
		return nil
	}

	ip := net.ParseIP(destIP)
	if ip == nil {
		return fmt.Errorf("invalid destination address: %s", destIP)
	}

	routes, err := netlink.RouteGet(ip)
	if err != nil {
		return fmt.Errorf("failed to look up current route to %s: %v", destIP, err)
	}
	if len(routes) == 0 {
		return fmt.Errorf("no route found to %s", destIP)
	}
	current := routes[0]

	link, err := netlink.LinkByIndex(current.LinkIndex)
	if err != nil {
		return fmt.Errorf("failed to resolve interface for route to %s: %v", destIP, err)
	}

	route := &netlink.Route{
		Dst:       &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)},
		Gw:        current.Gw,
		LinkIndex: link.Attrs().Index,
	}

	logger.Info("Adding bypass route to %s via %s (interface %s)", destIP, current.Gw, link.Attrs().Name)

	if err := netlink.RouteAdd(route); err != nil {
		return fmt.Errorf("failed to add bypass route to %s: %v", destIP, err)
	}

	return nil
}

// LinuxRemoveBypassRoute removes a route previously added by
// LinuxAddBypassRoute. It deliberately does not re-derive the route via
// RouteGet - by the time this runs, our own /32 bypass route is the most
// specific match for destIP and RouteGet would just find itself - so it
// instead deletes by destination alone.
func LinuxRemoveBypassRoute(destIP string) error {
	if runtime.GOOS != "linux" {
		return nil
	}

	ip := net.ParseIP(destIP)
	if ip == nil {
		return fmt.Errorf("invalid destination address: %s", destIP)
	}

	route := &netlink.Route{
		Dst: &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)},
	}

	if err := netlink.RouteDel(route); err != nil {
		return fmt.Errorf("failed to remove bypass route to %s: %v", destIP, err)
	}

	return nil
}

// DarwinAddBypassRoute adds an explicit /32 host route for destIP via
// whatever gateway/interface the kernel currently uses to reach it (parsed
// from `route -n get`), so a broader route added afterward can never capture
// this destination - see AddBypassRouteForDestination.
func DarwinAddBypassRoute(destIP string) error {
	if runtime.GOOS != "darwin" {
		return nil
	}
	if NativeConfigDisabled {
		return nil
	}

	cmd := exec.Command("route", "-n", "get", destIP)
	logger.Info("Running command: %v", cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("route get command failed: %v, output: %s", err, out)
	}

	var gateway, iface string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "gateway:"):
			gateway = strings.TrimSpace(strings.TrimPrefix(line, "gateway:"))
		case strings.HasPrefix(line, "interface:"):
			iface = strings.TrimSpace(strings.TrimPrefix(line, "interface:"))
		}
	}
	if gateway == "" && iface == "" {
		return fmt.Errorf("could not determine current route to %s from `route get` output: %s", destIP, out)
	}

	return DarwinAddRouteWithSource(destIP+"/32", gateway, iface, "")
}

// DarwinRemoveBypassRoute removes a route previously added by
// DarwinAddBypassRoute.
func DarwinRemoveBypassRoute(destIP string) error {
	if runtime.GOOS != "darwin" {
		return nil
	}
	return DarwinRemoveRoute(destIP + "/32")
}

// AddGatewayDefaultRoute installs the OS-level "route everything" equivalent
// for a full-tunnel/gateway peer. NetworkSettings is always populated first
// (regardless of GOOS - mobile packet-tunnel providers read it independent
// of platform, see AddRouteForServerIPWithSource), via an IsDefault included
// route. On desktop platforms, where olm manages the OS routing table
// directly, this then also installs the standard wg-quick split-default-route
// technique (0.0.0.0/1 + 128.0.0.0/1) instead of a literal 0.0.0.0/0, so the
// host's real default route is never replaced or raced with - it is only
// outranked by two strictly more-specific halves. PreferLocalRoutes (if set)
// still applies to these routes exactly as it does to any other tunnel
// route, so an overlapping local/LAN route continues to win even in gateway
// mode.
func AddGatewayDefaultRoute(interfaceName, sourceIP string) error {
	AddIPv4IncludedRoute(IPv4Route{DestinationAddress: "0.0.0.0", SubnetMask: "0.0.0.0", IsDefault: true})

	if runtime.GOOS == "android" || runtime.GOOS == "ios" {
		return nil
	}
	return AddRoutesWithSource([]string{"0.0.0.0/1", "128.0.0.0/1"}, interfaceName, sourceIP)
}

// RemoveGatewayDefaultRoute reverses AddGatewayDefaultRoute.
func RemoveGatewayDefaultRoute(interfaceName string) error {
	RemoveIPv4IncludedRoute(IPv4Route{DestinationAddress: "0.0.0.0", SubnetMask: "0.0.0.0", IsDefault: true})

	if runtime.GOOS == "android" || runtime.GOOS == "ios" {
		return nil
	}
	return RemoveRoutes([]string{"0.0.0.0/1", "128.0.0.0/1"}, interfaceName)
}

// AddBypassRouteForDestination installs an explicit /32 host route for destIP
// using whatever gateway/interface the OS routing table currently uses to
// reach it - i.e. the physical/original path, not the tunnel. It must be
// called BEFORE AddGatewayDefaultRoute so the destination's own path is
// pinned down first and can never be captured by the more general gateway
// route. This is the same technique wg-quick uses (set_endpoint_direct_route)
// to keep a WireGuard peer's own UDP traffic from being captured by the
// gateway route it is itself responsible for installing.
//
// NetworkSettings is always populated (an excluded route, for mobile
// packet-tunnel providers), regardless of GOOS; the OS routing table is only
// touched on desktop platforms, which have no equivalent of
// NEIPv4Settings.excludedRoutes/VpnService.Builder.excludeRoute.
func AddBypassRouteForDestination(destIP string) error {
	AddIPv4ExcludedRoute(IPv4Route{DestinationAddress: destIP, SubnetMask: "255.255.255.255"})

	switch runtime.GOOS {
	case "linux":
		return LinuxAddBypassRoute(destIP)
	case "darwin":
		return DarwinAddBypassRoute(destIP)
	case "windows":
		return WindowsAddBypassRoute(destIP)
	}
	return nil
}

// RemoveBypassRouteForDestination reverses AddBypassRouteForDestination.
func RemoveBypassRouteForDestination(destIP string) error {
	RemoveIPv4ExcludedRoute(IPv4Route{DestinationAddress: destIP, SubnetMask: "255.255.255.255"})

	switch runtime.GOOS {
	case "linux":
		return LinuxRemoveBypassRoute(destIP)
	case "darwin":
		return DarwinRemoveBypassRoute(destIP)
	case "windows":
		return WindowsRemoveBypassRoute(destIP)
	}
	return nil
}

// addRouteForServerIP adds an OS-specific route for the server IP
func AddRouteForServerIP(serverIP, interfaceName string) error {
	return AddRouteForServerIPWithSource(serverIP, interfaceName, "")
}

// AddRouteForServerIPWithSource is AddRouteForServerIP with an explicit source
// address for the darwin route (see DarwinAddRouteWithSource) - needed when
// the interface carries more than one address, e.g. an exit node connection
// where the interface's primary address belongs to the site tunnel rather
// than the exit node.
func AddRouteForServerIPWithSource(serverIP, interfaceName string, sourceIP string) error {
	if interfaceName == "" {
		return nil
	}

	// Populate the NetworkSettings entry (and its gatewayAddress, for the
	// NetworkExtension source-pinning trick above) unconditionally, same as
	// AddRoutesWithSource does for remote subnets - mobile packet-tunnel
	// providers rely on this regardless of GOOS.
	if err := AddRouteForNetworkConfigWithGateway(serverIP, sourceIP); err != nil {
		return err
	}

	// TODO: does this also need to be ios?
	if runtime.GOOS == "darwin" { // macos requires routes for each peer to be added but this messes with other platforms
		return DarwinAddRouteWithSource(serverIP, "", interfaceName, sourceIP)
	}
	// else if runtime.GOOS == "windows" {
	//	return WindowsAddRoute(serverIP, "", interfaceName)
	// } else if runtime.GOOS == "linux" {
	//	return LinuxAddRoute(serverIP, "", interfaceName)
	// }
	return nil
}

// removeRouteForServerIP removes an OS-specific route for the server IP
func RemoveRouteForServerIP(serverIP string, interfaceName string) error {
	return RemoveRouteForServerIPWithSource(serverIP, interfaceName, "")
}

// RemoveRouteForServerIPWithSource is RemoveRouteForServerIP with an explicit
// source/gateway address - must match whatever was passed to
// AddRouteForServerIPWithSource when the route was added (see
// RemoveRouteForNetworkConfigWithGateway).
func RemoveRouteForServerIPWithSource(serverIP string, interfaceName string, sourceIP string) error {
	if interfaceName == "" {
		return nil
	}

	if err := RemoveRouteForNetworkConfigWithGateway(serverIP, sourceIP); err != nil {
		return err
	}

	// TODO: does this also need to be ios?
	if runtime.GOOS == "darwin" { // macos requires routes for each peer to be added but this messes with other platforms
		return DarwinRemoveRoute(serverIP)
	}
	// else if runtime.GOOS == "windows" {
	// 	return WindowsRemoveRoute(serverIP, interfaceName)
	// } else if runtime.GOOS == "linux" {
	// 	return LinuxRemoveRoute(serverIP, interfaceName)
	// }
	return nil
}

func AddRouteForNetworkConfig(destination string) error {
	return AddRouteForNetworkConfigWithGateway(destination, "")
}

// AddRouteForNetworkConfigWithGateway is AddRouteForNetworkConfig with an
// explicit gateway address for the route entry surfaced via NetworkSettings.
// This is consumed by mobile (iOS/macOS NetworkExtension) packet-tunnel
// providers as NEIPv4Route.gatewayAddress. NetworkExtension gives us no
// direct way to pin a route's source address (no equivalent of BSD's `route
// -ifa`) - but setting gatewayAddress to one of the tunnel interface's own
// addresses makes the OS resolve "how do I reach this gateway" recursively
// to that address/interface pairing, which is what determines the source
// address used for packets matching the route. This is the same underlying
// mechanism as `route add -gateway` (see DarwinAddRoute's gateway branch).
func AddRouteForNetworkConfigWithGateway(destination string, gateway string) error {
	// Parse the subnet to extract IP and mask
	_, ipNet, err := net.ParseCIDR(destination)
	if err != nil {
		return fmt.Errorf("failed to parse subnet %s: %v", destination, err)
	}

	// Convert CIDR mask to dotted decimal format (e.g., 255.255.255.0)
	mask := net.IP(ipNet.Mask).String()
	destinationAddress := ipNet.IP.String()

	AddIPv4IncludedRoute(IPv4Route{DestinationAddress: destinationAddress, SubnetMask: mask, GatewayAddress: gateway})

	return nil
}

func RemoveRouteForNetworkConfig(destination string) error {
	return RemoveRouteForNetworkConfigWithGateway(destination, "")
}

// RemoveRouteForNetworkConfigWithGateway is RemoveRouteForNetworkConfig with
// an explicit gateway address. This must match whatever gateway the route was
// added with (see AddRouteForNetworkConfigWithGateway) - RemoveIPv4IncludedRoute
// matches by full struct equality, so a mismatched gateway means the entry is
// silently never found/removed.
func RemoveRouteForNetworkConfigWithGateway(destination string, gateway string) error {
	// Parse the subnet to extract IP and mask
	_, ipNet, err := net.ParseCIDR(destination)
	if err != nil {
		return fmt.Errorf("failed to parse subnet %s: %v", destination, err)
	}

	// Convert CIDR mask to dotted decimal format (e.g., 255.255.255.0)
	mask := net.IP(ipNet.Mask).String()
	destinationAddress := ipNet.IP.String()

	RemoveIPv4IncludedRoute(IPv4Route{DestinationAddress: destinationAddress, SubnetMask: mask, GatewayAddress: gateway})

	return nil
}

// addRoutes adds routes for each subnet in RemoteSubnets
func AddRoutes(remoteSubnets []string, interfaceName string) error {
	return AddRoutesWithSource(remoteSubnets, interfaceName, "")
}

// AddRoutesWithSource is AddRoutes with an explicit source address for the
// darwin routes (see DarwinAddRouteWithSource) - needed when the interface
// carries more than one address (e.g. a site tunnel address alongside an
// exit node's secondary address), so the routes for these subnets are pinned
// to the address they actually belong to rather than whichever address
// darwin would otherwise default to.
func AddRoutesWithSource(remoteSubnets []string, interfaceName string, sourceIP string) error {
	if len(remoteSubnets) == 0 {
		return nil
	}

	// Add routes for each subnet
	for _, subnet := range remoteSubnets {
		subnet = strings.TrimSpace(subnet)
		if subnet == "" {
			continue
		}

		if err := AddRouteForNetworkConfig(subnet); err != nil {
			logger.Error("Failed to add network config for subnet %s: %v", subnet, err)
			continue
		}

		// Add route based on operating system
		if interfaceName == "" {
			continue
		}

		switch runtime.GOOS {
		case "darwin":
			if err := DarwinAddRouteWithSource(subnet, "", interfaceName, sourceIP); err != nil {
				logger.Error("Failed to add Darwin route for subnet %s: %v", subnet, err)
			}
		case "windows":
			if err := WindowsAddRoute(subnet, "", interfaceName); err != nil {
				logger.Error("Failed to add Windows route for subnet %s: %v", subnet, err)
			}
		case "linux":
			if err := LinuxAddRoute(subnet, "", interfaceName); err != nil {
				logger.Error("Failed to add Linux route for subnet %s: %v", subnet, err)
			}
		case "android", "ios":
			// Routes handled by the OS/VPN service
			continue
		}

		logger.Info("Added route for remote subnet: %s", subnet)
	}
	return nil
}

// removeRoutesForRemoteSubnets removes routes for each subnet in RemoteSubnets.
// interfaceName must match the interface the routes were added on (see
// AddRoutes) so that only the routes we own are deleted, never an unrelated
// local/native route to the same destination on another interface.
func RemoveRoutes(remoteSubnets []string, interfaceName string) error {
	if len(remoteSubnets) == 0 {
		return nil
	}

	// Remove routes for each subnet
	for _, subnet := range remoteSubnets {
		subnet = strings.TrimSpace(subnet)
		if subnet == "" {
			continue
		}

		if err := RemoveRouteForNetworkConfig(subnet); err != nil {
			logger.Error("Failed to remove network config for subnet %s: %v", subnet, err)
			continue
		}

		// Remove route based on operating system
		switch runtime.GOOS {
		case "darwin":
			if err := DarwinRemoveRoute(subnet); err != nil {
				logger.Error("Failed to remove Darwin route for subnet %s: %v", subnet, err)
			}
		case "windows":
			if err := WindowsRemoveRoute(subnet, interfaceName); err != nil {
				logger.Error("Failed to remove Windows route for subnet %s: %v", subnet, err)
			}
		case "linux":
			if err := LinuxRemoveRoute(subnet, interfaceName); err != nil {
				logger.Error("Failed to remove Linux route for subnet %s: %v", subnet, err)
			}
		case "android", "ios":
			// Routes handled by the OS/VPN service
			continue
		}

		logger.Info("Removed route for remote subnet: %s", subnet)
	}

	return nil
}
