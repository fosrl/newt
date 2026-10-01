package network

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"

	"github.com/fosrl/newt/logger"
	"github.com/vishvananda/netlink"
)

// rtnUnicast (RTN_UNICAST, a regular gateway or directly-connected route)
// and familyV4 (AF_INET) are the Linux netlink values. Defined here rather
// than taken from golang.org/x/sys/unix or netlink.FAMILY_V4 because this
// file also builds on platforms where those aren't defined.
const (
	rtnUnicast = 1
	familyV4   = 2
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

// ErrNoPhysicalRoute is returned (wrapped) when a bypass route can't be
// installed or reconciled because there is currently no route to the
// destination outside the tunnel - typically because the host is offline or
// between networks. Callers can treat it as transient: the next reconcile
// after the network comes back installs the route.
var ErrNoPhysicalRoute = errors.New("no route outside the tunnel")

// LinuxAddBypassRoute adds an explicit /32 host route for destIP via
// whatever gateway/interface the kernel currently uses to reach it, so a
// broader route added afterward (e.g. a gateway/full-tunnel default route)
// can never capture this destination - see AddBypassRouteForDestination.
// Routes on tunnelInterface are ignored when picking that path - see
// linuxBypassNextHop. Replaces any existing /32 route to destIP.
func LinuxAddBypassRoute(destIP string, tunnelInterface string) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	_, err := linuxEnsureBypassRoute(destIP, tunnelInterface)
	return err
}

// linuxEnsureBypassRoute makes the /32 route to destIP match the current
// physical path (see linuxBypassNextHop), replacing or adding it as needed.
// Returns whether the routing table was changed.
func linuxEnsureBypassRoute(destIP string, tunnelInterface string) (bool, error) {
	ip := net.ParseIP(destIP).To4()
	if ip == nil {
		return false, fmt.Errorf("invalid IPv4 destination address: %s", destIP)
	}

	routes, err := netlink.RouteList(nil, familyV4)
	if err != nil {
		return false, fmt.Errorf("failed to list routes: %v", err)
	}

	tunnelIndex := -1
	if tunnelInterface != "" {
		if link, err := netlink.LinkByName(tunnelInterface); err == nil {
			tunnelIndex = link.Attrs().Index
		}
	}

	gw, linkIndex, err := linuxBypassNextHop(routes, ip, tunnelIndex)
	if err != nil {
		return false, err
	}

	for _, r := range routes {
		if isHostRouteTo(r.Dst, ip) && r.LinkIndex == linkIndex && r.Gw.Equal(gw) {
			return false, nil
		}
	}

	link, err := netlink.LinkByIndex(linkIndex)
	if err != nil {
		return false, fmt.Errorf("failed to resolve interface for route to %s: %v", destIP, err)
	}

	route := &netlink.Route{
		Dst:       &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)},
		Gw:        gw,
		LinkIndex: linkIndex,
	}

	logger.Info("Setting bypass route to %s via %s (interface %s)", destIP, gw, link.Attrs().Name)

	if err := netlink.RouteReplace(route); err != nil {
		return false, fmt.Errorf("failed to set bypass route to %s: %v", destIP, err)
	}

	return true, nil
}

// linuxBypassNextHop picks, from the main-table routes, the gateway and
// interface the kernel would use to reach ip if neither the tunnel nor our
// own bypass route existed: the most specific unicast route containing ip,
// lowest metric first, skipping any route on tunnelIndex and any /32 route to
// ip itself. While a gateway route (0.0.0.0/1 + 128.0.0.0/1 on the tunnel)
// is installed, that is normally the untouched physical 0.0.0.0/0 default
// route, which the gateway route deliberately leaves in place. Skipping our
// own /32 lets the same lookup tell whether an existing bypass route still
// matches the current physical path (see linuxEnsureBypassRoute). Policy
// routing rules are not considered.
func linuxBypassNextHop(routes []netlink.Route, ip net.IP, tunnelIndex int) (net.IP, int, error) {
	var best *netlink.Route
	bestBits := -1
	for i := range routes {
		r := &routes[i]
		if r.Type != rtnUnicast || isHostRouteTo(r.Dst, ip) {
			continue
		}
		bits := 0
		if r.Dst != nil {
			if !r.Dst.Contains(ip) {
				continue
			}
			bits, _ = r.Dst.Mask.Size()
		}
		gw, linkIndex := r.Gw, r.LinkIndex
		if linkIndex == 0 && len(r.MultiPath) > 0 {
			gw, linkIndex = r.MultiPath[0].Gw, r.MultiPath[0].LinkIndex
		}
		if linkIndex == 0 || linkIndex == tunnelIndex {
			continue
		}
		if bits > bestBits || (bits == bestBits && r.Priority < best.Priority) {
			route := *r
			route.Gw, route.LinkIndex = gw, linkIndex
			best = &route
			bestBits = bits
		}
	}
	if best == nil {
		return nil, 0, fmt.Errorf("%w: %s", ErrNoPhysicalRoute, ip)
	}
	return best.Gw, best.LinkIndex, nil
}

// isHostRouteTo reports whether dst is exactly ip/32.
func isHostRouteTo(dst *net.IPNet, ip net.IP) bool {
	if dst == nil {
		return false
	}
	ones, bits := dst.Mask.Size()
	return ones == 32 && bits == 32 && dst.IP.Equal(ip)
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
// this destination - see AddBypassRouteForDestination. If that route is on
// tunnelInterface - i.e. a gateway route (0.0.0.0/1 + 128.0.0.0/1) is already
// capturing destIP - the physical default route, which the gateway route
// deliberately leaves in place, is used instead (see darwinBypassNextHop).
func DarwinAddBypassRoute(destIP string, tunnelInterface string) error {
	if runtime.GOOS != "darwin" {
		return nil
	}
	if NativeConfigDisabled {
		return nil
	}
	_, err := darwinEnsureBypassRoute(destIP, tunnelInterface)
	return err
}

// darwinEnsureBypassRoute makes the /32 route to destIP match the current
// physical path, adding it if missing and replacing it if it points
// somewhere else. Returns whether the routing table was changed.
func darwinEnsureBypassRoute(destIP string, tunnelInterface string) (bool, error) {
	ip := net.ParseIP(destIP).To4()
	if ip == nil {
		return false, fmt.Errorf("invalid IPv4 destination address: %s", destIP)
	}

	current, err := darwinRouteGet(destIP)
	if err != nil {
		return false, err
	}
	installed := current.isStaticHostRouteTo(ip)

	var gateway, iface string
	if installed {
		// `route get` now just finds our own route, so work the physical
		// path out without it.
		gateway, iface, err = darwinBypassNextHop(ip, tunnelInterface)
		if err != nil {
			return false, err
		}
		if iface == current.iface && (gateway == "" || gateway == current.gateway) {
			return false, nil
		}
		if err := DarwinRemoveRoute(destIP + "/32"); err != nil {
			return false, err
		}
	} else {
		gateway, iface = current.gateway, current.iface
		if net.ParseIP(gateway) == nil {
			// On-link (e.g. an ARP entry's link-layer "gateway"): route
			// via the interface itself.
			gateway = ""
		}
		if tunnelInterface != "" && iface == tunnelInterface {
			gateway, iface, err = darwinBypassNextHop(ip, tunnelInterface)
			if err != nil {
				return false, err
			}
		}
	}

	if err := DarwinAddRouteWithSource(destIP+"/32", gateway, iface, ""); err != nil {
		return false, err
	}
	return true, nil
}

// darwinBypassNextHop returns the physical path to ip without consulting
// any more specific route to it (ours, or the tunnel's): directly on-link
// through a non-tunnel interface whose subnet contains ip, otherwise the
// unscoped default route - which a gateway route (0.0.0.0/1 + 128.0.0.0/1)
// deliberately leaves in place. Other, more specific non-default routes are
// not considered.
func darwinBypassNextHop(ip net.IP, tunnelInterface string) (gateway, iface string, err error) {
	if ifaces, err := net.Interfaces(); err == nil {
		for _, ifc := range ifaces {
			if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 || ifc.Name == tunnelInterface {
				continue
			}
			addrs, err := ifc.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil && ipNet.Contains(ip) {
					return "", ifc.Name, nil
				}
			}
		}
	}

	def, err := darwinRouteGet("default")
	if err != nil {
		return "", "", err
	}
	if def.iface == tunnelInterface {
		return "", "", fmt.Errorf("%w: %s", ErrNoPhysicalRoute, ip)
	}
	return def.gateway, def.iface, nil
}

// darwinRoute is the relevant part of `route -n get` output.
type darwinRoute struct {
	destination, mask, gateway, iface string
	flags                             []string
}

// isStaticHostRouteTo reports whether r is a static /32 route to ip - i.e.
// one we added, as opposed to an ARP-cloned host entry or a broader route.
func (r darwinRoute) isStaticHostRouteTo(ip net.IP) bool {
	if !net.ParseIP(r.destination).Equal(ip) {
		return false
	}
	if r.mask != "" && r.mask != "255.255.255.255" {
		return false
	}
	for _, f := range r.flags {
		if f == "STATIC" {
			return true
		}
	}
	return false
}

// darwinRouteGet returns what `route -n get` reports for destination (an
// address, or "default").
func darwinRouteGet(destination string) (darwinRoute, error) {
	cmd := exec.Command("route", "-n", "get", destination)
	logger.Debug("Running command: %v", cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return darwinRoute{}, fmt.Errorf("%w: route get %s failed: %v, output: %s", ErrNoPhysicalRoute, destination, err, out)
	}

	var r darwinRoute
	for _, line := range strings.Split(string(out), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "destination":
			r.destination = value
		case "mask":
			r.mask = value
		case "gateway":
			r.gateway = value
		case "interface":
			r.iface = value
		case "flags":
			r.flags = strings.Split(strings.Trim(value, "<>"), ",")
		}
	}
	if r.gateway == "" && r.iface == "" {
		return darwinRoute{}, fmt.Errorf("could not determine current route to %s from `route get` output: %s", destination, out)
	}
	return r, nil
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
// tunnelInterface is the interface the gateway route is (or will be)
// installed on. Routes on it are ignored when looking up the current path to
// destIP, so a bypass route added while the gateway route is already
// installed still points at the physical network rather than back into the
// tunnel. May be "" if there is no tunnel interface to ignore.
//
// NetworkSettings is always populated (an excluded route, for mobile
// packet-tunnel providers), regardless of GOOS; the OS routing table is only
// touched on desktop platforms, which have no equivalent of
// NEIPv4Settings.excludedRoutes/VpnService.Builder.excludeRoute.
func AddBypassRouteForDestination(destIP string, tunnelInterface string) error {
	AddIPv4ExcludedRoute(IPv4Route{DestinationAddress: destIP, SubnetMask: "255.255.255.255"})

	switch runtime.GOOS {
	case "linux":
		return LinuxAddBypassRoute(destIP, tunnelInterface)
	case "darwin":
		return DarwinAddBypassRoute(destIP, tunnelInterface)
	case "windows":
		return WindowsAddBypassRoute(destIP, tunnelInterface)
	}
	return nil
}

// ReconcileBypassRoute makes sure the host route AddBypassRouteForDestination
// installed for destIP is still present and still follows the current
// physical path, re-adding or moving it if not. The OS drops these routes
// along with the interface or address they were on (e.g. switching Wi-Fi
// networks, or Wi-Fi to Ethernet), and if the default route moves to a
// different interface they would otherwise keep using the old one. Routes on
// tunnelInterface are ignored, as in AddBypassRouteForDestination. Returns
// whether anything changed; a no-op where ManagesHostRoutes is false.
// NetworkSettings is not touched - platforms that apply excluded routes from
// it track the physical network themselves.
func ReconcileBypassRoute(destIP string, tunnelInterface string) (bool, error) {
	if !ManagesHostRoutes() {
		return false, nil
	}
	switch runtime.GOOS {
	case "linux":
		return linuxEnsureBypassRoute(destIP, tunnelInterface)
	case "darwin":
		return darwinEnsureBypassRoute(destIP, tunnelInterface)
	case "windows":
		return windowsEnsureBypassRoute(destIP, tunnelInterface)
	}
	return false, nil
}

// ManagesHostRoutes reports whether this package installs routes in the host
// OS routing table itself (desktop platforms), as opposed to only populating
// NetworkSettings for a mobile/NetworkExtension host app to apply.
func ManagesHostRoutes() bool {
	switch runtime.GOOS {
	case "linux", "windows":
		return true
	case "darwin":
		return !NativeConfigDisabled
	}
	return false
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
