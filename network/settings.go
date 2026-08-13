package network

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/fosrl/newt/logger"
)

// NetworkSettings represents the network configuration for the tunnel
type NetworkSettings struct {
	TunnelRemoteAddress string      `json:"tunnel_remote_address,omitempty"`
	MTU                 *int        `json:"mtu,omitempty"`
	DNSServers          []string    `json:"dns_servers,omitempty"`
	IPv4Addresses       []string    `json:"ipv4_addresses,omitempty"`
	IPv4SubnetMasks     []string    `json:"ipv4_subnet_masks,omitempty"`
	IPv4IncludedRoutes  []IPv4Route `json:"ipv4_included_routes,omitempty"`
	IPv4ExcludedRoutes  []IPv4Route `json:"ipv4_excluded_routes,omitempty"`
	IPv6Addresses       []string    `json:"ipv6_addresses,omitempty"`
	IPv6NetworkPrefixes []string    `json:"ipv6_network_prefixes,omitempty"`
	IPv6IncludedRoutes  []IPv6Route `json:"ipv6_included_routes,omitempty"`
	IPv6ExcludedRoutes  []IPv6Route `json:"ipv6_excluded_routes,omitempty"`
}

// IPv4Route represents an IPv4 route
type IPv4Route struct {
	DestinationAddress string `json:"destination_address"`
	SubnetMask         string `json:"subnet_mask,omitempty"`
	GatewayAddress     string `json:"gateway_address,omitempty"`
	IsDefault          bool   `json:"is_default,omitempty"`
}

// IPv6Route represents an IPv6 route
type IPv6Route struct {
	DestinationAddress  string `json:"destination_address"`
	NetworkPrefixLength int    `json:"network_prefix_length,omitempty"`
	GatewayAddress      string `json:"gateway_address,omitempty"`
	IsDefault           bool   `json:"is_default,omitempty"`
}

var (
	networkSettings      NetworkSettings
	networkSettingsMutex sync.RWMutex
	incrementor          int
)

// SetTunnelRemoteAddress sets the tunnel remote address
func SetTunnelRemoteAddress(address string) {
	networkSettingsMutex.Lock()
	defer networkSettingsMutex.Unlock()
	networkSettings.TunnelRemoteAddress = address
	incrementor++
	logger.Info("Set tunnel remote address: %s", address)
}

// SetMTU sets the MTU value
func SetMTU(mtu int) {
	networkSettingsMutex.Lock()
	defer networkSettingsMutex.Unlock()
	networkSettings.MTU = &mtu
	incrementor++
	logger.Info("Set MTU: %d", mtu)
}

// SetDNSServers sets the DNS servers
func SetDNSServers(servers []string) {
	networkSettingsMutex.Lock()
	defer networkSettingsMutex.Unlock()
	networkSettings.DNSServers = servers
	incrementor++
	logger.Info("Set DNS servers: %v", servers)
}

// SetIPv4Settings sets IPv4 addresses and subnet masks
func SetIPv4Settings(addresses []string, subnetMasks []string) {
	networkSettingsMutex.Lock()
	defer networkSettingsMutex.Unlock()
	networkSettings.IPv4Addresses = addresses
	networkSettings.IPv4SubnetMasks = subnetMasks
	incrementor++
	logger.Info("Set IPv4 addresses: %v, subnet masks: %v", addresses, subnetMasks)
}

// AddIPv4Address appends an additional IPv4 address/subnet mask pair to the
// tunnel's network settings. This is how a secondary interface address gets
// exposed to mobile (iOS/Android) packet-tunnel providers, which read the
// full IPv4Addresses/IPv4SubnetMasks arrays (not just the first entry) and
// re-apply them on every settings poll.
//
// It requires a primary address to already be set (via SetIPv4Settings,
// i.e. ConfigureInterface) and refuses to add otherwise: on mobile
// platforms, array order is what determines which address the OS treats as
// primary, so appending to an empty list would silently make this
// "additional" address the primary one instead.
func AddIPv4Address(address string, subnetMask string) error {
	networkSettingsMutex.Lock()
	defer networkSettingsMutex.Unlock()

	if len(networkSettings.IPv4Addresses) == 0 {
		return fmt.Errorf("cannot add secondary IPv4 address %s: no primary address configured yet", address)
	}

	for _, a := range networkSettings.IPv4Addresses {
		if a == address {
			logger.Info("IPv4 address already exists: %s", address)
			return nil
		}
	}

	networkSettings.IPv4Addresses = append(networkSettings.IPv4Addresses, address)
	networkSettings.IPv4SubnetMasks = append(networkSettings.IPv4SubnetMasks, subnetMask)
	incrementor++
	logger.Info("Added IPv4 address: %s/%s", address, subnetMask)
	return nil
}

// RemoveIPv4Address removes a previously added secondary IPv4 address.
func RemoveIPv4Address(address string) {
	networkSettingsMutex.Lock()
	defer networkSettingsMutex.Unlock()

	for i, a := range networkSettings.IPv4Addresses {
		if a == address {
			networkSettings.IPv4Addresses = append(networkSettings.IPv4Addresses[:i], networkSettings.IPv4Addresses[i+1:]...)
			networkSettings.IPv4SubnetMasks = append(networkSettings.IPv4SubnetMasks[:i], networkSettings.IPv4SubnetMasks[i+1:]...)
			incrementor++
			logger.Info("Removed IPv4 address: %s", address)
			return
		}
	}
	logger.Info("IPv4 address not found for removal: %s", address)
}

// SetIPv4IncludedRoutes sets the included IPv4 routes
func SetIPv4IncludedRoutes(routes []IPv4Route) {
	networkSettingsMutex.Lock()
	defer networkSettingsMutex.Unlock()
	networkSettings.IPv4IncludedRoutes = routes
	incrementor++
	logger.Info("Set IPv4 included routes: %d routes", len(routes))
}

func AddIPv4IncludedRoute(route IPv4Route) {
	networkSettingsMutex.Lock()
	defer networkSettingsMutex.Unlock()

	// make sure it does not already exist
	for _, r := range networkSettings.IPv4IncludedRoutes {
		if r == route {
			logger.Info("IPv4 included route already exists: %+v", route)
			return
		}
	}

	networkSettings.IPv4IncludedRoutes = append(networkSettings.IPv4IncludedRoutes, route)
	incrementor++
	logger.Info("Added IPv4 included route: %+v", route)
}

func RemoveIPv4IncludedRoute(route IPv4Route) {
	networkSettingsMutex.Lock()
	defer networkSettingsMutex.Unlock()
	routes := networkSettings.IPv4IncludedRoutes
	for i, r := range routes {
		if r == route {
			networkSettings.IPv4IncludedRoutes = append(routes[:i], routes[i+1:]...)
			logger.Info("Removed IPv4 included route: %+v", route)
			break
		}
	}
	incrementor++
	logger.Info("IPv4 included route not found for removal: %+v", route)
}

func SetIPv4ExcludedRoutes(routes []IPv4Route) {
	networkSettingsMutex.Lock()
	defer networkSettingsMutex.Unlock()
	networkSettings.IPv4ExcludedRoutes = routes
	incrementor++
	logger.Info("Set IPv4 excluded routes: %d routes", len(routes))
}

// SetIPv6Settings sets IPv6 addresses and network prefixes
func SetIPv6Settings(addresses []string, networkPrefixes []string) {
	networkSettingsMutex.Lock()
	defer networkSettingsMutex.Unlock()
	networkSettings.IPv6Addresses = addresses
	networkSettings.IPv6NetworkPrefixes = networkPrefixes
	incrementor++
	logger.Info("Set IPv6 addresses: %v, network prefixes: %v", addresses, networkPrefixes)
}

// SetIPv6IncludedRoutes sets the included IPv6 routes
func SetIPv6IncludedRoutes(routes []IPv6Route) {
	networkSettingsMutex.Lock()
	defer networkSettingsMutex.Unlock()
	networkSettings.IPv6IncludedRoutes = routes
	incrementor++
	logger.Info("Set IPv6 included routes: %d routes", len(routes))
}

// SetIPv6ExcludedRoutes sets the excluded IPv6 routes
func SetIPv6ExcludedRoutes(routes []IPv6Route) {
	networkSettingsMutex.Lock()
	defer networkSettingsMutex.Unlock()
	networkSettings.IPv6ExcludedRoutes = routes
	incrementor++
	logger.Info("Set IPv6 excluded routes: %d routes", len(routes))
}

// ClearNetworkSettings clears all network settings
func ClearNetworkSettings() {
	networkSettingsMutex.Lock()
	defer networkSettingsMutex.Unlock()
	networkSettings = NetworkSettings{}
	incrementor++
	logger.Info("Cleared all network settings")
}

func GetJSON() (string, error) {
	networkSettingsMutex.RLock()
	defer networkSettingsMutex.RUnlock()
	data, err := json.MarshalIndent(networkSettings, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func GetSettings() NetworkSettings {
	networkSettingsMutex.RLock()
	defer networkSettingsMutex.RUnlock()
	return networkSettings
}

func GetIncrementor() int {
	networkSettingsMutex.Lock()
	defer networkSettingsMutex.Unlock()
	return incrementor
}
