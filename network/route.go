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

func DarwinAddRoute(destination string, gateway string, interfaceName string) error {
	if runtime.GOOS != "darwin" {
		return nil
	}

	var cmd *exec.Cmd

	if gateway != "" {
		// Route with specific gateway
		cmd = exec.Command("route", "-q", "-n", "add", "-inet", destination, "-gateway", gateway)
	} else if interfaceName != "" {
		// Route via interface
		cmd = exec.Command("route", "-q", "-n", "add", "-inet", destination, "-interface", interfaceName)
	} else {
		return fmt.Errorf("either gateway or interface must be specified")
	}

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

	metric := linuxDefaultTunnelRouteMetric
	if gateway == "" && interfaceName != "" {
		if m, overlap, err := linuxTunnelRouteMetric(destination, interfaceName); err != nil {
			logger.Warn("Failed to check local subnet overlap for %s: %v; using high metric", destination, err)
			metric = linuxOverlapTunnelRouteMetric
		} else {
			metric = m
			if overlap {
				logger.Warn("Remote subnet %s overlaps a local LAN subnet; adding tunnel route with metric %d", destination, metric)
			}
		}
	}

	_, ipNet, err := net.ParseCIDR(destination)
	if err != nil {
		return fmt.Errorf("invalid destination address: %v", err)
	}

	route := &netlink.Route{Dst: ipNet, Priority: metric}

	if gateway != "" {
		gw := net.ParseIP(gateway)
		if gw == nil {
			return fmt.Errorf("invalid gateway address: %s", gateway)
		}
		route.Gw = gw
		logger.Info("Adding route to %s via gateway %s (metric %d)", destination, gateway, metric)
	} else if interfaceName != "" {
		link, err := netlink.LinkByName(interfaceName)
		if err != nil {
			return fmt.Errorf("failed to get interface %s: %v", interfaceName, err)
		}
		route.LinkIndex = link.Attrs().Index
		logger.Info("Adding route to %s via interface %s (metric %d)", destination, interfaceName, metric)
	} else {
		return fmt.Errorf("either gateway or interface must be specified")
	}

	if err := netlink.RouteAdd(route); err != nil {
		return fmt.Errorf("failed to add route: %v", err)
	}
	return nil
}

func LinuxRemoveRoute(destination string, interfaceName ...string) error {
	if runtime.GOOS != "linux" {
		return nil
	}

	_, ipNet, err := net.ParseCIDR(destination)
	if err != nil {
		return fmt.Errorf("invalid destination address: %v", err)
	}

	routes, err := netlink.RouteList(nil, linuxRouteFamily(ipNet))
	if err != nil {
		return fmt.Errorf("failed to list routes: %w", err)
	}

	targetLinkIndex := 0
	if len(interfaceName) > 0 && interfaceName[0] != "" {
		link, err := netlink.LinkByName(interfaceName[0])
		if err != nil {
			return fmt.Errorf("failed to get interface %s: %w", interfaceName[0], err)
		}
		targetLinkIndex = link.Attrs().Index
	}

	logger.Info("Removing route to %s", destination)
	var matches []netlink.Route
	linkIndexes := make(map[int]struct{})
	for _, route := range routes {
		if route.Dst == nil || route.Dst.String() != ipNet.String() {
			continue
		}
		if route.Priority != linuxDefaultTunnelRouteMetric && route.Priority != linuxOverlapTunnelRouteMetric {
			continue
		}
		if targetLinkIndex != 0 && route.LinkIndex != targetLinkIndex {
			continue
		}
		matches = append(matches, route)
		linkIndexes[route.LinkIndex] = struct{}{}
	}
	if targetLinkIndex == 0 && len(linkIndexes) > 1 {
		return fmt.Errorf("multiple tunnel routes to %s found; interface name is required", destination)
	}

	var delErr error
	removed := 0
	for _, route := range matches {
		del := &netlink.Route{
			Dst:       route.Dst,
			LinkIndex: route.LinkIndex,
			Priority:  route.Priority,
		}
		if err := netlink.RouteDel(del); err != nil {
			delErr = errors.Join(delErr, fmt.Errorf("failed to delete route: %w", err))
			continue
		}
		removed++
	}
	if removed == 0 && delErr == nil {
		return fmt.Errorf("tunnel route to %s not found", destination)
	}
	return delErr
}

// addRouteForServerIP adds an OS-specific route for the server IP
func AddRouteForServerIP(serverIP, interfaceName string) error {
	if interfaceName == "" {
		return nil
	}
	// TODO: does this also need to be ios?
	if runtime.GOOS == "darwin" { // macos requires routes for each peer to be added but this messes with other platforms
		if err := AddRouteForNetworkConfig(serverIP); err != nil {
			return err
		}
		return DarwinAddRoute(serverIP, "", interfaceName)
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
	if interfaceName == "" {
		return nil
	}
	// TODO: does this also need to be ios?
	if runtime.GOOS == "darwin" { // macos requires routes for each peer to be added but this messes with other platforms
		if err := RemoveRouteForNetworkConfig(serverIP); err != nil {
			return err
		}
		return DarwinRemoveRoute(serverIP)
	}
	// else if runtime.GOOS == "windows" {
	// 	return WindowsRemoveRoute(serverIP)
	// } else if runtime.GOOS == "linux" {
	// 	return LinuxRemoveRoute(serverIP)
	// }
	return nil
}

func AddRouteForNetworkConfig(destination string) error {
	// Parse the subnet to extract IP and mask
	_, ipNet, err := net.ParseCIDR(destination)
	if err != nil {
		return fmt.Errorf("failed to parse subnet %s: %v", destination, err)
	}

	// Convert CIDR mask to dotted decimal format (e.g., 255.255.255.0)
	mask := net.IP(ipNet.Mask).String()
	destinationAddress := ipNet.IP.String()

	AddIPv4IncludedRoute(IPv4Route{DestinationAddress: destinationAddress, SubnetMask: mask})

	return nil
}

func RemoveRouteForNetworkConfig(destination string) error {
	// Parse the subnet to extract IP and mask
	_, ipNet, err := net.ParseCIDR(destination)
	if err != nil {
		return fmt.Errorf("failed to parse subnet %s: %v", destination, err)
	}

	// Convert CIDR mask to dotted decimal format (e.g., 255.255.255.0)
	mask := net.IP(ipNet.Mask).String()
	destinationAddress := ipNet.IP.String()

	RemoveIPv4IncludedRoute(IPv4Route{DestinationAddress: destinationAddress, SubnetMask: mask})

	return nil
}

// addRoutes adds routes for each subnet in RemoteSubnets
func AddRoutes(remoteSubnets []string, interfaceName string) error {
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
			if err := DarwinAddRoute(subnet, "", interfaceName); err != nil {
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

// removeRoutesForRemoteSubnets removes routes for each subnet in RemoteSubnets
func RemoveRoutes(remoteSubnets []string, interfaceName ...string) error {
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
			if err := WindowsRemoveRoute(subnet); err != nil {
				logger.Error("Failed to remove Windows route for subnet %s: %v", subnet, err)
			}
		case "linux":
			if err := LinuxRemoveRoute(subnet, interfaceName...); err != nil {
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
