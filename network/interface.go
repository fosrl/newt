package network

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"time"

	"github.com/fosrl/newt/logger"
	"github.com/vishvananda/netlink"
)

// ConfigureInterface configures a network interface with an IP address and brings it up
func ConfigureInterface(interfaceName string, tunnelIp string, mtu int) error {
	logger.Info("The tunnel IP is: %s", tunnelIp)

	// Parse the IP address and network using netip
	prefix, err := netip.ParsePrefix(tunnelIp)
	if err != nil {
		return fmt.Errorf("invalid IP address: %v", err)
	}

	// Convert CIDR mask to dotted decimal format (e.g., 255.255.255.0)
	mask := prefixToMaskString(prefix)
	destinationAddress := prefix.Addr().String()

	logger.Debug("The destination address is: %s", destinationAddress)

	// network.SetTunnelRemoteAddress() // what does this do?
	SetIPv4Settings([]string{destinationAddress}, []string{mask})
	SetMTU(mtu)

	if interfaceName == "" {
		return nil
	}

	switch runtime.GOOS {
	case "linux":
		return configureLinux(interfaceName, prefix)
	case "darwin":
		return configureDarwin(interfaceName, prefix)
	case "windows":
		return configureWindows(interfaceName, prefix)
	case "android":
		return nil
	case "ios":
		return nil
	}

	return nil
}

// prefixToMaskString converts a netip.Prefix to a dotted decimal subnet mask string
func prefixToMaskString(prefix netip.Prefix) string {
	bits := prefix.Bits()
	if prefix.Addr().Is4() {
		mask := net.CIDRMask(bits, 32)
		return net.IP(mask).String()
	}
	// For IPv6, return the prefix length as we don't typically use dotted decimal
	return fmt.Sprintf("/%d", bits)
}

// waitForInterfaceUp polls the network interface until it's up or times out
func waitForInterfaceUp(interfaceName string, expectedIP netip.Addr, timeout time.Duration) error {
	logger.Info("Waiting for interface %s to be up with IP %s", interfaceName, expectedIP)
	deadline := time.Now().Add(timeout)
	pollInterval := 500 * time.Millisecond

	for time.Now().Before(deadline) {
		// Check if interface exists and is up
		iface, err := net.InterfaceByName(interfaceName)
		if err == nil {
			// Check if interface is up
			if iface.Flags&net.FlagUp != 0 {
				// Check if it has the expected IP
				addrs, err := iface.Addrs()
				if err == nil {
					for _, addr := range addrs {
						ipNet, ok := addr.(*net.IPNet)
						if ok {
							if ifaceAddr, ok := netip.AddrFromSlice(ipNet.IP); ok {
								// Unmap IPv4-mapped IPv6 addresses for comparison
								if ifaceAddr.Unmap() == expectedIP.Unmap() {
									logger.Info("Interface %s is up with correct IP", interfaceName)
									return nil // Interface is up with correct IP
								}
							}
						}
					}
					logger.Info("Interface %s is up but doesn't have expected IP yet", interfaceName)
				}
			} else {
				logger.Info("Interface %s exists but is not up yet", interfaceName)
			}
		} else {
			logger.Info("Interface %s not found yet: %v", interfaceName, err)
		}

		// Wait before next check
		time.Sleep(pollInterval)
	}

	return fmt.Errorf("timed out waiting for interface %s to be up with IP %s", interfaceName, expectedIP)
}

func FindUnusedUTUN() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("failed to list interfaces: %v", err)
	}
	used := make(map[int]bool)
	re := regexp.MustCompile(`^utun(\d+)$`)
	for _, iface := range ifaces {
		if matches := re.FindStringSubmatch(iface.Name); len(matches) == 2 {
			if num, err := strconv.Atoi(matches[1]); err == nil {
				used[num] = true
			}
		}
	}
	// Try utun0 up to utun255.
	for i := 0; i < 256; i++ {
		if !used[i] {
			return fmt.Sprintf("utun%d", i), nil
		}
	}
	return "", fmt.Errorf("no unused utun interface found")
}

func configureDarwin(interfaceName string, prefix netip.Prefix) error {
	logger.Info("Configuring darwin interface: %s", interfaceName)

	ipStr := prefix.String()
	ip := prefix.Addr().String()

	cmd := exec.Command("ifconfig", interfaceName, "inet", ipStr, ip, "alias")
	logger.Info("Running command: %v", cmd)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ifconfig command failed: %v, output: %s", err, out)
	}

	// Bring up the interface
	cmd = exec.Command("ifconfig", interfaceName, "up")
	logger.Info("Running command: %v", cmd)

	out, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ifconfig up command failed: %v, output: %s", err, out)
	}

	return nil
}

func configureLinux(interfaceName string, prefix netip.Prefix) error {
	// Get the interface
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get interface %s: %v", interfaceName, err)
	}

	// Convert netip.Prefix to net.IPNet for netlink library
	ipNet := prefixToIPNet(prefix)

	// Create the IP address attributes
	addr := &netlink.Addr{
		IPNet: ipNet,
	}

	// Add the IP address to the interface
	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("failed to add IP address: %v", err)
	}

	// Bring up the interface
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to bring up interface: %v", err)
	}

	return nil
}

// prefixToIPNet converts a netip.Prefix to a *net.IPNet for compatibility with netlink
func prefixToIPNet(prefix netip.Prefix) *net.IPNet {
	addr := prefix.Addr()
	bits := prefix.Bits()
	if addr.Is4() {
		ip := addr.As4()
		return &net.IPNet{
			IP:   net.IP(ip[:]),
			Mask: net.CIDRMask(bits, 32),
		}
	}
	ip := addr.As16()
	return &net.IPNet{
		IP:   net.IP(ip[:]),
		Mask: net.CIDRMask(bits, 128),
	}
}
