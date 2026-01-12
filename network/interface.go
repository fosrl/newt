package network

import (
	"fmt"
	"net"
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

	// Parse the IP address and network
	ip, ipNet, err := net.ParseCIDR(tunnelIp)
	if err != nil {
		return fmt.Errorf("invalid IP address: %v", err)
	}

	// Convert CIDR mask to dotted decimal format (e.g., 255.255.255.0)
	mask := net.IP(ipNet.Mask).String()
	destinationAddress := ip.String()

	logger.Debug("The destination address is: %s", destinationAddress)

	// network.SetTunnelRemoteAddress() // what does this do?
	SetIPv4Settings([]string{destinationAddress}, []string{mask})
	SetMTU(mtu)

	if interfaceName == "" {
		return nil
	}

	switch runtime.GOOS {
	case "linux":
		return configureLinux(interfaceName, ip, ipNet)
	case "darwin":
		return configureDarwin(interfaceName, ip, ipNet)
	case "windows":
		return configureWindows(interfaceName, ip, ipNet)
	case "android":
		return nil
	case "ios":
		return nil
	}

	return nil
}

// waitForInterfaceUp polls the network interface until it's up or times out
func waitForInterfaceUp(interfaceName string, expectedIP net.IP, timeout time.Duration) error {
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
						if ok && ipNet.IP.Equal(expectedIP) {
							logger.Info("Interface %s is up with correct IP", interfaceName)
							return nil // Interface is up with correct IP
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

func configureDarwin(interfaceName string, ip net.IP, ipNet *net.IPNet) error {
	logger.Info("Configuring darwin interface: %s", interfaceName)

	prefix, _ := ipNet.Mask.Size()
	ipStr := fmt.Sprintf("%s/%d", ip.String(), prefix)

	cmd := exec.Command("ifconfig", interfaceName, "inet", ipStr, ip.String(), "alias")
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

func configureLinux(interfaceName string, ip net.IP, ipNet *net.IPNet) error {
	// Get the interface
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get interface %s: %v", interfaceName, err)
	}

	// Create the IP address attributes
	addr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   ip,
			Mask: ipNet.Mask,
		},
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
