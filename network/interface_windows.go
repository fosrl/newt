//go:build windows

package network

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/fosrl/newt/logger"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func configureWindows(interfaceName string, ip net.IP, ipNet *net.IPNet) error {
	logger.Info("Configuring Windows interface: %s", interfaceName)

	// Get the LUID for the interface
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get interface %s: %v", interfaceName, err)
	}

	luid, err := winipcfg.LUIDFromIndex(uint32(iface.Index))
	if err != nil {
		return fmt.Errorf("failed to get LUID for interface %s: %v", interfaceName, err)
	}

	// Create the IP address prefix
	maskBits, _ := ipNet.Mask.Size()

	// Ensure we convert to the correct IP version (IPv4 vs IPv6)
	var addr netip.Addr
	if ip4 := ip.To4(); ip4 != nil {
		// IPv4 address
		addr, _ = netip.AddrFromSlice(ip4)
	} else {
		// IPv6 address
		addr, _ = netip.AddrFromSlice(ip)
	}
	if !addr.IsValid() {
		return fmt.Errorf("failed to convert IP address")
	}
	prefix := netip.PrefixFrom(addr, maskBits)

	// Add the IP address to the interface
	logger.Info("Adding IP address %s to interface %s", prefix.String(), interfaceName)
	err = luid.AddIPAddress(prefix)
	if err != nil {
		return fmt.Errorf("failed to add IP address: %v", err)
	}

	// This was required when we were using the subprocess "netsh" command to bring up the interface.
	// With the winipcfg library, the interface should already be up after adding the IP so we dont
	// need this step anymore as far as I can tell.

	// // Wait for the interface to be up and have the correct IP
	// err = waitForInterfaceUp(interfaceName, ip, 30*time.Second)
	// if err != nil {
	// 	return fmt.Errorf("interface did not come up within timeout: %v", err)
	// }

	return nil
}
