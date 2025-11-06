// Example of using netstack2 TCP/UDP proxying with WireGuard
//
// This example shows how to enable transparent TCP/UDP proxying
// through a WireGuard tunnel using netstack.
//
// Build: go build -o example examples/proxying/main.go
// Run: ./example

package main

import (
	"fmt"
	"log"
	"net/netip"

	"github.com/fosrl/newt/netstack2"
)

func main() {
	fmt.Println("Netstack2 TCP/UDP Proxying Examples")
	fmt.Println("====================================\n")

	// Example 1: Recommended - Subnet-based proxying (dual-interface)
	example1()

	// Example 2: Single interface with proxying (may conflict with WireGuard)
	example2()

	// Example 3: Enable proxying after creation (single interface)
	example3()

	// Example 4: Standard netstack without proxying (backward compatible)
	example4()
}

func example1() {
	fmt.Println("=== Example 1: Subnet-Based Proxying (Recommended) ===")
	fmt.Println("This approach avoids conflicts with WireGuard by using a secondary NIC")

	localAddresses := []netip.Addr{
		netip.MustParseAddr("10.0.0.2"),
	}
	dnsServers := []netip.Addr{
		netip.MustParseAddr("1.1.1.1"),
	}
	mtu := 1420

	// Create netstack normally (no proxying on main interface)
	tun, tnet, err := netstack2.CreateNetTUN(localAddresses, dnsServers, mtu)
	if err != nil {
		log.Fatalf("Failed to create netstack: %v", err)
	}
	defer tun.Close()

	fmt.Println("✓ Netstack created (WireGuard uses NIC 1)")

	// Define subnets that should be proxied
	proxySubnets := []netip.Prefix{
		netip.MustParsePrefix("192.168.1.0/24"), // Internal services
		netip.MustParsePrefix("10.20.0.0/16"),   // Application subnet
	}

	// Enable proxying on a secondary NIC for these subnets
	err = tnet.EnableProxyOnSubnet(proxySubnets, true, true)
	if err != nil {
		log.Fatalf("Failed to enable proxy on subnet: %v", err)
	}

	fmt.Println("✓ TCP/UDP proxying enabled on NIC 2 for:")
	for _, subnet := range proxySubnets {
		fmt.Printf("  - %s\n", subnet)
	}
	fmt.Println("✓ Routing table updated to direct subnet traffic to proxy NIC")
	fmt.Println("  → WireGuard on NIC 1: handles encryption/decryption")
	fmt.Println("  → Proxy on NIC 2: handles TCP/UDP termination for specified subnets")

	fmt.Println()
}

func example2() {
	fmt.Println("=== Example 2: Single Interface with Proxying (Not Recommended) ===")
	fmt.Println("⚠️  May conflict with WireGuard packet handling!")

	localAddresses := []netip.Addr{
		netip.MustParseAddr("10.0.0.2"),
	}
	dnsServers := []netip.Addr{
		netip.MustParseAddr("1.1.1.1"),
	}
	mtu := 1420

	// Create netstack with both TCP and UDP proxying enabled
	tun, tnet, err := netstack2.CreateNetTUNWithOptions(
		localAddresses,
		dnsServers,
		mtu,
		netstack2.NetTunOptions{
			EnableTCPProxy: true,
			EnableUDPProxy: true,
		},
	)
	if err != nil {
		log.Fatalf("Failed to create netstack: %v", err)
	}
	defer tun.Close()

	fmt.Println("✓ Netstack created with TCP and UDP proxying enabled")
	fmt.Println("  → Any TCP/UDP traffic through the tunnel will be proxied to actual targets")

	// Now any TCP or UDP connection made through the tunnel will be
	// automatically terminated in netstack and proxied to the target

	_ = tnet
	fmt.Println()
}

func example2() {
	fmt.Println("=== Example 2: Enable proxying after creation ===")

	localAddresses := []netip.Addr{
		netip.MustParseAddr("10.0.0.3"),
	}
	dnsServers := []netip.Addr{
		netip.MustParseAddr("1.1.1.1"),
	}
	mtu := 1420

	// Create standard netstack first
	tun, tnet, err := netstack2.CreateNetTUN(localAddresses, dnsServers, mtu)
	if err != nil {
		log.Fatalf("Failed to create netstack: %v", err)
	}
	defer tun.Close()

	fmt.Println("✓ Netstack created")

	// Enable TCP proxying
	if err := tnet.EnableTCPProxy(); err != nil {
		log.Fatalf("Failed to enable TCP proxy: %v", err)
	}
	fmt.Println("✓ TCP proxying enabled")

	// Enable UDP proxying
	if err := tnet.EnableUDPProxy(); err != nil {
		log.Fatalf("Failed to enable UDP proxy: %v", err)
	}
	fmt.Println("✓ UDP proxying enabled")

	// Calling EnableTCPProxy again is safe (no-op)
	if err := tnet.EnableTCPProxy(); err != nil {
		log.Fatalf("Failed to re-enable TCP proxy: %v", err)
	}
	fmt.Println("✓ Re-enabling TCP proxying is safe (no-op)")

	fmt.Println()
}

func example3() {
	fmt.Println("=== Example 3: Standard netstack (no proxying) ===")

	localAddresses := []netip.Addr{
		netip.MustParseAddr("10.0.0.4"),
	}
	dnsServers := []netip.Addr{
		netip.MustParseAddr("1.1.1.1"),
	}
	mtu := 1420

	// Use standard CreateNetTUN - backward compatible
	tun, tnet, err := netstack2.CreateNetTUN(localAddresses, dnsServers, mtu)
	if err != nil {
		log.Fatalf("Failed to create netstack: %v", err)
	}
	defer tun.Close()

	fmt.Println("✓ Standard netstack created (no proxying)")
	fmt.Println("  → Use tnet.DialTCP(), tnet.DialUDP() for manual connections")

	_ = tnet
	fmt.Println()
}
