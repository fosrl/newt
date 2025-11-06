# Netstack2 TCP/UDP Proxying

This package provides transparent TCP and UDP connection proxying through WireGuard netstack, inspired by the tun2socks project.

## Overview

The netstack implementation now supports terminating TCP and UDP connections directly in the netstack layer and transparently proxying them to their actual destination targets. This is useful when you want to intercept and forward traffic that enters through a WireGuard tunnel.

## ⚠️ Important: Dual-Interface Architecture

**WARNING**: Installing TCP/UDP handlers on the same interface used by WireGuard can cause packet handling conflicts, as WireGuard already manipulates packets at the transport layer.

**Recommended Approach**: Use `EnableProxyOnSubnet()` to create a **secondary NIC** (Network Interface Card) within the netstack that is dedicated to TCP/UDP proxying. This approach:

1. **Isolates proxying from WireGuard**: WireGuard operates on NIC 1, proxying on NIC 2
2. **Uses route-based steering**: Specific subnets are routed to the proxy NIC via routing table entries
3. **Avoids conflicts**: Each NIC has its own packet handling pipeline

### Architecture Comparison

#### ❌ Single Interface (Not Recommended)
```
Client → WireGuard Tunnel → NIC 1 (with TCP/UDP handlers) → Conflicts!
                              ↓
                          Both WireGuard and handlers process same packets
```

#### ✅ Dual Interface (Recommended)
```
Client → WireGuard Tunnel → NIC 1 (WireGuard traffic, no handlers)
                              ↓
                          Routing Table
                              ↓
                          NIC 2 (TCP/UDP proxy for specific subnets)
                              ↓
                          Direct connection to targets
```

## Key Differences from tun2socks

While tun2socks proxies connections to an upstream SOCKS proxy, newt's implementation directly connects to the actual target addresses. This is because newt has direct network access to the targets.

## Architecture

### TCP Handling

1. **TCP Forwarder**: Installed on the netstack to intercept incoming TCP connections
2. **Connection Establishment**: Performs the TCP three-way handshake with the client through netstack
3. **Target Connection**: Establishes a direct TCP connection to the actual target
4. **Bidirectional Proxy**: Copies data bidirectionally between the netstack connection and the target connection
5. **Half-Close Support**: Properly handles TCP half-close semantics for graceful shutdown

### UDP Handling

1. **UDP Forwarder**: Installed on the netstack to intercept incoming UDP packets
2. **Connection Creation**: Creates a UDP endpoint in netstack for the client
3. **Target Connection**: Establishes a direct UDP connection to the actual target
4. **Packet Forwarding**: Forwards UDP packets bidirectionally with timeout handling
5. **Session Timeout**: UDP sessions timeout after 60 seconds of inactivity

## Usage

### ✅ Recommended: Subnet-Based Proxying (Dual-Interface)

This is the **recommended approach** to avoid conflicts with WireGuard:

```go
import "github.com/fosrl/newt/netstack2"

// Create netstack normally (no proxying on main interface)
tun, tnet, err := netstack2.CreateNetTUN(localAddresses, dnsServers, mtu)

// Define which subnets should be proxied
// These could be specific services or networks you want to intercept
proxySubnets := []netip.Prefix{
    netip.MustParsePrefix("192.168.1.0/24"),  // Internal network
    netip.MustParsePrefix("10.20.0.0/16"),    // Service network
}

// Enable proxying on a secondary NIC for these subnets only
err = tnet.EnableProxyOnSubnet(proxySubnets, true, true) // TCP=true, UDP=true
if err != nil {
    log.Fatalf("Failed to enable proxy on subnet: %v", err)
}

// Now:
// - Traffic to 192.168.1.0/24 and 10.20.0.0/16 → Proxied via NIC 2
// - All other traffic → Handled normally by WireGuard on NIC 1
```

### Option 2: Enable During Creation (Single-Interface - Use with Caution)

**⚠️ May conflict with WireGuard packet handling!**

```go
// Enable proxying on the main interface
tun, tnet, err := netstack2.CreateNetTUNWithOptions(
    localAddresses,
    dnsServers,
    mtu,
    netstack2.NetTunOptions{
        EnableTCPProxy: true,
        EnableUDPProxy: true,
    },
)

// All TCP/UDP traffic will be intercepted - may conflict with WireGuard
```

### Option 3: Enable After Creation (Single-Interface - Use with Caution)

**⚠️ May conflict with WireGuard packet handling!**

```go
// Create netstack normally
tun, tnet, err := netstack2.CreateNetTUN(localAddresses, dnsServers, mtu)

// Enable TCP proxying later on main interface
if err := tnet.EnableTCPProxy(); err != nil {
    log.Fatalf("Failed to enable TCP proxy: %v", err)
}

// Enable UDP proxying later on main interface  
if err := tnet.EnableUDPProxy(); err != nil {
    log.Fatalf("Failed to enable UDP proxy: %v", err)
}
```

### Option 4: Backward Compatible (No Proxying)

```go
// Use the standard CreateNetTUN - no proxying enabled
tun, tnet, err := netstack2.CreateNetTUN(localAddresses, dnsServers, mtu)
// Connections will use standard netstack dial methods
```

## Configuration Parameters

### TCP Settings

- **TCP Connect Timeout**: 5 seconds for establishing connections to targets
- **TCP Keepalive Idle**: 60 seconds before first keepalive probe
- **TCP Keepalive Interval**: 30 seconds between keepalive probes
- **TCP Keepalive Count**: 9 probes before giving up
- **TCP Half-Close Timeout**: 60 seconds for graceful shutdown

### UDP Settings

- **UDP Session Timeout**: 60 seconds of inactivity before closing session
- **Max Packet Size**: 65535 bytes (standard UDP maximum)

## Performance Considerations

1. **Buffer Sizes**: 32KB buffers for TCP, 64KB for UDP
2. **Goroutines**: Each connection spawns 2 goroutines for bidirectional copying
3. **Memory**: Buffer allocations are reused where possible
4. **Socket Options**: Optimized TCP send/receive buffer sizes from stack defaults

## Example: WireGuard Integration

```go
func (s *WireGuardService) createNetstack() error {
    // Create netstack WITHOUT proxying on the main interface
    s.tun, s.tnet, err = netstack2.CreateNetTUN(
        []netip.Addr{tunnelIP},
        s.dns,
        s.mtu,
    )
    if err != nil {
        return err
    }
    
    // Define subnets that should be proxied
    // These are typically the target services you want to intercept
    proxySubnets := []netip.Prefix{
        netip.MustParsePrefix("192.168.100.0/24"), // Service subnet 1
        netip.MustParsePrefix("10.50.0.0/16"),     // Service subnet 2
    }
    
    // Enable proxying on a secondary NIC for specific subnets
    // This avoids conflicts with WireGuard's packet handling
    err = s.tnet.EnableProxyOnSubnet(proxySubnets, true, true)
    if err != nil {
        return fmt.Errorf("failed to enable proxy: %v", err)
    }
    
    // Now:
    // - WireGuard handles encryption/decryption on NIC 1
    // - Traffic to proxySubnets is routed to NIC 2 for TCP/UDP proxying
    // - All other traffic goes through normal WireGuard path
    
    return nil
}
```

## Debugging

When proxying is enabled:
- Failed TCP connections will result in RST packets being sent back to the client
- Failed UDP connections will silently drop packets (standard UDP behavior)
- Connection timeouts follow standard TCP/UDP semantics

## Limitations

1. **No Filtering**: All connections are proxied, no filtering capability
2. **Direct Routing**: Assumes direct network access to all target addresses
3. **No NAT Traversal**: Does not handle complex NAT scenarios
4. **Memory Usage**: Each active connection uses ~64KB of buffer space

## Future Enhancements

Potential improvements:
- Connection filtering/allow-listing
- Per-connection rate limiting
- Connection statistics and monitoring
- Dynamic timeout configuration
- Connection pooling for frequently accessed targets
