# Dynamic Proxy Feature

This document describes the dynamic proxy feature that allows the proxy manager to automatically create TCP and UDP proxies based on intercepted packets, without requiring pre-configured targets.

## Overview

The dynamic proxy feature uses the packet interception primitives in `netstack2` to intercept packets destined for specific subnet ranges and automatically create proxy connections to the destination. This enables transparent proxying of any traffic to registered subnets.

## How It Works

1. **Subnet Registration**: You register one or more subnet ranges (e.g., `10.20.20.0/24`) for dynamic proxying
2. **Packet Interception**: When a packet destined for a registered subnet is received, it's intercepted before normal processing
3. **Dynamic Proxy Creation**: A new proxy connection is created on-demand to the actual destination
4. **Bidirectional Communication**: 
   - Outbound: Packets from the tunnel are forwarded to the target through the host's network
   - Inbound: Responses from the target are injected back into the tunnel
5. **Connection Tracking**: Active connections are tracked and automatically cleaned up after inactivity

## Usage Example

```go
package main

import (
    "net/netip"
    "github.com/fosrl/newt/proxy"
    "github.com/fosrl/newt/netstack2"
)

func main() {
    // Create netstack and proxy manager
    localAddrs := []netip.Addr{netip.MustParseAddr("10.0.0.1")}
    dnsServers := []netip.Addr{netip.MustParseAddr("8.8.8.8")}
    tun, net, _ := netstack2.CreateNetTUN(localAddrs, dnsServers, 1420)
    
    pm := proxy.NewProxyManager(net)
    pm.Start()
    
    // Enable dynamic proxying for specific subnet
    subnets := []netip.Prefix{
        netip.MustParsePrefix("10.20.20.0/24"),  // All traffic to 10.20.20.x
    }
    
    err := pm.EnableDynamicProxying(subnets)
    if err != nil {
        panic(err)
    }
    
    // Now any connection to 10.20.20.x:port will be automatically proxied
    // For example: HTTP to 10.20.20.20:8000 will proxy to the real server
    
    // Add more subnets dynamically
    pm.AddDynamicSubnet(netip.MustParsePrefix("192.168.100.0/24"))
    
    // Check status
    if pm.IsDynamicProxyingEnabled() {
        subnets := pm.GetDynamicSubnets()
        for _, subnet := range subnets {
            println("Dynamic proxy enabled for:", subnet.String())
        }
    }
    
    // Remove a subnet
    pm.RemoveDynamicSubnet(netip.MustParsePrefix("192.168.100.0/24"))
    
    // Disable all dynamic proxying
    pm.DisableDynamicProxying()
}
```

## API Reference

### ProxyManager Methods

#### EnableDynamicProxying(subnets []netip.Prefix) error
Enables dynamic proxying for the specified subnet ranges. Creates the dynamic handler and registers all subnets for packet interception.

**Parameters:**
- `subnets`: List of subnet prefixes to enable dynamic proxying for

**Returns:** Error if netstack is not initialized or registration fails

**Example:**
```go
subnets := []netip.Prefix{
    netip.MustParsePrefix("10.20.20.0/24"),
    netip.MustParsePrefix("172.16.0.0/16"),
}
err := pm.EnableDynamicProxying(subnets)
```

#### DisableDynamicProxying() error
Disables all dynamic proxying. Unregisters all subnets, stops the handler, and closes all active dynamic connections.

**Returns:** Error (always nil currently)

**Example:**
```go
pm.DisableDynamicProxying()
```

#### AddDynamicSubnet(subnet netip.Prefix) error
Adds a single subnet range for dynamic proxying. Creates the handler if it doesn't exist.

**Parameters:**
- `subnet`: Subnet prefix to add

**Returns:** Error if already registered or registration fails

**Example:**
```go
err := pm.AddDynamicSubnet(netip.MustParsePrefix("10.30.30.0/24"))
```

#### RemoveDynamicSubnet(subnet netip.Prefix) error
Removes a subnet range from dynamic proxying. Stops the handler if no subnets remain.

**Parameters:**
- `subnet`: Subnet prefix to remove

**Returns:** Error if subnet not found

**Example:**
```go
err := pm.RemoveDynamicSubnet(netip.MustParsePrefix("10.30.30.0/24"))
```

#### GetDynamicSubnets() []netip.Prefix
Returns a list of all currently registered subnets for dynamic proxying.

**Returns:** Copy of subnet list

**Example:**
```go
subnets := pm.GetDynamicSubnets()
for _, subnet := range subnets {
    fmt.Printf("Registered: %s\n", subnet)
}
```

#### IsDynamicProxyingEnabled() bool
Checks if dynamic proxying is currently enabled.

**Returns:** True if handler exists and at least one subnet is registered

**Example:**
```go
if pm.IsDynamicProxyingEnabled() {
    fmt.Println("Dynamic proxying is active")
}
```

## Protocol Support

### TCP
- Full bidirectional proxy support
- Automatic SYN/FIN/RST handling
- Connection state tracking
- 5-minute idle timeout
- Proper TCP checksums and sequence numbers

### UDP
- Full bidirectional proxy support
- Stateless protocol handling
- Per-flow connection tracking
- 30-second idle timeout
- Proper UDP checksums

## Connection Lifecycle

### TCP Connections

1. **Establishment**: 
   - SYN packet intercepted
   - `net.Dial("tcp", target)` called
   - Response goroutine started
   - Connection added to tracking map

2. **Data Transfer**:
   - Inbound: Payload extracted from packets and written to target
   - Outbound: Data read from target and injected as packets into tunnel
   - Telemetry tracked for both directions

3. **Termination**:
   - FIN or RST detected → close target connection
   - Target closes → stop reading
   - 5-minute idle → automatic cleanup
   - Connection removed from tracking

### UDP Connections

1. **Establishment**:
   - First packet intercepted
   - `net.DialUDP(target)` called
   - Response goroutine started
   - Connection added to tracking map

2. **Data Transfer**:
   - Inbound: Payload extracted and written to target
   - Outbound: Data read from target and injected into tunnel
   - Telemetry tracked for both directions

3. **Termination**:
   - 30-second idle → automatic cleanup
   - Connection removed from tracking

## Packet Construction

The dynamic proxy handler constructs proper IP packets with:

### IPv4 Packets
- Correct IP header (version, length, TTL, protocol)
- Proper IP checksum
- Support for both TCP and UDP

### IPv6 Packets
- Correct IPv6 header (version, payload length, hop limit)
- Support for both TCP and UDP
- Extension headers not yet supported

### TCP Packets
- Correct TCP header (ports, sequence numbers, flags, window)
- Proper TCP checksum with pseudo-header
- Support for common flags (SYN, ACK, FIN, RST)

### UDP Packets
- Correct UDP header (ports, length)
- Proper UDP checksum with pseudo-header

## Telemetry Integration

All dynamic proxy connections are tracked with the same telemetry as static proxies:

- **proxy_accepts**: Incremented on successful connection creation
- **proxy_connection_events**: Tracks opened/closed events
- **tunnel_bytes**: Tracks bytes in both directions
- **proxy_active_connections**: Observable gauge for active connection count
- **proxy_drops**: Incremented on write failures

Metrics include labels for:
- `tunnel_id`: WireGuard peer public key
- `protocol`: "tcp" or "udp"
- `direction`: "ingress" or "egress"
- `result`: "success" or "failure"

## Performance Considerations

### Memory
- Each connection requires ~1KB for state tracking
- Connection maps are cleaned up periodically
- Buffers are allocated per-connection (65KB for read buffers)

### CPU
- Packet parsing and construction add overhead
- Checksum calculations required for each packet
- Linear search through registered subnets on each packet

### Recommendations
1. Register only necessary subnets (fewer is better)
2. Use larger subnet ranges when possible (e.g., /24 instead of multiple /32s)
3. Monitor active connection count
4. Consider connection limits for production use

## Limitations

1. **TCP State**: Simplified TCP implementation doesn't track full state machine
2. **IPv6**: Extension headers not parsed in packet info
3. **Fragmentation**: IP fragmentation not handled
4. **MTU**: No path MTU discovery, fixed MTU from tunnel
5. **Connection Limits**: No built-in connection limiting (should be added for production)
6. **Protocol Support**: Only TCP and UDP (ICMP, etc. not supported)

## Error Handling

### Connection Errors
- Target unreachable → TCP RST sent to client
- Target refuses connection → TCP RST sent to client
- UDP target unreachable → packet silently dropped

### Telemetry
- All errors tracked in `proxy_accepts` with failure result
- Drops tracked in `proxy_drops` counter
- Error types classified for better debugging

### Logging
- Connection establishment logged at INFO level
- Errors logged at ERROR level
- Debug logging available for troubleshooting

## Security Considerations

1. **Access Control**: No built-in access control; all packets to registered subnets are proxied
2. **Rate Limiting**: No rate limiting implemented
3. **Resource Exhaustion**: No connection limits or memory limits
4. **Logging**: Connection details logged (may include sensitive data)

**Recommendations:**
- Only enable for trusted subnets
- Add connection limits in production
- Monitor resource usage
- Consider adding authentication/authorization layer

## Debugging

### Enable Debug Logging
```go
import "github.com/fosrl/newt/logger"

logger.SetLevel(logger.DEBUG)
```

### Check Active Connections
Dynamic connections are tracked internally. Monitor via telemetry:
```go
// Check metrics endpoint for:
// - proxy_active_connections
// - proxy_connection_events
// - tunnel_bytes
```

### Common Issues

**Issue**: Connections not being created
- Verify subnet is registered: `pm.GetDynamicSubnets()`
- Check logs for interception messages
- Verify packet destination matches subnet

**Issue**: Data not flowing
- Check target is reachable from host network
- Verify checksums are correct
- Check for MTU issues

**Issue**: High memory usage
- Monitor connection count
- Check for connection leaks
- Verify cleanup is working (check idle timeout)

## Future Enhancements

Potential improvements for the dynamic proxy feature:

1. **Connection Pooling**: Reuse connections to same destination
2. **Advanced TCP State**: Full TCP state machine implementation
3. **IPv6 Extension Headers**: Proper parsing and handling
4. **Connection Limits**: Per-subnet or global connection limits
5. **Bandwidth Limiting**: Per-connection or per-subnet rate limiting
6. **Access Control**: Firewall-like rules for filtering
7. **Protocol Inspection**: Deep packet inspection for protocols
8. **Load Balancing**: Distribute connections across multiple targets
9. **Failover**: Automatic failover to backup targets
10. **Metrics Dashboard**: Real-time connection monitoring UI
