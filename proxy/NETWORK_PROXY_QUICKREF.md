# Network Proxy Quick Reference

## API Reference

### Adding Network Targets

```go
// Add a subnet for proxying
err := pm.AddNetworkTarget("10.0.0.0/30")
err := pm.AddNetworkTarget("192.168.1.0/24")
err := pm.AddNetworkTarget("2001:db8::/32") // IPv6 support
```

### Removing Network Targets

```go
// Remove a subnet
err := pm.RemoveNetworkTarget("10.0.0.0/30")
```

### Getting Information

```go
// Get list of registered subnets
subnets := pm.GetNetworkTargets()
// Returns: []string{"10.0.0.0/30", "192.168.1.0/24"}

// Get detailed connection statistics
stats := pm.GetNetworkConnectionStats()
// Returns map with:
//   - total_connections: int
//   - tcp_connections: int
//   - udp_connections: int
//   - connections: []map[string]interface{} with flow details

// Print all targets (port-based and network)
pm.PrintTargets()
```

### Lifecycle Management

```go
// Create proxy manager
pm := proxy.NewProxyManager(tnet)

// Set tunnel ID for telemetry
pm.SetTunnelID("peer_public_key")

// Add targets before or after Start()
pm.AddNetworkTarget("10.0.0.0/30")

// Start all proxies
pm.Start()

// Add more dynamically
pm.AddNetworkTarget("10.1.0.0/24")

// Stop all proxies (cleans up connections)
pm.Stop()

// Clear tunnel telemetry
pm.ClearTunnelID()
```

## Common Patterns

### Pattern 1: Static Subnet Proxy

```go
pm := proxy.NewProxyManager(tnet)
pm.AddNetworkTarget("10.0.0.0/30")
pm.Start()
```

### Pattern 2: Dynamic Subnet Management

```go
pm.Start()

// Add based on some condition
if needsPrivateNetwork {
    pm.AddNetworkTarget("192.168.1.0/24")
}

// Remove when no longer needed
pm.RemoveNetworkTarget("192.168.1.0/24")
```

### Pattern 3: Multiple Subnets

```go
subnets := []string{
    "10.0.0.0/30",
    "10.1.0.0/24",
    "192.168.1.0/24",
}

for _, subnet := range subnets {
    pm.AddNetworkTarget(subnet)
}
```

### Pattern 4: Monitoring Active Connections

```go
import "encoding/json"

// Get statistics
stats := pm.GetNetworkConnectionStats()

// Pretty print
jsonStats, _ := json.MarshalIndent(stats, "", "  ")
fmt.Println(string(jsonStats))

// Example output:
// {
//   "total_connections": 3,
//   "tcp_connections": 2,
//   "udp_connections": 1,
//   "connections": [
//     {
//       "flow_key": "10.0.0.2:52341->192.168.1.100:80:6",
//       "src_addr": "10.0.0.2:52341",
//       "dst_addr": "192.168.1.100:80",
//       "protocol": "tcp",
//       "tunnel_id": "peer_abc123",
//       "last_active": "2025-11-05T10:30:45Z",
//       "idle_time": "15s"
//     }
//   ]
// }
```

### Pattern 5: Combined Port and Network Proxying

```go
pm := proxy.NewProxyManager(tnet)

// Traditional port-based proxies
pm.AddTarget("tcp", "0.0.0.0", 8080, "backend:80")
pm.AddTarget("udp", "0.0.0.0", 53, "8.8.8.8:53")

// Network-level proxies
pm.AddNetworkTarget("10.0.0.0/30")
pm.AddNetworkTarget("192.168.1.0/24")

pm.Start()
```

## Subnet Planning Guide

### Small Ranges (Perfect for SNAT)
- `/32` - Single IP (1 address)
- `/31` - Point-to-point (2 addresses)
- `/30` - Small network (4 addresses) ✅ Recommended for demo
- `/29` - 8 addresses
- `/28` - 16 addresses

### Medium Ranges
- `/24` - 256 addresses (standard subnet) ✅ Common choice
- `/23` - 512 addresses
- `/22` - 1,024 addresses

### Large Ranges
- `/16` - 65,536 addresses ⚠️ Use with caution
- `/8` - 16,777,216 addresses ⚠️ Very large

### Private Network Ranges
- `10.0.0.0/8` - 10.x.x.x
- `172.16.0.0/12` - 172.16.x.x - 172.31.x.x
- `192.168.0.0/16` - 192.168.x.x

## Troubleshooting

### Issue: Subnet not being intercepted
```go
// Check if subnet is registered
subnets := pm.GetNetworkTargets()
fmt.Println("Registered subnets:", subnets)

// Ensure ProxyManager is started
pm.Start()
```

### Issue: No active connections
```go
// Check connection stats
stats := pm.GetNetworkConnectionStats()
fmt.Printf("Active connections: %d\n", stats["total_connections"])

// Check if packets are reaching the interceptor
// Enable debug logging to see HandlePacket calls
```

### Issue: Connections stuck
```go
// Connections timeout after 5 minutes of idle time
// You can restart the proxy to clear all connections
pm.Stop()
pm.Start()
```

### Issue: Performance problems
```go
// Network proxying is userspace - not as fast as kernel routing
// Consider:
// - Using smaller subnet ranges
// - Using port-based proxying for specific services
// - Monitoring connection count and idle cleanup
```

## Telemetry Metrics

Automatically tracked when using network proxies:

- **Bytes**: `tunnel_bytes` counter with direction (ingress/egress)
- **Connections**: Active connection count gauge
- **Accepts**: Connection establishment success/failure
- **Events**: Connection opened/closed events
- **Duration**: Connection lifetime histograms
- **Errors**: Failed connections with error classification

All metrics include:
- `tunnel_id` (if set)
- `protocol` (tcp/udp)
- `direction` (ingress/egress)
- Site labels (if configured)

## Best Practices

1. **Start small**: Test with `/30` before using larger subnets
2. **Monitor connections**: Use `GetNetworkConnectionStats()` regularly
3. **Set tunnel IDs**: Always set tunnel ID for proper telemetry
4. **Clean up**: Call `ClearTunnelID()` when peer disconnects
5. **IPv6 ready**: Support both IPv4 and IPv6 from the start
6. **Error handling**: Check errors from Add/Remove operations
7. **Lifecycle**: Add targets before `Start()` when possible
