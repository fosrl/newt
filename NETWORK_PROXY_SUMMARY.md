# Network Proxy Feature Summary

## What Was Added

Successfully integrated subnet-based packet interception into the ProxyManager, enabling SNAT-like network proxying capabilities.

## Architecture

### Two-Layer Design

1. **netstack2 Package** (Low-level primitives):
   - `PacketInfo` struct - Contains parsed packet metadata
   - `PacketHandler` interface - For handling intercepted packets
   - `RegisterSubnetInterceptor()` - Register subnet ranges for interception
   - `InjectPacket()` - Inject response packets back into tunnel
   - Packet parsing and flow control

2. **proxy Package** (High-level proxy logic):
   - Implements `PacketHandler` interface
   - Connection tracking and lifecycle management
   - Packet forwarding to/from host network
   - Response packet construction (IPv4/IPv6, TCP/UDP)
   - Telemetry integration

## New ProxyManager Methods

```go
// Add a subnet for network-level proxying
pm.AddNetworkTarget("10.0.0.0/30") 

// Remove a subnet
pm.RemoveNetworkTarget("10.0.0.0/30")

// Existing PrintTargets() now shows network targets too
pm.PrintTargets()
```

## How It Works

1. **Packet Interception**:
   - Packets arriving through WireGuard tunnel are checked against registered subnets
   - Matching packets are intercepted before reaching the netstack
   - `HandlePacket()` is called with packet metadata

2. **Connection Establishment**:
   - First packet creates a connection through host's network stack
   - Connection tracked by flow key (src:port->dst:port:protocol)
   - Subsequent packets on same flow reuse connection

3. **Bidirectional Communication**:
   - **Outbound**: Packet payload extracted and written to host connection
   - **Inbound**: Host connection responses read and injected back as IP packets
   - Proper src/dst address swapping for responses

4. **Connection Cleanup**:
   - Idle timeout: 5 minutes
   - Subnet removal closes all related connections
   - ProxyManager.Stop() closes everything

## Features

✅ **Protocols**: TCP and UDP support
✅ **IPv4/IPv6**: Both address families supported  
✅ **Telemetry**: Full metrics integration (bytes, connections, errors)
✅ **Per-tunnel tracking**: Tunnel ID support for multi-peer scenarios
✅ **Dynamic management**: Add/remove subnets at runtime
✅ **Lifecycle integration**: Works with Start/Stop

## Use Cases

1. **SNAT Gateway**: Allow tunnel clients to access networks without routing setup
2. **Private Network Access**: Proxy to internal networks (e.g., 192.168.x.x)
3. **Service Mesh**: Route specific subnet traffic through host
4. **Multi-region**: Different subnets for different backend regions
5. **Development**: Test network scenarios without complex routing

## Limitations

⚠️ **TCP State**: Simplified headers without full TCP state machine
⚠️ **Performance**: Userspace processing (slower than kernel routing)
⚠️ **IPv6 Extensions**: Extension headers not fully parsed
⚠️ **ICMP**: Not currently proxied (TCP/UDP only)

## Files Modified

- `netstack2/tun.go` - Added packet interception primitives
- `proxy/manager.go` - Implemented network proxy logic

## Files Created

- `netstack2/PACKET_INTERCEPTION.md` - Low-level API documentation
- `netstack2/example_proxy.go.txt` - Basic implementation example
- `proxy/network_proxy_example.go.txt` - Usage examples

## Testing Suggestions

1. Register subnet: `pm.AddNetworkTarget("10.0.0.0/30")`
2. From tunnel client, ping/curl to 10.0.0.1-10.0.0.3
3. Verify packets are proxied through host
4. Check telemetry metrics
5. Test subnet removal while connections active
6. Test both TCP and UDP protocols
7. Test IPv4 and IPv6

## Integration Example

```go
// In your tunnel setup code:
pm := proxy.NewProxyManager(tnet)
pm.SetTunnelID(peerPublicKey)

// Add port-based proxies (existing)
pm.AddTarget("tcp", "0.0.0.0", 8080, "backend:80")

// Add network proxies (new)
pm.AddNetworkTarget("10.0.0.0/30")
pm.AddNetworkTarget("192.168.1.0/24")

pm.Start()
```

## Next Steps

Consider adding:
- Proper TCP state machine for better reliability
- ICMP support for ping/traceroute
- Per-subnet connection limits
- Bandwidth throttling per subnet
- More sophisticated packet filtering
