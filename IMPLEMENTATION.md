# TCP/UDP Proxying Implementation Summary

## Overview

This implementation adds transparent TCP and UDP connection proxying to newt's netstack2 package, inspired by tun2socks. Traffic entering through the WireGuard tunnel is terminated in netstack and automatically proxied to the actual target addresses.

## Key Changes

### 1. New File: `netstack2/handlers.go`

**Purpose**: Contains TCP and UDP handler implementations that proxy connections.

**Key Components**:

- `TCPHandler`: Manages TCP connection forwarding
  - Installs TCP forwarder on netstack
  - Performs TCP three-way handshake with clients
  - Dials actual target addresses
  - Bidirectionally copies data with proper half-close handling
  
- `UDPHandler`: Manages UDP packet forwarding
  - Installs UDP forwarder on netstack
  - Creates UDP endpoints for clients
  - Forwards packets to actual targets
  - Handles session timeouts

**Features**:
- Configurable timeouts (5s TCP connect, 60s TCP half-close, 60s UDP session)
- TCP keepalive support (60s idle, 30s interval, 9 probes)
- Optimized buffer sizes (32KB for TCP, 64KB for UDP)
- Proper error handling and connection cleanup

### 2. Modified File: `netstack2/tun.go`

**Changes**:

1. Added `tcpHandler` and `udpHandler` fields to `netTun` struct
2. Added `NetTunOptions` struct for configuration:
   ```go
   type NetTunOptions struct {
       EnableTCPProxy bool
       EnableUDPProxy bool
   }
   ```
3. Added `CreateNetTUNWithOptions()` function for explicit proxying control
4. Modified existing `CreateNetTUN()` to call `CreateNetTUNWithOptions()` with proxying disabled (backward compatible)
5. Added `EnableTCPProxy()` and `EnableUDPProxy()` methods on `*Net` for runtime activation

### 3. Documentation: `netstack2/README.md`

Comprehensive documentation covering:
- Architecture overview
- Usage examples (3 different approaches)
- Configuration parameters
- Performance considerations
- Limitations and debugging tips

### 4. Example: `examples/netstack-proxying/main.go`

Runnable examples demonstrating:
- Creating netstack with proxying enabled
- Enabling proxying after creation
- Standard netstack usage (no proxying)

## Usage Patterns

### Pattern 1: Enable During Creation
```go
tun, tnet, err := netstack2.CreateNetTUNWithOptions(
    localAddresses, dnsServers, mtu,
    netstack2.NetTunOptions{
        EnableTCPProxy: true,
        EnableUDPProxy: true,
    },
)
```

### Pattern 2: Enable After Creation
```go
tun, tnet, err := netstack2.CreateNetTUN(localAddresses, dnsServers, mtu)
tnet.EnableTCPProxy()
tnet.EnableUDPProxy()
```

### Pattern 3: No Proxying (Backward Compatible)
```go
tun, tnet, err := netstack2.CreateNetTUN(localAddresses, dnsServers, mtu)
// Use standard tnet.DialTCP(), tnet.DialUDP() methods
```

## How It Works

### TCP Flow:
1. Client sends TCP SYN to target address through WireGuard tunnel
2. Packet arrives at netstack
3. TCP forwarder intercepts and completes three-way handshake
4. Handler dials actual target address
5. Data copied bidirectionally until connection closes
6. Proper TCP half-close and FIN handling

### UDP Flow:
1. Client sends UDP packet to target address through WireGuard tunnel
2. Packet arrives at netstack
3. UDP forwarder creates endpoint for client
4. Handler creates UDP connection to actual target
5. Packets forwarded bidirectionally
6. Session closes after 60s timeout or explicit close

## Key Differences from tun2socks

| Aspect | tun2socks | newt |
|--------|-----------|------|
| Target | SOCKS proxy | Direct target addresses |
| Use Case | Route to proxy | Direct network access |
| Architecture | Proxy adapter | Direct dial |
| Complexity | Higher (SOCKS protocol) | Lower (direct TCP/UDP) |

## Integration with WireGuard

The handlers integrate seamlessly with existing WireGuard code:

```go
// In wgnetstack.go:
func (s *WireGuardService) ensureWireguardInterface(wgconfig WgConfig) error {
    // Create netstack with proxying
    s.tun, s.tnet, err = netstack2.CreateNetTUNWithOptions(
        []netip.Addr{tunnelIP},
        s.dns,
        s.mtu,
        netstack2.NetTunOptions{
            EnableTCPProxy: true,
            EnableUDPProxy: true,
        },
    )
    
    // Rest of WireGuard setup...
}
```

## Performance Characteristics

- **Memory**: ~64KB per active connection (buffer space)
- **Goroutines**: 2 per connection (bidirectional copying)
- **Latency**: Minimal overhead (single netstack hop + direct dial)
- **Throughput**: Limited by buffer size and network bandwidth

## Testing

To test the implementation:

1. Build the example:
   ```bash
   cd /home/owen/fossorial/newt
   go build -o /tmp/netstack-example examples/netstack-proxying/main.go
   ```

2. Run the example:
   ```bash
   /tmp/netstack-example
   ```

3. Integration test with WireGuard:
   - Enable proxying in wgnetstack
   - Send TCP/UDP traffic through tunnel
   - Verify connections reach actual targets

## Error Handling

- **TCP**: Failed connections result in RST packets to client
- **UDP**: Failed sends are silently dropped (standard UDP behavior)
- **Timeouts**: Configurable per protocol
- **Resources**: Proper cleanup on connection close

## Security Considerations

1. **No Filtering**: All connections are proxied (no allow-list)
2. **Direct Access**: Assumes network access to all targets
3. **Resource Limits**: No per-connection rate limiting
4. **Logging**: No built-in connection logging (can be added)

## Future Enhancements

Potential improvements:
1. Connection filtering/allow-listing
2. Per-connection rate limiting
3. Connection statistics and monitoring
4. Dynamic timeout configuration
5. Connection pooling
6. Logging and metrics
7. Connection replay prevention

## Backward Compatibility

✅ **Fully backward compatible**: Existing code using `CreateNetTUN()` continues to work without any changes. Proxying is opt-in via `CreateNetTUNWithOptions()` or `EnableTCPProxy()`/`EnableUDPProxy()`.

## Files Modified/Created

**Created**:
- `netstack2/handlers.go` (286 lines)
- `netstack2/README.md` (documentation)
- `examples/netstack-proxying/main.go` (example code)
- `IMPLEMENTATION.md` (this file)

**Modified**:
- `netstack2/tun.go` (added 40 lines)
  - Added handler fields to `netTun` struct
  - Added `NetTunOptions` type
  - Added `CreateNetTUNWithOptions()` function
  - Added `EnableTCPProxy()` and `EnableUDPProxy()` methods
  - Modified `CreateNetTUN()` to call new function with disabled options

## Build Verification

```bash
cd /home/owen/fossorial/newt
go build ./netstack2/
# Success - no compilation errors
```

## Next Steps

To use this in newt:

1. **Test in isolation**: Run the example program to verify basic functionality
2. **Integrate with WireGuard**: Modify `wgnetstack.go` to use `CreateNetTUNWithOptions()`
3. **Add configuration**: Make proxying configurable via newt's config file
4. **Add logging**: Integrate with newt's logger for connection tracking
5. **Monitor performance**: Add metrics for connection count, throughput, errors
6. **Add tests**: Create unit and integration tests

## References

- **tun2socks**: https://github.com/xjasonlyu/tun2socks
  - Referenced files: `core/tcp.go`, `core/udp.go`, `tunnel/tcp.go`, `tunnel/udp.go`
- **gVisor netstack**: https://gvisor.dev/docs/user_guide/networking/
- **WireGuard**: https://www.wireguard.com/
