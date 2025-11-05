# Packet Interception Feature

This document describes the packet interception primitives added to netstack2 for implementing SNAT-like proxy behavior.

## Overview

The packet interception feature allows external Go modules to intercept packets destined for specific subnet ranges and handle them with custom logic (e.g., proxying through the host's network stack). This enables bidirectional communication where packets from the tunnel are proxied to external destinations and responses are sent back through the tunnel.

## Core Primitives

### 1. PacketInfo Struct

Contains parsed information about an intercepted packet:

```go
type PacketInfo struct {
    Data     []byte       // Raw packet data (IP header + payload)
    SrcAddr  netip.Addr   // Source address
    DstAddr  netip.Addr   // Destination address
    SrcPort  uint16       // Source port (TCP/UDP)
    DstPort  uint16       // Destination port (TCP/UDP)
    Protocol uint8        // Protocol (6=TCP, 17=UDP)
    IsIPv4   bool         // IPv4 or IPv6
}
```

### 2. PacketHandler Interface

External proxy modules implement this interface:

```go
type PacketHandler interface {
    HandlePacket(info PacketInfo) bool
}
```

- Return `true` if packet was handled (prevents normal processing)
- Return `false` to let packet through normally

### 3. Subnet Registration

Register/unregister subnet ranges for interception:

```go
// Register a handler for a subnet
err := net.RegisterSubnetInterceptor(netip.MustParsePrefix("10.0.0.0/30"), handler)

// Unregister when done
net.UnregisterSubnetInterceptor(netip.MustParsePrefix("10.0.0.0/30"))

// List all registered subnets
subnets := net.GetRegisteredSubnets()
```

### 4. Packet Injection

Inject response packets back into the tunnel:

```go
// Build a complete IP packet and inject it
err := net.InjectPacket(responsePacket)
```

## Usage Pattern

### Step 1: Implement PacketHandler

```go
type MyProxy struct {
    netstack *netstack2.Net
}

func (p *MyProxy) HandlePacket(info netstack2.PacketInfo) bool {
    // 1. Extract payload from IP packet
    // 2. Create connection through host's network (net.Dial)
    // 3. Forward payload to destination
    // 4. Read responses in goroutine
    // 5. Build response packets and call net.InjectPacket()
    return true
}
```

### Step 2: Register Subnet

```go
proxy := &MyProxy{netstack: net}
net.RegisterSubnetInterceptor(netip.MustParsePrefix("10.0.0.0/30"), proxy)
```

### Step 3: Handle Bidirectional Communication

- **Outbound**: `HandlePacket()` is called with packets from tunnel
- **Inbound**: Use `InjectPacket()` to send responses back

## Implementation Notes

### Packet Processing Flow

1. Packet arrives via `Write()` method (from WireGuard)
2. Destination IP is checked against registered subnets
3. If match found, `HandlePacket()` is called
4. If handler returns `true`, normal processing is skipped
5. Handler creates host connection and forwards data
6. Responses are captured and injected back via `InjectPacket()`

### Threading Considerations

- `HandlePacket()` is called synchronously during packet processing
- Handler should spawn goroutines for long-running operations
- Use proper synchronization for connection tracking

### Packet Construction

When building response packets for `InjectPacket()`:

1. Swap source/destination addresses and ports
2. Construct proper IP header (IPv4 or IPv6)
3. Construct proper transport header (TCP/UDP)
4. Calculate checksums correctly
5. Use proper TCP sequence/acknowledgment numbers

See `example_proxy.go.txt` for a complete example.

## Example Use Cases

1. **SNAT Proxy**: Intercept packets to 10.0.0.0/30 and proxy through host
2. **Port Forwarding**: Redirect tunnel traffic to different destinations
3. **Protocol Translation**: Convert between protocols
4. **Traffic Inspection**: Log or modify packets before forwarding
5. **Load Balancing**: Distribute traffic across multiple backends

## Limitations

- Handlers run in the packet processing path (keep them fast)
- No automatic connection tracking (implement in handler)
- No automatic TCP state machine (use raw connections or implement yourself)
- IPv6 extension headers not fully parsed in `parsePacketInfo()`

## Error Handling

- Invalid packets are silently dropped
- Registration errors return descriptive error messages
- Injection errors indicate channel full or invalid packet
- Handlers should handle network errors gracefully

## Performance Tips

1. Use connection pooling in handlers
2. Process packets in goroutines if needed
3. Pre-allocate buffers for packet construction
4. Consider using `sync.Pool` for temporary objects
5. Monitor registered subnet count (linear search on each packet)
