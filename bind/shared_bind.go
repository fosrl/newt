//go:build !js

package bind

import (
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	wgConn "golang.zx2c4.com/wireguard/conn"
)

// Endpoint represents a network endpoint for the SharedBind
type Endpoint struct {
	AddrPort netip.AddrPort
}

// ClearSrc implements the wgConn.Endpoint interface
func (e *Endpoint) ClearSrc() {}

// DstIP implements the wgConn.Endpoint interface
func (e *Endpoint) DstIP() netip.Addr {
	return e.AddrPort.Addr()
}

// SrcIP implements the wgConn.Endpoint interface
func (e *Endpoint) SrcIP() netip.Addr {
	return netip.Addr{}
}

// DstToBytes implements the wgConn.Endpoint interface
func (e *Endpoint) DstToBytes() []byte {
	b, _ := e.AddrPort.MarshalBinary()
	return b
}

// DstToString implements the wgConn.Endpoint interface
func (e *Endpoint) DstToString() string {
	return e.AddrPort.String()
}

// SrcToString implements the wgConn.Endpoint interface
func (e *Endpoint) SrcToString() string {
	return ""
}

// SharedBind is a thread-safe UDP bind that can be shared between WireGuard
// and hole punch senders. It wraps a single UDP connection and implements
// reference counting to prevent premature closure.
type SharedBind struct {
	mu sync.RWMutex

	// The underlying UDP connection
	udpConn *net.UDPConn

	// IPv4 and IPv6 packet connections for advanced features
	ipv4PC *ipv4.PacketConn
	ipv6PC *ipv6.PacketConn

	// Reference counting to prevent closing while in use
	refCount atomic.Int32
	closed   atomic.Bool

	// Channels for receiving data
	recvFuncs []wgConn.ReceiveFunc

	// Port binding information
	port uint16
}

// New creates a new SharedBind from an existing UDP connection.
// The SharedBind takes ownership of the connection and will close it
// when all references are released.
func New(udpConn *net.UDPConn) (*SharedBind, error) {
	if udpConn == nil {
		return nil, fmt.Errorf("udpConn cannot be nil")
	}

	bind := &SharedBind{
		udpConn: udpConn,
	}

	// Initialize reference count to 1 (the creator holds the first reference)
	bind.refCount.Store(1)

	// Get the local port
	if addr, ok := udpConn.LocalAddr().(*net.UDPAddr); ok {
		bind.port = uint16(addr.Port)
	}

	return bind, nil
}

// AddRef increments the reference count. Call this when sharing
// the bind with another component.
func (b *SharedBind) AddRef() {
	newCount := b.refCount.Add(1)
	// Optional: Add logging for debugging
	_ = newCount // Placeholder for potential logging
}

// Release decrements the reference count. When it reaches zero,
// the underlying UDP connection is closed.
func (b *SharedBind) Release() error {
	newCount := b.refCount.Add(-1)
	// Optional: Add logging for debugging
	_ = newCount // Placeholder for potential logging

	if newCount < 0 {
		// This should never happen with proper usage
		b.refCount.Store(0)
		return fmt.Errorf("SharedBind reference count went negative")
	}

	if newCount == 0 {
		return b.closeConnection()
	}

	return nil
}

// closeConnection actually closes the UDP connection
func (b *SharedBind) closeConnection() error {
	if !b.closed.CompareAndSwap(false, true) {
		// Already closed
		return nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	var err error
	if b.udpConn != nil {
		err = b.udpConn.Close()
		b.udpConn = nil
	}

	b.ipv4PC = nil
	b.ipv6PC = nil

	return err
}

// GetUDPConn returns the underlying UDP connection.
// The caller must not close this connection directly.
func (b *SharedBind) GetUDPConn() *net.UDPConn {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.udpConn
}

// GetRefCount returns the current reference count (for debugging)
func (b *SharedBind) GetRefCount() int32 {
	return b.refCount.Load()
}

// IsClosed returns whether the bind is closed
func (b *SharedBind) IsClosed() bool {
	return b.closed.Load()
}

// WriteToUDP writes data to a specific UDP address.
// This is thread-safe and can be used by hole punch senders.
func (b *SharedBind) WriteToUDP(data []byte, addr *net.UDPAddr) (int, error) {
	if b.closed.Load() {
		return 0, net.ErrClosed
	}

	b.mu.RLock()
	conn := b.udpConn
	b.mu.RUnlock()

	if conn == nil {
		return 0, net.ErrClosed
	}

	return conn.WriteToUDP(data, addr)
}

// Close implements the WireGuard Bind interface.
// It decrements the reference count and closes the connection if no references remain.
func (b *SharedBind) Close() error {
	return b.Release()
}

// Open implements the WireGuard Bind interface.
// Since the connection is already open, this just sets up the receive functions.
func (b *SharedBind) Open(uport uint16) ([]wgConn.ReceiveFunc, uint16, error) {
	if b.closed.Load() {
		return nil, 0, net.ErrClosed
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.udpConn == nil {
		return nil, 0, net.ErrClosed
	}

	// Set up IPv4 and IPv6 packet connections for advanced features
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		b.ipv4PC = ipv4.NewPacketConn(b.udpConn)
		b.ipv6PC = ipv6.NewPacketConn(b.udpConn)
	}

	// Create receive functions
	recvFuncs := make([]wgConn.ReceiveFunc, 0, 2)

	// Add IPv4 receive function
	if b.ipv4PC != nil || runtime.GOOS != "linux" {
		recvFuncs = append(recvFuncs, b.makeReceiveIPv4())
	}

	// Add IPv6 receive function if needed
	// For now, we focus on IPv4 for hole punching use case

	b.recvFuncs = recvFuncs
	return recvFuncs, b.port, nil
}

// makeReceiveIPv4 creates a receive function for IPv4 packets
func (b *SharedBind) makeReceiveIPv4() wgConn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []wgConn.Endpoint) (n int, err error) {
		if b.closed.Load() {
			return 0, net.ErrClosed
		}

		b.mu.RLock()
		conn := b.udpConn
		pc := b.ipv4PC
		b.mu.RUnlock()

		if conn == nil {
			return 0, net.ErrClosed
		}

		// Use batch reading on Linux for performance
		if pc != nil && (runtime.GOOS == "linux" || runtime.GOOS == "android") {
			return b.receiveIPv4Batch(pc, bufs, sizes, eps)
		}

		// Fallback to simple read for other platforms
		return b.receiveIPv4Simple(conn, bufs, sizes, eps)
	}
}

// receiveIPv4Batch uses batch reading for better performance on Linux
func (b *SharedBind) receiveIPv4Batch(pc *ipv4.PacketConn, bufs [][]byte, sizes []int, eps []wgConn.Endpoint) (int, error) {
	// Create messages for batch reading
	msgs := make([]ipv4.Message, len(bufs))
	for i := range bufs {
		msgs[i].Buffers = [][]byte{bufs[i]}
		msgs[i].OOB = make([]byte, 0) // No OOB data needed for basic use
	}

	numMsgs, err := pc.ReadBatch(msgs, 0)
	if err != nil {
		return 0, err
	}

	for i := 0; i < numMsgs; i++ {
		sizes[i] = msgs[i].N
		if sizes[i] == 0 {
			continue
		}

		if msgs[i].Addr != nil {
			if udpAddr, ok := msgs[i].Addr.(*net.UDPAddr); ok {
				addrPort := udpAddr.AddrPort()
				eps[i] = &wgConn.StdNetEndpoint{AddrPort: addrPort}
			}
		}
	}

	return numMsgs, nil
}

// receiveIPv4Simple uses simple ReadFromUDP for non-Linux platforms
func (b *SharedBind) receiveIPv4Simple(conn *net.UDPConn, bufs [][]byte, sizes []int, eps []wgConn.Endpoint) (int, error) {
	n, addr, err := conn.ReadFromUDP(bufs[0])
	if err != nil {
		return 0, err
	}

	sizes[0] = n
	if addr != nil {
		addrPort := addr.AddrPort()
		eps[0] = &wgConn.StdNetEndpoint{AddrPort: addrPort}
	}

	return 1, nil
}

// Send implements the WireGuard Bind interface.
// It sends packets to the specified endpoint.
func (b *SharedBind) Send(bufs [][]byte, ep wgConn.Endpoint) error {
	if b.closed.Load() {
		return net.ErrClosed
	}

	b.mu.RLock()
	conn := b.udpConn
	b.mu.RUnlock()

	if conn == nil {
		return net.ErrClosed
	}

	// Extract the destination address from the endpoint
	var destAddr *net.UDPAddr

	// Try to cast to StdNetEndpoint first
	if stdEp, ok := ep.(*wgConn.StdNetEndpoint); ok {
		destAddr = net.UDPAddrFromAddrPort(stdEp.AddrPort)
	} else {
		// Fallback: construct from DstIP and DstToBytes
		dstBytes := ep.DstToBytes()
		if len(dstBytes) >= 6 { // Minimum for IPv4 (4 bytes) + port (2 bytes)
			var addr netip.Addr
			var port uint16

			if len(dstBytes) >= 18 { // IPv6 (16 bytes) + port (2 bytes)
				addr, _ = netip.AddrFromSlice(dstBytes[:16])
				port = uint16(dstBytes[16]) | uint16(dstBytes[17])<<8
			} else { // IPv4
				addr, _ = netip.AddrFromSlice(dstBytes[:4])
				port = uint16(dstBytes[4]) | uint16(dstBytes[5])<<8
			}

			if addr.IsValid() {
				destAddr = net.UDPAddrFromAddrPort(netip.AddrPortFrom(addr, port))
			}
		}
	}

	if destAddr == nil {
		return fmt.Errorf("could not extract destination address from endpoint")
	}

	// Send all buffers to the destination
	for _, buf := range bufs {
		_, err := conn.WriteToUDP(buf, destAddr)
		if err != nil {
			return err
		}
	}

	return nil
}

// SetMark implements the WireGuard Bind interface.
// It's a no-op for this implementation.
func (b *SharedBind) SetMark(mark uint32) error {
	// Not implemented for this use case
	return nil
}

// BatchSize returns the preferred batch size for sending packets.
func (b *SharedBind) BatchSize() int {
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		return wgConn.IdealBatchSize
	}
	return 1
}

// ParseEndpoint creates a new endpoint from a string address.
func (b *SharedBind) ParseEndpoint(s string) (wgConn.Endpoint, error) {
	addrPort, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &wgConn.StdNetEndpoint{AddrPort: addrPort}, nil
}
