//go:build !js

package bind

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/fosrl/newt/logger"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	wgConn "golang.zx2c4.com/wireguard/conn"
)

// Magic packet constants for connection testing
// These packets are intercepted by SharedBind and responded to directly,
// without being passed to the WireGuard device.
var (
	// MagicTestRequest is the prefix for a test request packet
	// Format: PANGOLIN_TEST_REQ + 8 bytes of random data (for echo)
	MagicTestRequest = []byte("PANGOLIN_TEST_REQ")

	// MagicTestResponse is the prefix for a test response packet
	// Format: PANGOLIN_TEST_RSP + 8 bytes echoed from request
	MagicTestResponse = []byte("PANGOLIN_TEST_RSP")
)

const (
	// MagicPacketDataLen is the length of random data included in test packets
	MagicPacketDataLen = 8

	// MagicTestRequestLen is the total length of a test request packet
	MagicTestRequestLen = 17 + MagicPacketDataLen // len("PANGOLIN_TEST_REQ") + 8

	// MagicTestResponseLen is the total length of a test response packet
	MagicTestResponseLen = 17 + MagicPacketDataLen // len("PANGOLIN_TEST_RSP") + 8
)

// PacketSource identifies where a packet came from
type PacketSource uint8

const (
	SourceSocket   PacketSource = iota // From physical UDP socket (hole-punched clients)
	SourceNetstack                     // From netstack (relay through main tunnel)
)

// SourceAwareEndpoint wraps an endpoint with source information
type SourceAwareEndpoint struct {
	wgConn.Endpoint
	source PacketSource
}

// GetSource returns the source of this endpoint
func (e *SourceAwareEndpoint) GetSource() PacketSource {
	return e.source
}

// injectedPacket represents a packet injected into the SharedBind from an internal source
type injectedPacket struct {
	data     []byte
	endpoint wgConn.Endpoint
}

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
// It also supports receiving packets from a netstack and routing responses
// back through the appropriate source.
type SharedBind struct {
	mu sync.RWMutex

	// The underlying UDP connection (for hole-punched clients)
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

	// Channel for packets from netstack (from direct relay) - larger buffer for throughput
	netstackPackets chan injectedPacket

	// Netstack connection for sending responses back through the tunnel
	// Using atomic.Pointer for lock-free access in hot path
	netstackConn atomic.Pointer[net.PacketConn]

	// Track which endpoints came from netstack (key: netip.AddrPort, value: struct{})
	// Using netip.AddrPort directly as key is more efficient than string
	netstackEndpoints sync.Map

	// Pre-allocated message buffers for batch operations (Linux only)
	ipv4Msgs []ipv4.Message

	// Shutdown signal for receive goroutines
	closeChan chan struct{}

	// Callback for magic test responses (used for holepunch testing)
	magicResponseCallback atomic.Pointer[func(addr netip.AddrPort, echoData []byte)]

	// Rebinding state - used to keep receive goroutines alive during socket transition
	rebinding     bool       // true when socket is being replaced
	rebindingCond *sync.Cond // signaled when rebind completes
}

// MagicResponseCallback is the function signature for magic packet response callbacks
type MagicResponseCallback func(addr netip.AddrPort, echoData []byte)

// New creates a new SharedBind from an existing UDP connection.
// The SharedBind takes ownership of the connection and will close it
// when all references are released.
func New(udpConn *net.UDPConn) (*SharedBind, error) {
	if udpConn == nil {
		return nil, fmt.Errorf("udpConn cannot be nil")
	}

	bind := &SharedBind{
		udpConn:         udpConn,
		netstackPackets: make(chan injectedPacket, 1024), // Larger buffer for better throughput
		closeChan:       make(chan struct{}),
	}

	// Initialize the rebinding condition variable
	bind.rebindingCond = sync.NewCond(&bind.mu)

	// Initialize reference count to 1 (the creator holds the first reference)
	bind.refCount.Store(1)

	// Get the local port
	if addr, ok := udpConn.LocalAddr().(*net.UDPAddr); ok {
		bind.port = uint16(addr.Port)
	}

	return bind, nil
}

// SetNetstackConn sets the netstack connection for receiving/sending packets through the tunnel.
// This connection is used for relay traffic that should go back through the main tunnel.
func (b *SharedBind) SetNetstackConn(conn net.PacketConn) {
	b.netstackConn.Store(&conn)
}

// GetNetstackConn returns the netstack connection if set
func (b *SharedBind) GetNetstackConn() net.PacketConn {
	ptr := b.netstackConn.Load()
	if ptr == nil {
		return nil
	}
	return *ptr
}

// InjectPacket allows injecting a packet directly into the SharedBind's receive path.
// This is used for direct relay from netstack without going through the host network.
// The fromAddr should be the address the packet appears to come from.
func (b *SharedBind) InjectPacket(data []byte, fromAddr netip.AddrPort) error {
	if b.closed.Load() {
		return net.ErrClosed
	}

	// Unmap IPv4-in-IPv6 addresses to ensure consistency with parsed endpoints
	if fromAddr.Addr().Is4In6() {
		fromAddr = netip.AddrPortFrom(fromAddr.Addr().Unmap(), fromAddr.Port())
	}

	// Track this endpoint as coming from netstack so responses go back the same way
	// Use AddrPort directly as key (more efficient than string)
	b.netstackEndpoints.Store(fromAddr, struct{}{})

	// Make a copy of the data to avoid issues with buffer reuse
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	select {
	case b.netstackPackets <- injectedPacket{
		data:     dataCopy,
		endpoint: &wgConn.StdNetEndpoint{AddrPort: fromAddr},
	}:
		return nil
	case <-b.closeChan:
		return net.ErrClosed
	default:
		// Channel full, drop the packet
		return fmt.Errorf("netstack packet buffer full")
	}
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

	// Signal all goroutines to stop
	close(b.closeChan)

	b.mu.Lock()
	defer b.mu.Unlock()

	var err error
	if b.udpConn != nil {
		err = b.udpConn.Close()
		b.udpConn = nil
	}

	b.ipv4PC = nil
	b.ipv6PC = nil

	// Clear netstack connection (but don't close it - it's managed externally)
	b.netstackConn.Store(nil)

	// Clear tracked netstack endpoints
	b.netstackEndpoints = sync.Map{}

	return err
}

// ClearNetstackConn clears the netstack connection and tracked endpoints.
// Call this when stopping the relay.
func (b *SharedBind) ClearNetstackConn() {
	b.netstackConn.Store(nil)

	// Clear tracked netstack endpoints
	b.netstackEndpoints = sync.Map{}
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

// GetPort returns the current UDP port the bind is using.
// This is useful when rebinding to try to reuse the same port.
func (b *SharedBind) GetPort() uint16 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.port
}

// CloseSocket closes the underlying UDP connection to release the port,
// but keeps the SharedBind in a state where it can accept a new connection via Rebind.
// This allows the caller to close the old socket first, then bind a new socket
// to the same port before calling Rebind.
//
// Returns the port that was being used, so the caller can attempt to rebind to it.
// Sets the rebinding flag so receive goroutines will wait for the new socket
// instead of exiting.
func (b *SharedBind) CloseSocket() (uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed.Load() {
		return 0, fmt.Errorf("bind is closed")
	}

	port := b.port

	// Set rebinding flag BEFORE closing the socket so receive goroutines
	// know to wait instead of exit
	b.rebinding = true

	// Close the old connection to release the port
	if b.udpConn != nil {
		logger.Debug("Closing UDP connection to release port %d (rebinding)", port)
		b.udpConn.Close()
		b.udpConn = nil
	}

	return port, nil
}

// Rebind replaces the underlying UDP connection with a new one.
// This is necessary when network connectivity changes (e.g., WiFi to cellular
// transition on macOS/iOS) and the old socket becomes stale.
//
// The caller is responsible for creating the new UDP connection and passing it here.
// After rebind, the caller should trigger a hole punch to re-establish NAT mappings.
//
// Note: Call CloseSocket() first if you need to rebind to the same port, as the
// old socket must be closed before a new socket can bind to the same port.
func (b *SharedBind) Rebind(newConn *net.UDPConn) error {
	if newConn == nil {
		return fmt.Errorf("newConn cannot be nil")
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed.Load() {
		return fmt.Errorf("bind is closed")
	}

	// Close the old connection if it's still open
	// (it may have already been closed via CloseSocket)
	if b.udpConn != nil {
		logger.Debug("Closing old UDP connection during rebind")
		b.udpConn.Close()
	}

	// Set up the new connection
	b.udpConn = newConn

	// Update packet connections for the new socket
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		b.ipv4PC = ipv4.NewPacketConn(newConn)
		b.ipv6PC = ipv6.NewPacketConn(newConn)

		// Re-initialize message buffers for batch operations
		batchSize := wgConn.IdealBatchSize
		b.ipv4Msgs = make([]ipv4.Message, batchSize)
		for i := range b.ipv4Msgs {
			b.ipv4Msgs[i].OOB = make([]byte, 0)
		}
	} else {
		// For non-Linux platforms, still set up ipv4PC for consistency
		b.ipv4PC = ipv4.NewPacketConn(newConn)
		b.ipv6PC = ipv6.NewPacketConn(newConn)
	}

	// Update the port
	if addr, ok := newConn.LocalAddr().(*net.UDPAddr); ok {
		b.port = uint16(addr.Port)
		logger.Info("Rebound UDP socket to port %d", b.port)
	}

	// Clear the rebinding flag and wake up any waiting receive goroutines
	b.rebinding = false
	b.rebindingCond.Broadcast()

	logger.Debug("Rebind complete, signaled waiting receive goroutines")

	return nil
}

// SetMagicResponseCallback sets a callback function that will be called when
// a magic test response packet is received. This is used for holepunch testing.
// Pass nil to clear the callback.
func (b *SharedBind) SetMagicResponseCallback(callback MagicResponseCallback) {
	if callback == nil {
		b.magicResponseCallback.Store(nil)
	} else {
		// Convert to the function type the atomic.Pointer expects
		fn := func(addr netip.AddrPort, echoData []byte) {
			callback(addr, echoData)
		}
		b.magicResponseCallback.Store(&fn)
	}
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

		// Pre-allocate message buffers for batch operations
		batchSize := wgConn.IdealBatchSize
		b.ipv4Msgs = make([]ipv4.Message, batchSize)
		for i := range b.ipv4Msgs {
			b.ipv4Msgs[i].OOB = make([]byte, 0)
		}
	}

	// Create receive functions - one for socket, one for netstack
	recvFuncs := make([]wgConn.ReceiveFunc, 0, 2)

	// Add socket receive function (reads from physical UDP socket)
	recvFuncs = append(recvFuncs, b.makeReceiveSocket())

	// Add netstack receive function (reads from injected packets channel)
	recvFuncs = append(recvFuncs, b.makeReceiveNetstack())

	b.recvFuncs = recvFuncs
	return recvFuncs, b.port, nil
}

// makeReceiveSocket creates a receive function for physical UDP socket packets
func (b *SharedBind) makeReceiveSocket() wgConn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []wgConn.Endpoint) (n int, err error) {
		for {
			if b.closed.Load() {
				return 0, net.ErrClosed
			}

			b.mu.RLock()
			conn := b.udpConn
			pc := b.ipv4PC
			b.mu.RUnlock()

			if conn == nil {
				// Socket is nil - check if we're rebinding or truly closed
				if b.closed.Load() {
					return 0, net.ErrClosed
				}

				// Wait for rebind to complete
				b.mu.Lock()
				for b.rebinding && !b.closed.Load() {
					logger.Debug("Receive goroutine waiting for socket rebind to complete")
					b.rebindingCond.Wait()
				}
				b.mu.Unlock()

				// Check again after waking up
				if b.closed.Load() {
					return 0, net.ErrClosed
				}

				// Loop back to retry with new socket
				continue
			}

			// Use batch reading on Linux for performance
			var n int
			var err error
			if pc != nil && (runtime.GOOS == "linux" || runtime.GOOS == "android") {
				n, err = b.receiveIPv4Batch(pc, bufs, sizes, eps)
			} else {
				n, err = b.receiveIPv4Simple(conn, bufs, sizes, eps)
			}

			if err != nil {
				// Check if this error is due to rebinding
				b.mu.RLock()
				rebinding := b.rebinding
				b.mu.RUnlock()

				if rebinding {
					logger.Debug("Receive got error during rebind, waiting for new socket: %v", err)
					// Wait for rebind to complete and retry
					b.mu.Lock()
					for b.rebinding && !b.closed.Load() {
						b.rebindingCond.Wait()
					}
					b.mu.Unlock()

					if b.closed.Load() {
						return 0, net.ErrClosed
					}

					// Retry with new socket
					continue
				}

				// Not rebinding, return the error
				return 0, err
			}

			return n, nil
		}
	}
}

// makeReceiveNetstack creates a receive function for netstack-injected packets
func (b *SharedBind) makeReceiveNetstack() wgConn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []wgConn.Endpoint) (n int, err error) {
		select {
		case <-b.closeChan:
			return 0, net.ErrClosed
		case pkt := <-b.netstackPackets:
			if len(pkt.data) <= len(bufs[0]) {
				copy(bufs[0], pkt.data)
				sizes[0] = len(pkt.data)
				eps[0] = pkt.endpoint
				return 1, nil
			}
			// Packet too large for buffer, skip it
			return 0, nil
		}
	}
}

// receiveIPv4Batch uses batch reading for better performance on Linux
func (b *SharedBind) receiveIPv4Batch(pc *ipv4.PacketConn, bufs [][]byte, sizes []int, eps []wgConn.Endpoint) (int, error) {
	// Use pre-allocated messages, just update buffer pointers
	numBufs := len(bufs)
	if numBufs > len(b.ipv4Msgs) {
		numBufs = len(b.ipv4Msgs)
	}

	for i := 0; i < numBufs; i++ {
		b.ipv4Msgs[i].Buffers = [][]byte{bufs[i]}
	}

	numMsgs, err := pc.ReadBatch(b.ipv4Msgs[:numBufs], 0)
	if err != nil {
		return 0, err
	}

	// Process messages and filter out magic packets
	writeIdx := 0
	for i := 0; i < numMsgs; i++ {
		if b.ipv4Msgs[i].N == 0 {
			continue
		}

		// Check for magic packet
		if b.ipv4Msgs[i].Addr != nil {
			if udpAddr, ok := b.ipv4Msgs[i].Addr.(*net.UDPAddr); ok {
				data := bufs[i][:b.ipv4Msgs[i].N]
				if b.handleMagicPacket(data, udpAddr) {
					// Magic packet handled, skip this message
					continue
				}
			}
		}

		// Not a magic packet, include in output
		if writeIdx != i {
			// Need to copy data to the correct position
			copy(bufs[writeIdx], bufs[i][:b.ipv4Msgs[i].N])
		}
		sizes[writeIdx] = b.ipv4Msgs[i].N

		if b.ipv4Msgs[i].Addr != nil {
			if udpAddr, ok := b.ipv4Msgs[i].Addr.(*net.UDPAddr); ok {
				addrPort := udpAddr.AddrPort()
				// Unmap IPv4-in-IPv6 addresses to ensure consistency with parsed endpoints
				if addrPort.Addr().Is4In6() {
					addrPort = netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port())
				}
				eps[writeIdx] = &wgConn.StdNetEndpoint{AddrPort: addrPort}
			}
		}
		writeIdx++
	}

	return writeIdx, nil
}

// receiveIPv4Simple uses simple ReadFromUDP for non-Linux platforms
func (b *SharedBind) receiveIPv4Simple(conn *net.UDPConn, bufs [][]byte, sizes []int, eps []wgConn.Endpoint) (int, error) {
	// No read deadline - we rely on socket close to unblock during rebind.
	// The caller (makeReceiveSocket) handles rebind state when errors occur.
	for {
		n, addr, err := conn.ReadFromUDP(bufs[0])
		if err != nil {
			return 0, err
		}

		// Check for magic test packet and handle it directly
		if b.handleMagicPacket(bufs[0][:n], addr) {
			// Magic packet was handled, read another packet
			continue
		}

		sizes[0] = n
		if addr != nil {
			addrPort := addr.AddrPort()
			// Unmap IPv4-in-IPv6 addresses to ensure consistency with parsed endpoints
			if addrPort.Addr().Is4In6() {
				addrPort = netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port())
			}
			eps[0] = &wgConn.StdNetEndpoint{AddrPort: addrPort}
		}

		return 1, nil
	}
}

// handleMagicPacket checks if the packet is a magic test packet and responds if so.
// Returns true if the packet was a magic packet and was handled (should not be passed to WireGuard).
func (b *SharedBind) handleMagicPacket(data []byte, addr *net.UDPAddr) bool {
	// Check if this is a test request packet
	if len(data) >= MagicTestRequestLen && bytes.HasPrefix(data, MagicTestRequest) {
		// logger.Debug("Received magic test REQUEST from %s, sending response", addr.String())
		// Extract the random data portion to echo back
		echoData := data[len(MagicTestRequest) : len(MagicTestRequest)+MagicPacketDataLen]

		// Build response packet
		response := make([]byte, MagicTestResponseLen)
		copy(response, MagicTestResponse)
		copy(response[len(MagicTestResponse):], echoData)

		// Send response back to sender
		b.mu.RLock()
		conn := b.udpConn
		b.mu.RUnlock()

		if conn != nil {
			_, _ = conn.WriteToUDP(response, addr)
		}

		return true
	}

	// Check if this is a test response packet
	if len(data) >= MagicTestResponseLen && bytes.HasPrefix(data, MagicTestResponse) {
		// logger.Debug("Received magic test RESPONSE from %s", addr.String())
		// Extract the echoed data
		echoData := data[len(MagicTestResponse) : len(MagicTestResponse)+MagicPacketDataLen]

		// Call the callback if set
		callbackPtr := b.magicResponseCallback.Load()
		if callbackPtr != nil {
			callback := *callbackPtr
			addrPort := addr.AddrPort()
			// Unmap IPv4-in-IPv6 addresses to ensure consistency
			if addrPort.Addr().Is4In6() {
				addrPort = netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port())
			}
			callback(addrPort, echoData)
		} else {
			logger.Debug("Magic response received but no callback registered")
		}

		return true
	}

	return false
}

// Send implements the WireGuard Bind interface.
// It sends packets to the specified endpoint, routing through the appropriate
// source (netstack or physical socket) based on where the endpoint's packets came from.
func (b *SharedBind) Send(bufs [][]byte, ep wgConn.Endpoint) error {
	if b.closed.Load() {
		return net.ErrClosed
	}

	// Extract the destination address from the endpoint
	var destAddrPort netip.AddrPort

	// Try to cast to StdNetEndpoint first (most common case, avoid allocations)
	if stdEp, ok := ep.(*wgConn.StdNetEndpoint); ok {
		destAddrPort = stdEp.AddrPort
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
				destAddrPort = netip.AddrPortFrom(addr, port)
			}
		}
	}

	if !destAddrPort.IsValid() {
		return fmt.Errorf("could not extract destination address from endpoint")
	}

	// Check if this endpoint came from netstack - if so, send through netstack
	// Use AddrPort directly as key (more efficient than string conversion)
	if _, isNetstackEndpoint := b.netstackEndpoints.Load(destAddrPort); isNetstackEndpoint {
		connPtr := b.netstackConn.Load()
		if connPtr != nil && *connPtr != nil {
			netstackConn := *connPtr
			destAddr := net.UDPAddrFromAddrPort(destAddrPort)
			// Send all buffers through netstack
			for _, buf := range bufs {
				_, err := netstackConn.WriteTo(buf, destAddr)
				if err != nil {
					return err
				}
			}
			return nil
		}
		// Fall through to socket if netstack conn not available
	}

	// Send through the physical UDP socket (for hole-punched clients)
	b.mu.RLock()
	conn := b.udpConn
	b.mu.RUnlock()

	if conn == nil {
		return net.ErrClosed
	}

	destAddr := net.UDPAddrFromAddrPort(destAddrPort)

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
