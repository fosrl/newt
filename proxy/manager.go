package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fosrl/newt/internal/state"
	"github.com/fosrl/newt/internal/telemetry"
	"github.com/fosrl/newt/logger"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const (
	errUnsupportedProtoFmt = "unsupported protocol: %s"
	maxUDPPacketSize       = 65507 // Maximum UDP packet size
	defaultUDPIdleTimeout  = 90 * time.Second
)

// udpBufferPool provides reusable buffers for UDP packet handling.
// This reduces GC pressure from frequent large allocations.
var udpBufferPool = sync.Pool{
	New: func() any {
		buf := make([]byte, maxUDPPacketSize)
		return &buf
	},
}

// getUDPBuffer retrieves a buffer from the pool.
func getUDPBuffer() *[]byte {
	return udpBufferPool.Get().(*[]byte)
}

// putUDPBuffer clears and returns a buffer to the pool.
func putUDPBuffer(buf *[]byte) {
	// Clear the buffer to prevent data leakage
	clear(*buf)
	udpBufferPool.Put(buf)
}

// Target represents a proxy target with its address and port
type Target struct {
	Address string
	Port    int
}

// managedListener wraps a net.Listener so an intentional Close() can be
// detected reliably by the accept loop. gVisor's netstack (unlike the
// stdlib) does not return net.ErrClosed from Accept() after Close() - it
// returns a generic "endpoint is in invalid state" error - so relying on
// errors.Is(err, net.ErrClosed) leaves the accept loop spinning forever.
type managedListener struct {
	net.Listener
	closed chan struct{}
}

func newManagedListener(l net.Listener) *managedListener {
	return &managedListener{Listener: l, closed: make(chan struct{})}
}

func (m *managedListener) Close() error {
	err := m.Listener.Close()
	select {
	case <-m.closed:
	default:
		close(m.closed)
	}
	return err
}

// managedPacketConn is the net.PacketConn equivalent of managedListener.
type managedPacketConn struct {
	net.PacketConn
	closed chan struct{}
}

func newManagedPacketConn(c net.PacketConn) *managedPacketConn {
	return &managedPacketConn{PacketConn: c, closed: make(chan struct{})}
}

func (m *managedPacketConn) Close() error {
	err := m.PacketConn.Close()
	select {
	case <-m.closed:
	default:
		close(m.closed)
	}
	return err
}

// ProxyManager handles the creation and management of proxy connections
type ProxyManager struct {
	tnet           *netstack.Net
	tcpTargets     map[string]map[int]string // map[listenIP]map[port]targetAddress
	udpTargets     map[string]map[int]string
	listeners      []net.Listener
	udpConns       []net.PacketConn
	running        bool
	mutex          sync.RWMutex
	nativeListenIP string // when non-empty, use native OS listeners instead of netstack

	// telemetry (multi-tunnel)
	currentTunnelID string
	tunnels         map[string]*tunnelEntry
	asyncBytes      bool
	flushStop       chan struct{}
	udpIdleTimeout  time.Duration

	// connection blocking
	blocked atomic.Bool
}

// tunnelEntry holds per-tunnel attributes and (optional) async counters.
type tunnelEntry struct {
	attrInTCP  attribute.Set
	attrOutTCP attribute.Set
	attrInUDP  attribute.Set
	attrOutUDP attribute.Set

	bytesInTCP  atomic.Uint64
	bytesOutTCP atomic.Uint64
	bytesInUDP  atomic.Uint64
	bytesOutUDP atomic.Uint64

	activeTCP atomic.Int64
	activeUDP atomic.Int64
}

// countingWriter wraps an io.Writer and adds bytes to OTel counter using a pre-built attribute set.
type countingWriter struct {
	ctx   context.Context
	w     io.Writer
	set   attribute.Set
	pm    *ProxyManager
	ent   *tunnelEntry
	out   bool   // false=in, true=out
	proto string // "tcp" or "udp"
}

func (cw *countingWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	if n > 0 {
		if cw.pm != nil && cw.pm.asyncBytes && cw.ent != nil {
			switch cw.proto {
			case "tcp":
				if cw.out {
					cw.ent.bytesOutTCP.Add(uint64(n))
				} else {
					cw.ent.bytesInTCP.Add(uint64(n))
				}
			case "udp":
				if cw.out {
					cw.ent.bytesOutUDP.Add(uint64(n))
				} else {
					cw.ent.bytesInUDP.Add(uint64(n))
				}
			}
		} else {
			telemetry.AddTunnelBytesSet(cw.ctx, int64(n), cw.set)
		}
	}
	return n, err
}

func classifyProxyError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, net.ErrClosed) {
		return "closed"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "refused"):
		return "refused"
	case strings.Contains(msg, "reset"):
		return "reset"
	default:
		return "io_error"
	}
}

// NewProxyManager creates a new proxy manager instance backed by a netstack.
func NewProxyManager(tnet *netstack.Net) *ProxyManager {
	return &ProxyManager{
		tnet:           tnet,
		tcpTargets:     make(map[string]map[int]string),
		udpTargets:     make(map[string]map[int]string),
		listeners:      make([]net.Listener, 0),
		udpConns:       make([]net.PacketConn, 0),
		tunnels:        make(map[string]*tunnelEntry),
		udpIdleTimeout: defaultUDPIdleTimeout,
	}
}

// NewProxyManagerNative creates a proxy manager that binds listeners directly
// to the host network stack on the given IP address.
func NewProxyManagerNative(listenIP string) *ProxyManager {
	return &ProxyManager{
		nativeListenIP: listenIP,
		tcpTargets:     make(map[string]map[int]string),
		udpTargets:     make(map[string]map[int]string),
		listeners:      make([]net.Listener, 0),
		udpConns:       make([]net.PacketConn, 0),
		tunnels:        make(map[string]*tunnelEntry),
		udpIdleTimeout: defaultUDPIdleTimeout,
	}
}

// SetTunnelID sets the WireGuard peer public key used as tunnel_id label.
func (pm *ProxyManager) SetTunnelID(id string) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()
	pm.currentTunnelID = id
	if _, ok := pm.tunnels[id]; !ok {
		pm.tunnels[id] = &tunnelEntry{}
	}
	e := pm.tunnels[id]
	// include site labels if available
	site := telemetry.SiteLabelKVs()
	build := func(base []attribute.KeyValue) attribute.Set {
		if telemetry.ShouldIncludeTunnelID() {
			base = append([]attribute.KeyValue{attribute.String("tunnel_id", id)}, base...)
		}
		base = append(site, base...)
		return attribute.NewSet(base...)
	}
	e.attrInTCP = build([]attribute.KeyValue{
		attribute.String("direction", "ingress"),
		attribute.String("protocol", "tcp"),
	})
	e.attrOutTCP = build([]attribute.KeyValue{
		attribute.String("direction", "egress"),
		attribute.String("protocol", "tcp"),
	})
	e.attrInUDP = build([]attribute.KeyValue{
		attribute.String("direction", "ingress"),
		attribute.String("protocol", "udp"),
	})
	e.attrOutUDP = build([]attribute.KeyValue{
		attribute.String("direction", "egress"),
		attribute.String("protocol", "udp"),
	})
}

// ClearTunnelID clears cached attribute sets for the current tunnel.
func (pm *ProxyManager) ClearTunnelID() {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()
	id := pm.currentTunnelID
	if id == "" {
		return
	}
	if e, ok := pm.tunnels[id]; ok {
		// final flush for this tunnel
		inTCP := e.bytesInTCP.Swap(0)
		outTCP := e.bytesOutTCP.Swap(0)
		inUDP := e.bytesInUDP.Swap(0)
		outUDP := e.bytesOutUDP.Swap(0)
		if inTCP > 0 {
			telemetry.AddTunnelBytesSet(context.Background(), int64(inTCP), e.attrInTCP)
		}
		if outTCP > 0 {
			telemetry.AddTunnelBytesSet(context.Background(), int64(outTCP), e.attrOutTCP)
		}
		if inUDP > 0 {
			telemetry.AddTunnelBytesSet(context.Background(), int64(inUDP), e.attrInUDP)
		}
		if outUDP > 0 {
			telemetry.AddTunnelBytesSet(context.Background(), int64(outUDP), e.attrOutUDP)
		}
		delete(pm.tunnels, id)
	}
	pm.currentTunnelID = ""
}

// NewProxyManagerWithoutTNet creates a proxy manager with no backing network.
// Call SetTNet before starting.
func NewProxyManagerWithoutTNet() *ProxyManager {
	return &ProxyManager{
		tcpTargets:     make(map[string]map[int]string),
		udpTargets:     make(map[string]map[int]string),
		listeners:      make([]net.Listener, 0),
		udpConns:       make([]net.PacketConn, 0),
		udpIdleTimeout: defaultUDPIdleTimeout,
	}
}

// Function to add tnet to existing ProxyManager
func (pm *ProxyManager) SetTNet(tnet *netstack.Net) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()
	pm.tnet = tnet
}

// SetBlocked enables or disables connection blocking.
// When enabled, all new incoming TCP connections are immediately closed
// and all incoming UDP packets are silently dropped.
func (pm *ProxyManager) SetBlocked(v bool) {
	pm.blocked.Store(v)
	if v {
		logger.Debug("ProxyManager: connection blocking enabled, new connections will be dropped")
	} else {
		logger.Debug("ProxyManager: connection blocking disabled, accepting connections")
	}
}

// AddTarget adds as new target for proxying
func (pm *ProxyManager) AddTarget(proto, listenIP string, port int, targetAddr string) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	switch proto {
	case "tcp":
		if pm.tcpTargets[listenIP] == nil {
			pm.tcpTargets[listenIP] = make(map[int]string)
		}
		pm.tcpTargets[listenIP][port] = targetAddr
	case "udp":
		if pm.udpTargets[listenIP] == nil {
			pm.udpTargets[listenIP] = make(map[int]string)
		}
		pm.udpTargets[listenIP][port] = targetAddr
	default:
		return fmt.Errorf(errUnsupportedProtoFmt, proto)
	}

	if pm.running {
		return pm.startTarget(proto, listenIP, port, targetAddr)
	} else {
		logger.Debug("Not adding target because not running")
	}
	return nil
}

func (pm *ProxyManager) RemoveTarget(proto, listenIP string, port int) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	switch proto {
	case "tcp":
		if targets, ok := pm.tcpTargets[listenIP]; ok {
			delete(targets, port)
			// Remove and close the corresponding TCP listener
			for i, listener := range pm.listeners {
				if addr, ok := listener.Addr().(*net.TCPAddr); ok && addr.Port == port {
					listener.Close()
					time.Sleep(50 * time.Millisecond)
					// Remove from slice
					pm.listeners = append(pm.listeners[:i], pm.listeners[i+1:]...)
					break
				}
			}
		} else {
			return fmt.Errorf("target not found: %s:%d", listenIP, port)
		}
	case "udp":
		if targets, ok := pm.udpTargets[listenIP]; ok {
			delete(targets, port)
			// Remove and close the corresponding UDP connection
			for i, conn := range pm.udpConns {
				if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok && addr.Port == port {
					conn.Close()
					time.Sleep(50 * time.Millisecond)
					// Remove from slice
					pm.udpConns = append(pm.udpConns[:i], pm.udpConns[i+1:]...)
					break
				}
			}
		} else {
			return fmt.Errorf("target not found: %s:%d", listenIP, port)
		}
	default:
		return fmt.Errorf(errUnsupportedProtoFmt, proto)
	}
	return nil
}

// Start begins listening for all configured proxy targets
func (pm *ProxyManager) Start() error {
	// Register proxy observables once per process
	telemetry.SetProxyObservableCallback(func(ctx context.Context, o metric.Observer) error {
		pm.mutex.RLock()
		defer pm.mutex.RUnlock()
		for _, e := range pm.tunnels {
			// active connections
			telemetry.ObserveProxyActiveConnsObs(o, e.activeTCP.Load(), e.attrOutTCP.ToSlice())
			telemetry.ObserveProxyActiveConnsObs(o, e.activeUDP.Load(), e.attrOutUDP.ToSlice())
			// backlog bytes (sum of unflushed counters)
			b := int64(e.bytesInTCP.Load() + e.bytesOutTCP.Load() + e.bytesInUDP.Load() + e.bytesOutUDP.Load())
			telemetry.ObserveProxyAsyncBacklogObs(o, b, e.attrOutTCP.ToSlice())
			telemetry.ObserveProxyBufferBytesObs(o, b, e.attrOutTCP.ToSlice())
		}
		return nil
	})
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if pm.running {
		return nil
	}

	// Start TCP targets
	for listenIP, targets := range pm.tcpTargets {
		for port, targetAddr := range targets {
			if err := pm.startTarget("tcp", listenIP, port, targetAddr); err != nil {
				return fmt.Errorf("failed to start TCP target: %v", err)
			}
		}
	}

	// Start UDP targets
	for listenIP, targets := range pm.udpTargets {
		for port, targetAddr := range targets {
			if err := pm.startTarget("udp", listenIP, port, targetAddr); err != nil {
				return fmt.Errorf("failed to start UDP target: %v", err)
			}
		}
	}

	pm.running = true
	return nil
}

func (pm *ProxyManager) SetAsyncBytes(b bool) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()
	pm.asyncBytes = b
	if b && pm.flushStop == nil {
		pm.flushStop = make(chan struct{})
		go pm.flushLoop()
	}
}

// SetUDPIdleTimeout configures when idle UDP client flows are reclaimed.
func (pm *ProxyManager) SetUDPIdleTimeout(d time.Duration) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()
	if d <= 0 {
		pm.udpIdleTimeout = defaultUDPIdleTimeout
		return
	}
	pm.udpIdleTimeout = d
}
func (pm *ProxyManager) flushLoop() {
	flushInterval := 2 * time.Second
	if v := os.Getenv("OTEL_METRIC_EXPORT_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			if d/2 < flushInterval {
				flushInterval = d / 2
			}
		}
	}
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			pm.mutex.RLock()
			for _, e := range pm.tunnels {
				inTCP := e.bytesInTCP.Swap(0)
				outTCP := e.bytesOutTCP.Swap(0)
				inUDP := e.bytesInUDP.Swap(0)
				outUDP := e.bytesOutUDP.Swap(0)
				if inTCP > 0 {
					telemetry.AddTunnelBytesSet(context.Background(), int64(inTCP), e.attrInTCP)
				}
				if outTCP > 0 {
					telemetry.AddTunnelBytesSet(context.Background(), int64(outTCP), e.attrOutTCP)
				}
				if inUDP > 0 {
					telemetry.AddTunnelBytesSet(context.Background(), int64(inUDP), e.attrInUDP)
				}
				if outUDP > 0 {
					telemetry.AddTunnelBytesSet(context.Background(), int64(outUDP), e.attrOutUDP)
				}
			}
			pm.mutex.RUnlock()
		case <-pm.flushStop:
			pm.mutex.RLock()
			for _, e := range pm.tunnels {
				inTCP := e.bytesInTCP.Swap(0)
				outTCP := e.bytesOutTCP.Swap(0)
				inUDP := e.bytesInUDP.Swap(0)
				outUDP := e.bytesOutUDP.Swap(0)
				if inTCP > 0 {
					telemetry.AddTunnelBytesSet(context.Background(), int64(inTCP), e.attrInTCP)
				}
				if outTCP > 0 {
					telemetry.AddTunnelBytesSet(context.Background(), int64(outTCP), e.attrOutTCP)
				}
				if inUDP > 0 {
					telemetry.AddTunnelBytesSet(context.Background(), int64(inUDP), e.attrInUDP)
				}
				if outUDP > 0 {
					telemetry.AddTunnelBytesSet(context.Background(), int64(outUDP), e.attrOutUDP)
				}
			}
			pm.mutex.RUnlock()
			return
		}
	}
}

func (pm *ProxyManager) Stop() error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if !pm.running {
		return nil
	}

	// Set running to false first to signal handlers to stop
	pm.running = false

	// Close TCP listeners
	for i := len(pm.listeners) - 1; i >= 0; i-- {
		listener := pm.listeners[i]
		if err := listener.Close(); err != nil {
			logger.Error("Error closing TCP listener: %v", err)
		}
		// Remove from slice
		pm.listeners = append(pm.listeners[:i], pm.listeners[i+1:]...)
	}

	// Close UDP connections
	for i := len(pm.udpConns) - 1; i >= 0; i-- {
		conn := pm.udpConns[i]
		if err := conn.Close(); err != nil {
			logger.Error("Error closing UDP connection: %v", err)
		}
		// Remove from slice
		pm.udpConns = append(pm.udpConns[:i], pm.udpConns[i+1:]...)
	}

	// Give active connections a chance to close gracefully
	time.Sleep(100 * time.Millisecond)

	return nil
}

func (pm *ProxyManager) startTarget(proto, listenIP string, port int, targetAddr string) error {
	switch proto {
	case "tcp":
		var listener net.Listener
		if pm.tnet != nil {
			l, err := pm.tnet.ListenTCP(&net.TCPAddr{Port: port})
			if err != nil {
				return fmt.Errorf("failed to create TCP listener: %v", err)
			}
			listener = l
		} else if pm.nativeListenIP != "" {
			l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP(pm.nativeListenIP), Port: port})
			if err != nil {
				return fmt.Errorf("failed to create native TCP listener on %s:%d: %v", pm.nativeListenIP, port, err)
			}
			listener = l
		} else {
			return fmt.Errorf("proxy manager has no tnet or native IP configured")
		}
		ml := newManagedListener(listener)
		pm.listeners = append(pm.listeners, ml)
		go pm.handleTCPProxy(ml, targetAddr)

	case "udp":
		var conn net.PacketConn
		if pm.tnet != nil {
			c, err := pm.tnet.ListenUDP(&net.UDPAddr{Port: port})
			if err != nil {
				return fmt.Errorf("failed to create UDP listener: %v", err)
			}
			conn = c
		} else if pm.nativeListenIP != "" {
			c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(pm.nativeListenIP), Port: port})
			if err != nil {
				return fmt.Errorf("failed to create native UDP listener on %s:%d: %v", pm.nativeListenIP, port, err)
			}
			conn = c
		} else {
			return fmt.Errorf("proxy manager has no tnet or native IP configured")
		}
		mc := newManagedPacketConn(conn)
		pm.udpConns = append(pm.udpConns, mc)
		go pm.handleUDPProxy(mc, targetAddr)

	default:
		return fmt.Errorf(errUnsupportedProtoFmt, proto)
	}

	logger.Info("Started %s proxy to %s", proto, targetAddr)
	logger.Debug("Started %s proxy from %s:%d to %s", proto, listenIP, port, targetAddr)

	return nil
}

// getEntry returns per-tunnel entry or nil.
func (pm *ProxyManager) getEntry(id string) *tunnelEntry {
	pm.mutex.RLock()
	e := pm.tunnels[id]
	pm.mutex.RUnlock()
	return e
}

func (pm *ProxyManager) handleTCPProxy(listener *managedListener, targetAddr string) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			telemetry.IncProxyAccept(context.Background(), pm.currentTunnelID, "tcp", "failure", classifyProxyError(err))
			select {
			case <-listener.closed:
				logger.Info("TCP listener closed, stopping proxy handler for %v", listener.Addr())
				return
			default:
			}
			if !pm.running {
				return
			}
			if errors.Is(err, net.ErrClosed) {
				logger.Info("TCP listener closed, stopping proxy handler for %v", listener.Addr())
				return
			}
			logger.Error("Error accepting TCP connection: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}

		tunnelID := pm.currentTunnelID
		// Drop connection if blocking is enabled
		if pm.blocked.Load() {
			conn.Close()
			logger.Debug("TCP proxy: connection dropped (blocking enabled)")
			continue
		}
		telemetry.IncProxyAccept(context.Background(), tunnelID, "tcp", "success", "")
		telemetry.IncProxyConnectionEvent(context.Background(), tunnelID, "tcp", telemetry.ProxyConnectionOpened)
		if tunnelID != "" {
			state.Global().IncSessions(tunnelID)
			if e := pm.getEntry(tunnelID); e != nil {
				e.activeTCP.Add(1)
			}
		}

		go func(tunnelID string, accepted net.Conn) {
			connStart := time.Now()
			target, err := net.Dial("tcp", targetAddr)
			if err != nil {
				logger.Error("Error connecting to target: %v", err)
				accepted.Close()
				telemetry.IncProxyAccept(context.Background(), tunnelID, "tcp", "failure", classifyProxyError(err))
				telemetry.IncProxyConnectionEvent(context.Background(), tunnelID, "tcp", telemetry.ProxyConnectionClosed)
				telemetry.ObserveProxyConnectionDuration(context.Background(), tunnelID, "tcp", "failure", time.Since(connStart).Seconds())
				return
			}

			entry := pm.getEntry(tunnelID)
			if entry == nil {
				entry = &tunnelEntry{}
			}
			var wg sync.WaitGroup
			wg.Add(2)

			go func(ent *tunnelEntry) {
				defer wg.Done()
				cw := &countingWriter{ctx: context.Background(), w: target, set: ent.attrInTCP, pm: pm, ent: ent, out: false, proto: "tcp"}
				_, _ = io.Copy(cw, accepted)
				_ = target.Close()
			}(entry)

			go func(ent *tunnelEntry) {
				defer wg.Done()
				cw := &countingWriter{ctx: context.Background(), w: accepted, set: ent.attrOutTCP, pm: pm, ent: ent, out: true, proto: "tcp"}
				_, _ = io.Copy(cw, target)
				_ = accepted.Close()
			}(entry)

			wg.Wait()
			if tunnelID != "" {
				state.Global().DecSessions(tunnelID)
				if e := pm.getEntry(tunnelID); e != nil {
					e.activeTCP.Add(-1)
				}
			}
			telemetry.ObserveProxyConnectionDuration(context.Background(), tunnelID, "tcp", "success", time.Since(connStart).Seconds())
			telemetry.IncProxyConnectionEvent(context.Background(), tunnelID, "tcp", telemetry.ProxyConnectionClosed)
		}(tunnelID, conn)
	}
}

func (pm *ProxyManager) handleUDPProxy(conn *managedPacketConn, targetAddr string) {
	bufPtr := getUDPBuffer()
	defer putUDPBuffer(bufPtr)
	buffer := *bufPtr
	clientConns := make(map[string]*net.UDPConn)
	var clientsMutex sync.RWMutex

	for {
		n, remoteAddr, err := conn.ReadFrom(buffer)
		if err != nil {
			closeAllClients := func() {
				clientsMutex.Lock()
				for _, targetConn := range clientConns {
					targetConn.Close()
				}
				clientConns = nil
				clientsMutex.Unlock()
			}

			// Check for intentional closure first: netstack does not
			// surface net.ErrClosed/io.EOF from ReadFrom() after Close(),
			// so this channel is the only reliable signal.
			select {
			case <-conn.closed:
				logger.Info("UDP connection closed, stopping proxy handler")
				closeAllClients()
				return
			default:
			}

			if !pm.running {
				closeAllClients()
				return
			}

			// Check for connection closed conditions
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				logger.Info("UDP connection closed, stopping proxy handler")
				closeAllClients()
				return
			}

			logger.Error("Error reading UDP packet: %v", err)
			// Avoid a tight busy-loop if this error persists.
			time.Sleep(100 * time.Millisecond)
			continue
		}

		clientKey := remoteAddr.String()
		// Drop packet if blocking is enabled
		if pm.blocked.Load() {
			logger.Debug("UDP proxy: packet dropped (blocking enabled)")
			continue
		}
		// bytes from client -> target (direction=in)
		if pm.currentTunnelID != "" && n > 0 {
			if pm.asyncBytes {
				if e := pm.getEntry(pm.currentTunnelID); e != nil {
					e.bytesInUDP.Add(uint64(n))
				}
			} else {
				if e := pm.getEntry(pm.currentTunnelID); e != nil {
					telemetry.AddTunnelBytesSet(context.Background(), int64(n), e.attrInUDP)
				}
			}
		}
		clientsMutex.RLock()
		targetConn, exists := clientConns[clientKey]
		clientsMutex.RUnlock()

		if !exists {
			targetUDPAddr, err := net.ResolveUDPAddr("udp", targetAddr)
			if err != nil {
				logger.Error("Error resolving target address: %v", err)
				telemetry.IncProxyAccept(context.Background(), pm.currentTunnelID, "udp", "failure", "resolve")
				continue
			}

			targetConn, err = net.DialUDP("udp", nil, targetUDPAddr)
			if err != nil {
				logger.Error("Error connecting to target: %v", err)
				telemetry.IncProxyAccept(context.Background(), pm.currentTunnelID, "udp", "failure", classifyProxyError(err))
				continue
			}
			// Prevent idle UDP client goroutines from living forever and
			// retaining large per-connection buffers.
			_ = targetConn.SetReadDeadline(time.Now().Add(pm.udpIdleTimeout))
			tunnelID := pm.currentTunnelID
			telemetry.IncProxyAccept(context.Background(), tunnelID, "udp", "success", "")
			telemetry.IncProxyConnectionEvent(context.Background(), tunnelID, "udp", telemetry.ProxyConnectionOpened)
			// Only increment activeUDP after a successful DialUDP
			if e := pm.getEntry(tunnelID); e != nil {
				e.activeUDP.Add(1)
			}

			clientsMutex.Lock()
			clientConns[clientKey] = targetConn
			clientsMutex.Unlock()

			go func(clientKey string, targetConn *net.UDPConn, remoteAddr net.Addr, tunnelID string) {
				start := time.Now()
				result := "success"
				bufPtr := getUDPBuffer()
				defer func() {
					// Return buffer to pool first
					putUDPBuffer(bufPtr)
					// Always clean up when this goroutine exits
					clientsMutex.Lock()
					if storedConn, exists := clientConns[clientKey]; exists && storedConn == targetConn {
						delete(clientConns, clientKey)
						targetConn.Close()
						if e := pm.getEntry(tunnelID); e != nil {
							e.activeUDP.Add(-1)
						}
					}
					clientsMutex.Unlock()
					telemetry.ObserveProxyConnectionDuration(context.Background(), tunnelID, "udp", result, time.Since(start).Seconds())
					telemetry.IncProxyConnectionEvent(context.Background(), tunnelID, "udp", telemetry.ProxyConnectionClosed)
				}()

				buffer := *bufPtr
				for {
					n, _, err := targetConn.ReadFromUDP(buffer)
					if err != nil {
						var netErr net.Error
						if errors.As(err, &netErr) && netErr.Timeout() {
							return
						}
						// Connection closed is normal during cleanup
						if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
							return // defer will handle cleanup, result stays "success"
						}
						logger.Error("Error reading from target: %v", err)
						result = "failure"
						return // defer will handle cleanup
					}

					// bytes from target -> client (direction=out)
					if pm.currentTunnelID != "" && n > 0 {
						if pm.asyncBytes {
							if e := pm.getEntry(pm.currentTunnelID); e != nil {
								e.bytesOutUDP.Add(uint64(n))
							}
						} else {
							if e := pm.getEntry(pm.currentTunnelID); e != nil {
								telemetry.AddTunnelBytesSet(context.Background(), int64(n), e.attrOutUDP)
							}
						}
					}

					_, err = conn.WriteTo(buffer[:n], remoteAddr)
					if err != nil {
						logger.Error("Error writing to client: %v", err)
						telemetry.IncProxyDrops(context.Background(), pm.currentTunnelID, "udp")
						result = "failure"
						return // defer will handle cleanup
					}
				}
			}(clientKey, targetConn, remoteAddr, tunnelID)
		}

		written, err := targetConn.Write(buffer[:n])
		if err != nil {
			logger.Error("Error writing to target: %v", err)
			telemetry.IncProxyDrops(context.Background(), pm.currentTunnelID, "udp")
			targetConn.Close()
			clientsMutex.Lock()
			delete(clientConns, clientKey)
			clientsMutex.Unlock()
		} else if pm.currentTunnelID != "" && written > 0 {
			// Extend idle timeout whenever client traffic is observed.
			_ = targetConn.SetReadDeadline(time.Now().Add(pm.udpIdleTimeout))
			if pm.asyncBytes {
				if e := pm.getEntry(pm.currentTunnelID); e != nil {
					e.bytesInUDP.Add(uint64(written))
				}
			} else {
				if e := pm.getEntry(pm.currentTunnelID); e != nil {
					telemetry.AddTunnelBytesSet(context.Background(), int64(written), e.attrInUDP)
				}
			}
		}
	}
}

// write a function to print out the current targets in the ProxyManager
func (pm *ProxyManager) PrintTargets() {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	logger.Info("Current TCP Targets:")
	for listenIP, targets := range pm.tcpTargets {
		for port, targetAddr := range targets {
			logger.Info("TCP %s:%d -> %s", listenIP, port, targetAddr)
		}
	}

	logger.Info("Current UDP Targets:")
	for listenIP, targets := range pm.udpTargets {
		for port, targetAddr := range targets {
			logger.Info("UDP %s:%d -> %s", listenIP, port, targetAddr)
		}
	}
}

// GetTargets returns a copy of the current TCP and UDP targets
// Returns map[listenIP]map[port]targetAddress for both TCP and UDP
func (pm *ProxyManager) GetTargets() (tcpTargets map[string]map[int]string, udpTargets map[string]map[int]string) {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	tcpTargets = make(map[string]map[int]string)
	for listenIP, targets := range pm.tcpTargets {
		tcpTargets[listenIP] = make(map[int]string)
		for port, targetAddr := range targets {
			tcpTargets[listenIP][port] = targetAddr
		}
	}

	udpTargets = make(map[string]map[int]string)
	for listenIP, targets := range pm.udpTargets {
		udpTargets[listenIP] = make(map[int]string)
		for port, targetAddr := range targets {
			udpTargets[listenIP][port] = targetAddr
		}
	}

	return tcpTargets, udpTargets
}
