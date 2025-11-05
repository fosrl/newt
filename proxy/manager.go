package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fosrl/newt/internal/state"
	"github.com/fosrl/newt/internal/telemetry"
	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/netstack2"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

const errUnsupportedProtoFmt = "unsupported protocol: %s"

// Target represents a proxy target with its address and port
type Target struct {
	Address string
	Port    int
}

// ProxyManager handles the creation and management of proxy connections
type ProxyManager struct {
	tnet       *netstack2.Net
	tcpTargets map[string]map[int]string // map[listenIP]map[port]targetAddress
	udpTargets map[string]map[int]string
	listeners  []*gonet.TCPListener
	udpConns   []*gonet.UDPConn
	running    bool
	mutex      sync.RWMutex

	// network-level proxying (subnet interception)
	networkTargets map[string]bool              // map[subnet_cidr]bool to track registered subnets
	netConnections map[string]*networkProxyConn // map[flow_key]connection
	netConnMutex   sync.RWMutex

	// telemetry (multi-tunnel)
	currentTunnelID string
	tunnels         map[string]*tunnelEntry
	asyncBytes      bool
	flushStop       chan struct{}
}

// networkProxyConn tracks an active network-level proxy connection
type networkProxyConn struct {
	srcAddr    string
	dstAddr    string
	protocol   uint8
	conn       net.Conn
	tunnelID   string
	lastActive time.Time
	cancel     context.CancelFunc
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
	if ne, ok := err.(net.Error); ok {
		if ne.Timeout() {
			return "timeout"
		}
		if ne.Temporary() {
			return "temporary"
		}
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

// NewProxyManager creates a new proxy manager instance
func NewProxyManager(tnet *netstack2.Net) *ProxyManager {
	return &ProxyManager{
		tnet:           tnet,
		tcpTargets:     make(map[string]map[int]string),
		udpTargets:     make(map[string]map[int]string),
		listeners:      make([]*gonet.TCPListener, 0),
		udpConns:       make([]*gonet.UDPConn, 0),
		networkTargets: make(map[string]bool),
		netConnections: make(map[string]*networkProxyConn),
		tunnels:        make(map[string]*tunnelEntry),
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

// init function without tnet
func NewProxyManagerWithoutTNet() *ProxyManager {
	return &ProxyManager{
		tcpTargets:     make(map[string]map[int]string),
		udpTargets:     make(map[string]map[int]string),
		listeners:      make([]*gonet.TCPListener, 0),
		udpConns:       make([]*gonet.UDPConn, 0),
		networkTargets: make(map[string]bool),
		netConnections: make(map[string]*networkProxyConn),
	}
}

// Function to add tnet to existing ProxyManager
func (pm *ProxyManager) SetTNet(tnet *netstack2.Net) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()
	pm.tnet = tnet
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

// AddNetworkTarget adds a subnet range for network-level proxying
// Packets destined for this subnet will be proxied through the host's network stack
func (pm *ProxyManager) AddNetworkTarget(subnet string) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	// Parse and validate subnet
	prefix, err := netip.ParsePrefix(subnet)
	if err != nil {
		return fmt.Errorf("invalid subnet: %w", err)
	}

	// Check if already registered
	if pm.networkTargets[subnet] {
		return fmt.Errorf("subnet %s already registered", subnet)
	}

	pm.networkTargets[subnet] = true

	// If running, register the interceptor immediately
	if pm.running && pm.tnet != nil {
		if err := pm.tnet.RegisterSubnetInterceptor(prefix, pm); err != nil {
			delete(pm.networkTargets, subnet)
			return fmt.Errorf("failed to register interceptor: %w", err)
		}
		logger.Info("Started network proxy for subnet %s", subnet)
	}

	return nil
}

// RemoveNetworkTarget removes a subnet from network-level proxying
func (pm *ProxyManager) RemoveNetworkTarget(subnet string) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if !pm.networkTargets[subnet] {
		return fmt.Errorf("subnet %s not registered", subnet)
	}

	// Parse subnet
	prefix, err := netip.ParsePrefix(subnet)
	if err != nil {
		return fmt.Errorf("invalid subnet: %w", err)
	}

	// Unregister interceptor if running
	if pm.running && pm.tnet != nil {
		pm.tnet.UnregisterSubnetInterceptor(prefix)
	}

	// Close all connections for this subnet
	pm.netConnMutex.Lock()
	for key, conn := range pm.netConnections {
		// Check if connection's destination matches this subnet
		dstAddr, err := netip.ParseAddr(conn.dstAddr)
		if err == nil && prefix.Contains(dstAddr) {
			if conn.cancel != nil {
				conn.cancel()
			}
			if conn.conn != nil {
				conn.conn.Close()
			}
			delete(pm.netConnections, key)
		}
	}
	pm.netConnMutex.Unlock()

	delete(pm.networkTargets, subnet)
	logger.Info("Removed network proxy for subnet %s", subnet)

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

	// Register network-level interceptors
	for subnet := range pm.networkTargets {
		prefix, err := netip.ParsePrefix(subnet)
		if err != nil {
			logger.Error("Invalid subnet %s: %v", subnet, err)
			continue
		}
		if err := pm.tnet.RegisterSubnetInterceptor(prefix, pm); err != nil {
			logger.Error("Failed to register network interceptor for %s: %v", subnet, err)
			continue
		}
		logger.Info("Started network proxy for subnet %s", subnet)
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

	// Unregister network interceptors and close all network connections
	for subnet := range pm.networkTargets {
		prefix, err := netip.ParsePrefix(subnet)
		if err == nil {
			pm.tnet.UnregisterSubnetInterceptor(prefix)
		}
	}

	// Close all active network proxy connections
	pm.netConnMutex.Lock()
	for flowKey, conn := range pm.netConnections {
		if conn.cancel != nil {
			conn.cancel()
		}
		if conn.conn != nil {
			conn.conn.Close()
		}
		delete(pm.netConnections, flowKey)
	}
	pm.netConnMutex.Unlock()

	// // Clear the target maps
	// for k := range pm.tcpTargets {
	// 	delete(pm.tcpTargets, k)
	// }
	// for k := range pm.udpTargets {
	// 	delete(pm.udpTargets, k)
	// }

	// Give active connections a chance to close gracefully
	time.Sleep(100 * time.Millisecond)

	return nil
}

func (pm *ProxyManager) startTarget(proto, listenIP string, port int, targetAddr string) error {
	switch proto {
	case "tcp":
		listener, err := pm.tnet.ListenTCP(&net.TCPAddr{Port: port})
		if err != nil {
			return fmt.Errorf("failed to create TCP listener: %v", err)
		}

		pm.listeners = append(pm.listeners, listener)
		go pm.handleTCPProxy(listener, targetAddr)

	case "udp":
		addr := &net.UDPAddr{Port: port}
		conn, err := pm.tnet.ListenUDP(addr)
		if err != nil {
			return fmt.Errorf("failed to create UDP listener: %v", err)
		}

		pm.udpConns = append(pm.udpConns, conn)
		go pm.handleUDPProxy(conn, targetAddr)

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

// HandlePacket implements netstack2.PacketHandler for network-level proxying
func (pm *ProxyManager) HandlePacket(info netstack2.PacketInfo) bool {
	// Build connection key: src_ip:src_port->dst_ip:dst_port:protocol
	flowKey := fmt.Sprintf("%s:%d->%s:%d:%d",
		info.SrcAddr, info.SrcPort,
		info.DstAddr, info.DstPort,
		info.Protocol)

	pm.netConnMutex.RLock()
	conn, exists := pm.netConnections[flowKey]
	pm.netConnMutex.RUnlock()

	if exists {
		// Forward packet on existing connection
		conn.lastActive = time.Now()
		go pm.forwardNetworkPacket(conn, info)
		return true
	}

	// Only handle TCP and UDP
	if info.Protocol != 6 && info.Protocol != 17 {
		return false // Let other protocols through
	}

	// Create new connection
	go pm.handleNewNetworkConnection(info, flowKey)
	return true
}

// handleNewNetworkConnection establishes a new proxied connection for network-level traffic
func (pm *ProxyManager) handleNewNetworkConnection(info netstack2.PacketInfo, flowKey string) {
	tunnelID := pm.currentTunnelID
	dstAddrPort := fmt.Sprintf("%s:%d", info.DstAddr, info.DstPort)

	ctx, cancel := context.WithCancel(context.Background())

	var conn net.Conn
	var err error
	var protoStr string

	switch info.Protocol {
	case 6: // TCP
		protoStr = "tcp"
		conn, err = net.DialTimeout("tcp", dstAddrPort, 10*time.Second)
	case 17: // UDP
		protoStr = "udp"
		raddr, _ := net.ResolveUDPAddr("udp", dstAddrPort)
		conn, err = net.DialUDP("udp", nil, raddr)
	default:
		cancel()
		return
	}

	if err != nil {
		logger.Error("Network proxy: failed to dial %s: %v", dstAddrPort, err)
		telemetry.IncProxyAccept(context.Background(), tunnelID, protoStr, "failure", classifyProxyError(err))
		cancel()
		return
	}

	proxyConn := &networkProxyConn{
		srcAddr:    fmt.Sprintf("%s:%d", info.SrcAddr, info.SrcPort),
		dstAddr:    fmt.Sprintf("%s:%d", info.DstAddr, info.DstPort),
		protocol:   info.Protocol,
		conn:       conn,
		tunnelID:   tunnelID,
		lastActive: time.Now(),
		cancel:     cancel,
	}

	pm.netConnMutex.Lock()
	pm.netConnections[flowKey] = proxyConn
	pm.netConnMutex.Unlock()

	telemetry.IncProxyAccept(context.Background(), tunnelID, protoStr, "success", "")
	telemetry.IncProxyConnectionEvent(context.Background(), tunnelID, protoStr, telemetry.ProxyConnectionOpened)

	// Track active connections
	if e := pm.getEntry(tunnelID); e != nil {
		if info.Protocol == 6 {
			e.activeTCP.Add(1)
		} else {
			e.activeUDP.Add(1)
		}
	}

	logger.Info("Network proxy: new %s connection %s", protoStr, flowKey)

	// Start goroutine to read responses from target
	go pm.readNetworkResponses(ctx, flowKey, proxyConn, info)

	// Forward the initial packet
	pm.forwardNetworkPacket(proxyConn, info)
}

// forwardNetworkPacket forwards a packet's payload to the target connection
func (pm *ProxyManager) forwardNetworkPacket(conn *networkProxyConn, info netstack2.PacketInfo) {
	// Extract payload from IP packet
	payload := pm.extractPayload(info)

	protoStr := "tcp"
	if info.Protocol == 17 {
		protoStr = "udp"
	}

	logger.Debug("Network proxy: extractPayload returned %d bytes for %s", len(payload), protoStr)

	if len(payload) == 0 {
		logger.Debug("Network proxy: no payload to forward (likely TCP control packet)")
		return
	}

	logger.Info("Network proxy: forwarding %d bytes to %s", len(payload), conn.dstAddr)

	// Write to target connection
	n, err := conn.conn.Write(payload)
	if err != nil {
		logger.Error("Network proxy: failed to forward packet: %v", err)
		pm.closeNetworkConnection(conn, fmt.Sprintf("%s:%d->%s:%d:%d",
			info.SrcAddr, info.SrcPort, info.DstAddr, info.DstPort, info.Protocol))
		return
	}

	logger.Info("Network proxy: successfully wrote %d bytes to target", n)

	// Track bytes (ingress: from tunnel to target)
	if n > 0 && conn.tunnelID != "" {
		protoStr := "tcp"
		if info.Protocol == 17 {
			protoStr = "udp"
		}
		if e := pm.getEntry(conn.tunnelID); e != nil {
			if pm.asyncBytes {
				if info.Protocol == 6 {
					e.bytesInTCP.Add(uint64(n))
				} else {
					e.bytesInUDP.Add(uint64(n))
				}
			} else {
				var attrSet attribute.Set
				if info.Protocol == 6 {
					attrSet = e.attrInTCP
				} else {
					attrSet = e.attrInUDP
				}
				telemetry.AddTunnelBytesSet(context.Background(), int64(n), attrSet)
			}
		}
		logger.Info("Network proxy: forwarded %d bytes %s", n, protoStr)
	}
}

// readNetworkResponses reads responses from the target and injects them back into the tunnel
func (pm *ProxyManager) readNetworkResponses(ctx context.Context, flowKey string, conn *networkProxyConn, originalInfo netstack2.PacketInfo) {
	defer pm.closeNetworkConnection(conn, flowKey)

	buf := make([]byte, 65536)
	protoStr := "tcp"
	if originalInfo.Protocol == 17 {
		protoStr = "udp"
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Set read deadline for cleanup of idle connections
		conn.conn.SetReadDeadline(time.Now().Add(5 * time.Minute))

		logger.Info("Network proxy: waiting for response %s", protoStr)
		n, err := conn.conn.Read(buf)
		logger.Info("Network proxy: read returned n=%d err=%v", n, err)
		if err != nil {
			if err != io.EOF && !errors.Is(err, net.ErrClosed) {
				logger.Error("Network proxy: error reading response: %v", err)
			}
			return
		}

		if n == 0 {
			continue
		}

		conn.lastActive = time.Now()

		// Build response packet with swapped src/dst
		responsePacket := pm.buildResponsePacket(
			originalInfo.DstAddr, originalInfo.SrcAddr,
			originalInfo.DstPort, originalInfo.SrcPort,
			originalInfo.Protocol, originalInfo.IsIPv4,
			buf[:n],
		)

		if responsePacket == nil {
			logger.Error("Network proxy: failed to build response packet")
			continue
		}

		// Inject response back into tunnel
		if err := pm.tnet.InjectPacket(responsePacket); err != nil {
			logger.Error("Network proxy: failed to inject response: %v", err)
			return
		}

		// // Track bytes (egress: from target back to tunnel)
		// if conn.tunnelID != "" {
		// 	if e := pm.getEntry(conn.tunnelID); e != nil {
		// 		if pm.asyncBytes {
		// 			if originalInfo.Protocol == 6 {
		// 				e.bytesOutTCP.Add(uint64(n))
		// 			} else {
		// 				e.bytesOutUDP.Add(uint64(n))
		// 			}
		// 		} else {
		// 			var attrSet attribute.Set
		// 			if originalInfo.Protocol == 6 {
		// 				attrSet = e.attrOutTCP
		// 			} else {
		// 				attrSet = e.attrOutUDP
		// 			}
		// 			telemetry.AddTunnelBytesSet(context.Background(), int64(n), attrSet)
		// 		}
		// 	}
		// }

		logger.Info("Network proxy: injected %d bytes response %s", n, protoStr)
	}
}

// closeNetworkConnection closes a network proxy connection and cleans up
func (pm *ProxyManager) closeNetworkConnection(conn *networkProxyConn, flowKey string) {
	if conn.cancel != nil {
		conn.cancel()
	}
	if conn.conn != nil {
		conn.conn.Close()
	}

	pm.netConnMutex.Lock()
	delete(pm.netConnections, flowKey)
	pm.netConnMutex.Unlock()

	protoStr := "tcp"
	if conn.protocol == 17 {
		protoStr = "udp"
	}

	// Decrement active connections
	if conn.tunnelID != "" {
		if e := pm.getEntry(conn.tunnelID); e != nil {
			if conn.protocol == 6 {
				e.activeTCP.Add(-1)
			} else {
				e.activeUDP.Add(-1)
			}
		}
	}

	telemetry.IncProxyConnectionEvent(context.Background(), conn.tunnelID, protoStr, telemetry.ProxyConnectionClosed)
	logger.Debug("Network proxy: closed connection %s", flowKey)
}

// extractPayload extracts the transport layer payload from an IP packet
func (pm *ProxyManager) extractPayload(info netstack2.PacketInfo) []byte {
	data := info.Data
	if len(data) < 20 {
		return nil
	}

	if info.IsIPv4 {
		// IPv4: get header length and skip to transport layer
		ihl := int(data[0]&0x0f) * 4
		if len(data) < ihl {
			return nil
		}

		switch info.Protocol {
		case 6: // TCP
			if len(data) < ihl+20 {
				return nil // TCP header incomplete
			}
			tcpHeaderLen := int(data[ihl+12]>>4) * 4
			if len(data) < ihl+tcpHeaderLen {
				return nil
			}
			return data[ihl+tcpHeaderLen:]

		case 17: // UDP
			if len(data) < ihl+8 {
				return nil // UDP header incomplete
			}
			return data[ihl+8:]
		}
	} else {
		// IPv6: fixed 40 byte header
		if len(data) < 40 {
			return nil
		}

		switch info.Protocol {
		case 6: // TCP
			if len(data) < 40+20 {
				return nil
			}
			tcpHeaderLen := int(data[40+12]>>4) * 4
			if len(data) < 40+tcpHeaderLen {
				return nil
			}
			return data[40+tcpHeaderLen:]

		case 17: // UDP
			if len(data) < 40+8 {
				return nil
			}
			return data[40+8:]
		}
	}

	return nil
}

// buildResponsePacket constructs a complete IP packet for the response
func (pm *ProxyManager) buildResponsePacket(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, protocol uint8, isIPv4 bool, payload []byte) []byte {
	if isIPv4 {
		return pm.buildIPv4Packet(srcIP, dstIP, srcPort, dstPort, protocol, payload)
	}
	return pm.buildIPv6Packet(srcIP, dstIP, srcPort, dstPort, protocol, payload)
}

// buildIPv4Packet constructs an IPv4 packet
func (pm *ProxyManager) buildIPv4Packet(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, protocol uint8, payload []byte) []byte {
	var transportHeader []byte
	var totalLen int

	switch protocol {
	case 6: // TCP
		// Simplified TCP header (20 bytes minimum)
		transportHeader = make([]byte, 20)
		transportHeader[0] = byte(srcPort >> 8)
		transportHeader[1] = byte(srcPort)
		transportHeader[2] = byte(dstPort >> 8)
		transportHeader[3] = byte(dstPort)
		// Sequence and ack numbers would need proper TCP state tracking
		// For now, using zeros (this is a limitation)
		transportHeader[12] = 0x50 // Data offset: 5 (20 bytes), no flags
		transportHeader[14] = 0xff // Window size
		transportHeader[15] = 0xff
		totalLen = 20 + 20 + len(payload)

	case 17: // UDP
		udpLen := 8 + len(payload)
		transportHeader = make([]byte, 8)
		transportHeader[0] = byte(srcPort >> 8)
		transportHeader[1] = byte(srcPort)
		transportHeader[2] = byte(dstPort >> 8)
		transportHeader[3] = byte(dstPort)
		transportHeader[4] = byte(udpLen >> 8)
		transportHeader[5] = byte(udpLen)
		// Checksum at [6:8] - leave as zero for now (optional in IPv4)
		totalLen = 20 + udpLen

	default:
		return nil
	}

	// Build IPv4 header (20 bytes)
	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45                // Version 4, IHL 5
	ipHeader[1] = 0                   // DSCP/ECN
	ipHeader[2] = byte(totalLen >> 8) // Total length
	ipHeader[3] = byte(totalLen)
	ipHeader[4] = 0 // ID
	ipHeader[5] = 0
	ipHeader[6] = 0x40     // Flags: Don't Fragment
	ipHeader[7] = 0        // Fragment offset
	ipHeader[8] = 64       // TTL
	ipHeader[9] = protocol // Protocol
	// Checksum at [10:12] - calculate below
	srcBytes := srcIP.As4()
	dstBytes := dstIP.As4()
	copy(ipHeader[12:16], srcBytes[:]) // Source IP
	copy(ipHeader[16:20], dstBytes[:]) // Dest IP

	// Calculate IPv4 header checksum
	checksum := uint32(0)
	for i := 0; i < 20; i += 2 {
		checksum += uint32(ipHeader[i])<<8 | uint32(ipHeader[i+1])
	}
	for checksum > 0xffff {
		checksum = (checksum & 0xffff) + (checksum >> 16)
	}
	ipHeader[10] = byte(^checksum >> 8)
	ipHeader[11] = byte(^checksum)

	// Assemble packet
	packet := make([]byte, 0, totalLen)
	packet = append(packet, ipHeader...)
	packet = append(packet, transportHeader...)
	packet = append(packet, payload...)

	return packet
}

// buildIPv6Packet constructs an IPv6 packet
func (pm *ProxyManager) buildIPv6Packet(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, protocol uint8, payload []byte) []byte {
	var transportHeader []byte
	var payloadLen int

	switch protocol {
	case 6: // TCP
		transportHeader = make([]byte, 20)
		transportHeader[0] = byte(srcPort >> 8)
		transportHeader[1] = byte(srcPort)
		transportHeader[2] = byte(dstPort >> 8)
		transportHeader[3] = byte(dstPort)
		transportHeader[12] = 0x50 // Data offset: 5 (20 bytes)
		transportHeader[14] = 0xff // Window size
		transportHeader[15] = 0xff
		payloadLen = 20 + len(payload)

	case 17: // UDP
		udpLen := 8 + len(payload)
		transportHeader = make([]byte, 8)
		transportHeader[0] = byte(srcPort >> 8)
		transportHeader[1] = byte(srcPort)
		transportHeader[2] = byte(dstPort >> 8)
		transportHeader[3] = byte(dstPort)
		transportHeader[4] = byte(udpLen >> 8)
		transportHeader[5] = byte(udpLen)
		payloadLen = udpLen

	default:
		return nil
	}

	// Build IPv6 header (40 bytes)
	ipHeader := make([]byte, 40)
	ipHeader[0] = 0x60                  // Version 6
	ipHeader[4] = byte(payloadLen >> 8) // Payload length
	ipHeader[5] = byte(payloadLen)
	ipHeader[6] = protocol // Next header
	ipHeader[7] = 64       // Hop limit
	srcBytes := srcIP.As16()
	dstBytes := dstIP.As16()
	copy(ipHeader[8:24], srcBytes[:])  // Source IP
	copy(ipHeader[24:40], dstBytes[:]) // Dest IP

	// Assemble packet
	packet := make([]byte, 0, 40+payloadLen)
	packet = append(packet, ipHeader...)
	packet = append(packet, transportHeader...)
	packet = append(packet, payload...)

	return packet
}

func (pm *ProxyManager) handleTCPProxy(listener net.Listener, targetAddr string) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			telemetry.IncProxyAccept(context.Background(), pm.currentTunnelID, "tcp", "failure", classifyProxyError(err))
			if !pm.running {
				return
			}
			if ne, ok := err.(net.Error); ok && !ne.Temporary() {
				logger.Info("TCP listener closed, stopping proxy handler for %v", listener.Addr())
				return
			}
			logger.Error("Error accepting TCP connection: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}

		tunnelID := pm.currentTunnelID
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

func (pm *ProxyManager) handleUDPProxy(conn *gonet.UDPConn, targetAddr string) {
	buffer := make([]byte, 65507) // Max UDP packet size
	clientConns := make(map[string]*net.UDPConn)
	var clientsMutex sync.RWMutex

	for {
		n, remoteAddr, err := conn.ReadFrom(buffer)
		if err != nil {
			if !pm.running {
				// Clean up all connections when stopping
				clientsMutex.Lock()
				for _, targetConn := range clientConns {
					targetConn.Close()
				}
				clientConns = nil
				clientsMutex.Unlock()
				return
			}

			// Check for connection closed conditions
			if err == io.EOF || strings.Contains(err.Error(), "use of closed network connection") {
				logger.Info("UDP connection closed, stopping proxy handler")

				// Clean up existing client connections
				clientsMutex.Lock()
				for _, targetConn := range clientConns {
					targetConn.Close()
				}
				clientConns = nil
				clientsMutex.Unlock()

				return
			}

			logger.Error("Error reading UDP packet: %v", err)
			continue
		}

		clientKey := remoteAddr.String()
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
				defer func() {
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

				buffer := make([]byte, 65507)
				for {
					n, _, err := targetConn.ReadFromUDP(buffer)
					if err != nil {
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

	logger.Info("Current Network Targets:")
	for subnet := range pm.networkTargets {
		logger.Info("Network %s -> (proxied through host)", subnet)
	}

	pm.netConnMutex.RLock()
	logger.Info("Active Network Connections: %d", len(pm.netConnections))
	pm.netConnMutex.RUnlock()
}

// GetNetworkConnectionStats returns statistics about active network proxy connections
func (pm *ProxyManager) GetNetworkConnectionStats() map[string]interface{} {
	pm.netConnMutex.RLock()
	defer pm.netConnMutex.RUnlock()

	stats := map[string]interface{}{
		"total_connections": len(pm.netConnections),
		"tcp_connections":   0,
		"udp_connections":   0,
		"connections":       []map[string]interface{}{},
	}

	tcpCount := 0
	udpCount := 0
	connDetails := []map[string]interface{}{}

	for flowKey, conn := range pm.netConnections {
		if conn.protocol == 6 {
			tcpCount++
		} else if conn.protocol == 17 {
			udpCount++
		}

		protoStr := "tcp"
		if conn.protocol == 17 {
			protoStr = "udp"
		}

		connDetails = append(connDetails, map[string]interface{}{
			"flow_key":    flowKey,
			"src_addr":    conn.srcAddr,
			"dst_addr":    conn.dstAddr,
			"protocol":    protoStr,
			"tunnel_id":   conn.tunnelID,
			"last_active": conn.lastActive.Format(time.RFC3339),
			"idle_time":   time.Since(conn.lastActive).String(),
		})
	}

	stats["tcp_connections"] = tcpCount
	stats["udp_connections"] = udpCount
	stats["connections"] = connDetails

	return stats
}

// GetNetworkTargets returns a list of all registered network subnets
func (pm *ProxyManager) GetNetworkTargets() []string {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	subnets := make([]string, 0, len(pm.networkTargets))
	for subnet := range pm.networkTargets {
		subnets = append(subnets, subnet)
	}

	return subnets
}
