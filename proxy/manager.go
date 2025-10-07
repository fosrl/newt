package proxy

import (
	"context"
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
	"golang.zx2c4.com/wireguard/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

// Target represents a proxy target with its address and port
type Target struct {
	Address string
	Port    int
}

// ProxyManager handles the creation and management of proxy connections
type ProxyManager struct {
	tnet       *netstack.Net
	tcpTargets map[string]map[int]string // map[listenIP]map[port]targetAddress
	udpTargets map[string]map[int]string
	listeners  []*gonet.TCPListener
	udpConns   []*gonet.UDPConn
	running    bool
	mutex      sync.RWMutex

	// telemetry (multi-tunnel)
	currentTunnelID string
	tunnels         map[string]*tunnelEntry
	asyncBytes      bool
	flushStop       chan struct{}
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
			if cw.proto == "tcp" {
				if cw.out {
					cw.ent.bytesOutTCP.Add(uint64(n))
				} else {
					cw.ent.bytesInTCP.Add(uint64(n))
				}
			} else if cw.proto == "udp" {
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

// NewProxyManager creates a new proxy manager instance
func NewProxyManager(tnet *netstack.Net) *ProxyManager {
	return &ProxyManager{
		tnet:       tnet,
		tcpTargets: make(map[string]map[int]string),
		udpTargets: make(map[string]map[int]string),
		listeners:  make([]*gonet.TCPListener, 0),
		udpConns:   make([]*gonet.UDPConn, 0),
		tunnels:    make(map[string]*tunnelEntry),
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
	e.attrInTCP = attribute.NewSet(attribute.String("tunnel_id", id), attribute.String("direction", "in"), attribute.String("protocol", "tcp"))
	e.attrOutTCP = attribute.NewSet(attribute.String("tunnel_id", id), attribute.String("direction", "out"), attribute.String("protocol", "tcp"))
	e.attrInUDP = attribute.NewSet(attribute.String("tunnel_id", id), attribute.String("direction", "in"), attribute.String("protocol", "udp"))
	e.attrOutUDP = attribute.NewSet(attribute.String("tunnel_id", id), attribute.String("direction", "out"), attribute.String("protocol", "udp"))
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
		tcpTargets: make(map[string]map[int]string),
		udpTargets: make(map[string]map[int]string),
		listeners:  make([]*gonet.TCPListener, 0),
		udpConns:   make([]*gonet.UDPConn, 0),
	}
}

// Function to add tnet to existing ProxyManager
func (pm *ProxyManager) SetTNet(tnet *netstack.Net) {
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
		return fmt.Errorf("unsupported protocol: %s", proto)
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
		return fmt.Errorf("unsupported protocol: %s", proto)
	}
	return nil
}

// Start begins listening for all configured proxy targets
func (pm *ProxyManager) Start() error {
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
		return fmt.Errorf("unsupported protocol: %s", proto)
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

func (pm *ProxyManager) handleTCPProxy(listener net.Listener, targetAddr string) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			// Check if we're shutting down or the listener was closed
			if !pm.running {
				return
			}

			// Check for specific network errors that indicate the listener is closed
			if ne, ok := err.(net.Error); ok && !ne.Temporary() {
				logger.Info("TCP listener closed, stopping proxy handler for %v", listener.Addr())
				return
			}

			logger.Error("Error accepting TCP connection: %v", err)
			// Don't hammer the CPU if we hit a temporary error
			time.Sleep(100 * time.Millisecond)
			continue
		}

		// Count sessions only once per accepted TCP connection
		if pm.currentTunnelID != "" {
			state.Global().IncSessions(pm.currentTunnelID)
		}

		go func() {
			target, err := net.Dial("tcp", targetAddr)
			if err != nil {
				logger.Error("Error connecting to target: %v", err)
				conn.Close()
				return
			}

			// already incremented on accept

			// Create a WaitGroup to ensure both copy operations complete
			var wg sync.WaitGroup
			wg.Add(2)

			// client -> target (direction=in)
			go func() {
				defer wg.Done()
				e := pm.getEntry(pm.currentTunnelID)
				cw := &countingWriter{ctx: context.Background(), w: target, set: e.attrInTCP, pm: pm, ent: e, out: false, proto: "tcp"}
				_, _ = io.Copy(cw, conn)
				_ = target.Close()
			}()

			// target -> client (direction=out)
			go func() {
				defer wg.Done()
				e := pm.getEntry(pm.currentTunnelID)
				cw := &countingWriter{ctx: context.Background(), w: conn, set: e.attrOutTCP, pm: pm, ent: e, out: true, proto: "tcp"}
				_, _ = io.Copy(cw, target)
				_ = conn.Close()
			}()

			// Wait for both copies to complete then session -1
			wg.Wait()
			if pm.currentTunnelID != "" {
				state.Global().DecSessions(pm.currentTunnelID)
			}
		}()
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
				continue
			}

			targetConn, err = net.DialUDP("udp", nil, targetUDPAddr)
			if err != nil {
				logger.Error("Error connecting to target: %v", err)
				continue
			}

			clientsMutex.Lock()
			clientConns[clientKey] = targetConn
			clientsMutex.Unlock()

			go func(clientKey string, targetConn *net.UDPConn, remoteAddr net.Addr) {
				defer func() {
					// Always clean up when this goroutine exits
					clientsMutex.Lock()
					if storedConn, exists := clientConns[clientKey]; exists && storedConn == targetConn {
						delete(clientConns, clientKey)
						targetConn.Close()
					}
					clientsMutex.Unlock()
				}()

				buffer := make([]byte, 65507)
				for {
					n, _, err := targetConn.ReadFromUDP(buffer)
					if err != nil {
						logger.Error("Error reading from target: %v", err)
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
						return // defer will handle cleanup
					}
				}
			}(clientKey, targetConn, remoteAddr)
		}

		written, err := targetConn.Write(buffer[:n])
		if err != nil {
			logger.Error("Error writing to target: %v", err)
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
}
