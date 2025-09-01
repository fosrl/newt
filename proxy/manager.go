package proxy

import (
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/fosrl/newt/logger"
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
}

// NewProxyManager creates a new proxy manager instance
func NewProxyManager(tnet *netstack.Net) *ProxyManager {
	return &ProxyManager{
		tnet:       tnet,
		tcpTargets: make(map[string]map[int]string),
		udpTargets: make(map[string]map[int]string),
		listeners:  make([]*gonet.TCPListener, 0),
		udpConns:   make([]*gonet.UDPConn, 0),
	}
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

		go func() {
			target, err := net.Dial("tcp", targetAddr)
			if err != nil {
				logger.Error("Error connecting to target: %v", err)
				conn.Close()
				return
			}

			// Create a WaitGroup to ensure both copy operations complete
			var wg sync.WaitGroup
			wg.Add(2)

			go func() {
				defer wg.Done()
				io.Copy(target, conn)
				target.Close()
			}()

			go func() {
				defer wg.Done()
				io.Copy(conn, target)
				conn.Close()
			}()

			// Wait for both copies to complete
			wg.Wait()
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

		// Use only the client IP as the key, not IP:port
		// This ensures all packets from the same client reuse the same target connection
		clientIP := remoteAddr.(*net.UDPAddr).IP.String()
		clientsMutex.RLock()
		targetConn, exists := clientConns[clientIP]
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
			clientConns[clientIP] = targetConn
			clientsMutex.Unlock()

			go func(clientIP string, targetConn *net.UDPConn, remoteAddr net.Addr) {
				defer func() {
					// Always clean up when this goroutine exits
					clientsMutex.Lock()
					if storedConn, exists := clientConns[clientIP]; exists && storedConn == targetConn {
						delete(clientConns, clientIP)
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

					_, err = conn.WriteTo(buffer[:n], remoteAddr)
					if err != nil {
						logger.Error("Error writing to client: %v", err)
						return // defer will handle cleanup
					}
				}
			}(clientIP, targetConn, remoteAddr)
		}

		_, err = targetConn.Write(buffer[:n])
		if err != nil {
			logger.Error("Error writing to target: %v", err)
			targetConn.Close()
			clientsMutex.Lock()
			delete(clientConns, clientIP)
			clientsMutex.Unlock()
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
