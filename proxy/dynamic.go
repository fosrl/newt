package proxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/fosrl/newt/internal/telemetry"
	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/netstack2"
)

// DynamicProxyHandler implements netstack2.PacketHandler to create proxies dynamically
// based on intercepted packets
type DynamicProxyHandler struct {
	pm       *ProxyManager
	netstack *netstack2.Net

	// Track active connections
	mu       sync.RWMutex
	tcpConns map[string]*dynamicTCPConn
	udpConns map[string]*dynamicUDPConn

	// Connection cleanup
	cleanupInterval time.Duration
	stopCleanup     chan struct{}
}

// dynamicTCPConn tracks a dynamic TCP proxy connection
type dynamicTCPConn struct {
	srcAddr    netip.AddrPort
	dstAddr    netip.AddrPort
	tunnelConn *tcpTunnelConn
	targetConn net.Conn
	lastActive time.Time
	closed     bool
	mu         sync.Mutex
}

// dynamicUDPConn tracks a dynamic UDP proxy connection
type dynamicUDPConn struct {
	srcAddr    netip.AddrPort
	dstAddr    netip.AddrPort
	targetConn *net.UDPConn
	lastActive time.Time
	closed     bool
	mu         sync.Mutex
}

// tcpTunnelConn manages TCP connection state for the tunnel side
type tcpTunnelConn struct {
	handler *DynamicProxyHandler
	srcAddr netip.AddrPort
	dstAddr netip.AddrPort
	connKey string

	// TCP state
	seqNum uint32
	ackNum uint32
	mu     sync.Mutex
}

// NewDynamicProxyHandler creates a new dynamic proxy handler
func NewDynamicProxyHandler(pm *ProxyManager, netstack *netstack2.Net) *DynamicProxyHandler {
	handler := &DynamicProxyHandler{
		pm:              pm,
		netstack:        netstack,
		tcpConns:        make(map[string]*dynamicTCPConn),
		udpConns:        make(map[string]*dynamicUDPConn),
		cleanupInterval: 30 * time.Second,
		stopCleanup:     make(chan struct{}),
	}

	// Start cleanup goroutine
	go handler.cleanupLoop()

	return handler
}

// HandlePacket implements netstack2.PacketHandler
func (h *DynamicProxyHandler) HandlePacket(info netstack2.PacketInfo) bool {
	switch info.Protocol {
	case 6: // TCP
		return h.handleTCP(info)
	case 17: // UDP
		return h.handleUDP(info)
	default:
		return false // Let other protocols pass through
	}
}

// handleTCP processes TCP packets
func (h *DynamicProxyHandler) handleTCP(info netstack2.PacketInfo) bool {
	srcAddr := netip.AddrPortFrom(info.SrcAddr, info.SrcPort)
	dstAddr := netip.AddrPortFrom(info.DstAddr, info.DstPort)
	connKey := fmt.Sprintf("tcp:%s->%s", srcAddr, dstAddr)

	h.mu.RLock()
	conn, exists := h.tcpConns[connKey]
	h.mu.RUnlock()

	if !exists {
		// Parse TCP flags from packet
		var headerLen int
		if info.IsIPv4 {
			headerLen = int(info.Data[0]&0x0f) * 4
		} else {
			headerLen = 40 // IPv6 fixed header
		}

		if len(info.Data) < headerLen+14 {
			return false // Packet too short
		}

		tcpFlags := info.Data[headerLen+13]
		isSYN := (tcpFlags & 0x02) != 0

		// Only create new connection on SYN
		if !isSYN {
			logger.Debug("Ignoring non-SYN packet for non-existent TCP connection: %s", connKey)
			return false
		}

		logger.Info("Creating dynamic TCP proxy: %s -> %s", srcAddr, dstAddr)

		// Create new TCP connection to target
		targetConn, err := net.DialTimeout("tcp", dstAddr.String(), 5*time.Second)
		if err != nil {
			logger.Error("Failed to dial TCP target %s: %v", dstAddr, err)
			// Send RST back to client
			h.sendTCPReset(info)
			return true
		}

		// Extract initial sequence numbers
		seqNum := binary.BigEndian.Uint32(info.Data[headerLen+4:])

		conn = &dynamicTCPConn{
			srcAddr: srcAddr,
			dstAddr: dstAddr,
			tunnelConn: &tcpTunnelConn{
				handler: h,
				srcAddr: srcAddr,
				dstAddr: dstAddr,
				connKey: connKey,
				seqNum:  seqNum,
				ackNum:  0,
			},
			targetConn: targetConn,
			lastActive: time.Now(),
		}

		h.mu.Lock()
		h.tcpConns[connKey] = conn
		h.mu.Unlock()

		// Track metrics
		if h.pm.currentTunnelID != "" {
			telemetry.IncProxyAccept(context.Background(), h.pm.currentTunnelID, "tcp", "success", "")
			telemetry.IncProxyConnectionEvent(context.Background(), h.pm.currentTunnelID, "tcp", telemetry.ProxyConnectionOpened)
			if entry := h.pm.getEntry(h.pm.currentTunnelID); entry != nil {
				entry.activeTCP.Add(1)
			}
		}

		// Start goroutine to read from target and send back to tunnel
		go h.readTCPTarget(conn)
	}

	// Forward packet payload to target
	return h.forwardTCPPacket(conn, info)
}

// forwardTCPPacket extracts TCP payload and forwards to target
func (h *DynamicProxyHandler) forwardTCPPacket(conn *dynamicTCPConn, info netstack2.PacketInfo) bool {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	if conn.closed {
		return true
	}

	payload := h.extractTCPPayload(info)
	if len(payload) == 0 {
		// Check for FIN or RST
		var headerLen int
		if info.IsIPv4 {
			headerLen = int(info.Data[0]&0x0f) * 4
		} else {
			headerLen = 40
		}

		if len(info.Data) >= headerLen+14 {
			tcpFlags := info.Data[headerLen+13]
			isFIN := (tcpFlags & 0x01) != 0
			isRST := (tcpFlags & 0x04) != 0

			if isFIN || isRST {
				// Close connection
				conn.targetConn.Close()
				conn.closed = true
				h.cleanupTCPConn(conn.tunnelConn.connKey)
				return true
			}
		}
		return true // No payload, likely ACK
	}

	// Write to target
	n, err := conn.targetConn.Write(payload)
	if err != nil {
		logger.Error("Failed to write to TCP target: %v", err)
		conn.closed = true
		conn.targetConn.Close()
		h.cleanupTCPConn(conn.tunnelConn.connKey)
		return true
	}

	conn.lastActive = time.Now()

	// Update telemetry
	if h.pm.currentTunnelID != "" && n > 0 {
		entry := h.pm.getEntry(h.pm.currentTunnelID)
		if entry != nil {
			if h.pm.asyncBytes {
				entry.bytesInTCP.Add(uint64(n))
			} else {
				telemetry.AddTunnelBytesSet(context.Background(), int64(n), entry.attrInTCP)
			}
		}
	}

	return true
}

// readTCPTarget reads from target connection and injects packets back to tunnel
func (h *DynamicProxyHandler) readTCPTarget(conn *dynamicTCPConn) {
	defer func() {
		conn.mu.Lock()
		if !conn.closed {
			conn.targetConn.Close()
			conn.closed = true
		}
		conn.mu.Unlock()
		h.cleanupTCPConn(conn.tunnelConn.connKey)
	}()

	buf := make([]byte, 65536)
	for {
		conn.targetConn.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := conn.targetConn.Read(buf)
		if err != nil {
			if err != io.EOF {
				logger.Debug("TCP target read error: %v", err)
			}
			return
		}

		if n > 0 {
			// Build and inject response packet
			responsePacket := h.buildTCPPacket(
				conn.dstAddr,
				conn.srcAddr,
				buf[:n],
				false, // not SYN
				false, // not FIN
			)

			if err := h.netstack.InjectPacket(responsePacket); err != nil {
				logger.Error("Failed to inject TCP response: %v", err)
				return
			}

			conn.lastActive = time.Now()

			// Update telemetry
			if h.pm.currentTunnelID != "" {
				entry := h.pm.getEntry(h.pm.currentTunnelID)
				if entry != nil {
					if h.pm.asyncBytes {
						entry.bytesOutTCP.Add(uint64(n))
					} else {
						telemetry.AddTunnelBytesSet(context.Background(), int64(n), entry.attrOutTCP)
					}
				}
			}
		}
	}
}

// handleUDP processes UDP packets
func (h *DynamicProxyHandler) handleUDP(info netstack2.PacketInfo) bool {
	srcAddr := netip.AddrPortFrom(info.SrcAddr, info.SrcPort)
	dstAddr := netip.AddrPortFrom(info.DstAddr, info.DstPort)
	connKey := fmt.Sprintf("udp:%s->%s", srcAddr, dstAddr)

	h.mu.RLock()
	conn, exists := h.udpConns[connKey]
	h.mu.RUnlock()

	if !exists {
		logger.Info("Creating dynamic UDP proxy: %s -> %s", srcAddr, dstAddr)

		// Create new UDP connection to target
		targetAddr, err := net.ResolveUDPAddr("udp", dstAddr.String())
		if err != nil {
			logger.Error("Failed to resolve UDP target %s: %v", dstAddr, err)
			return true
		}

		targetConn, err := net.DialUDP("udp", nil, targetAddr)
		if err != nil {
			logger.Error("Failed to dial UDP target %s: %v", dstAddr, err)
			return true
		}

		conn = &dynamicUDPConn{
			srcAddr:    srcAddr,
			dstAddr:    dstAddr,
			targetConn: targetConn,
			lastActive: time.Now(),
		}

		h.mu.Lock()
		h.udpConns[connKey] = conn
		h.mu.Unlock()

		// Track metrics
		if h.pm.currentTunnelID != "" {
			telemetry.IncProxyAccept(context.Background(), h.pm.currentTunnelID, "udp", "success", "")
			telemetry.IncProxyConnectionEvent(context.Background(), h.pm.currentTunnelID, "udp", telemetry.ProxyConnectionOpened)
			if entry := h.pm.getEntry(h.pm.currentTunnelID); entry != nil {
				entry.activeUDP.Add(1)
			}
		}

		// Start goroutine to read from target and send back to tunnel
		go h.readUDPTarget(conn, connKey)
	}

	// Extract and forward UDP payload
	return h.forwardUDPPacket(conn, info)
}

// forwardUDPPacket extracts UDP payload and forwards to target
func (h *DynamicProxyHandler) forwardUDPPacket(conn *dynamicUDPConn, info netstack2.PacketInfo) bool {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	if conn.closed {
		return true
	}

	payload := h.extractUDPPayload(info)
	if len(payload) == 0 {
		return true
	}

	// Write to target
	n, err := conn.targetConn.Write(payload)
	if err != nil {
		logger.Error("Failed to write to UDP target: %v", err)
		telemetry.IncProxyDrops(context.Background(), h.pm.currentTunnelID, "udp")
		return true
	}

	conn.lastActive = time.Now()

	// Update telemetry
	if h.pm.currentTunnelID != "" && n > 0 {
		entry := h.pm.getEntry(h.pm.currentTunnelID)
		if entry != nil {
			if h.pm.asyncBytes {
				entry.bytesInUDP.Add(uint64(n))
			} else {
				telemetry.AddTunnelBytesSet(context.Background(), int64(n), entry.attrInUDP)
			}
		}
	}

	return true
}

// readUDPTarget reads from target connection and injects packets back to tunnel
func (h *DynamicProxyHandler) readUDPTarget(conn *dynamicUDPConn, connKey string) {
	defer func() {
		conn.mu.Lock()
		if !conn.closed {
			conn.targetConn.Close()
			conn.closed = true
		}
		conn.mu.Unlock()
		h.cleanupUDPConn(connKey)
	}()

	buf := make([]byte, 65507)
	for {
		conn.targetConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := conn.targetConn.Read(buf)
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Timeout() {
				// Check if connection has been idle
				conn.mu.Lock()
				idle := time.Since(conn.lastActive)
				conn.mu.Unlock()

				if idle > 30*time.Second {
					logger.Debug("UDP connection idle, closing: %s", connKey)
					return
				}
				continue
			}
			logger.Debug("UDP target read error: %v", err)
			return
		}

		if n > 0 {
			// Build and inject response packet
			responsePacket := h.buildUDPPacket(
				conn.dstAddr,
				conn.srcAddr,
				buf[:n],
			)

			if err := h.netstack.InjectPacket(responsePacket); err != nil {
				logger.Error("Failed to inject UDP response: %v", err)
				return
			}

			conn.lastActive = time.Now()

			// Update telemetry
			if h.pm.currentTunnelID != "" {
				entry := h.pm.getEntry(h.pm.currentTunnelID)
				if entry != nil {
					if h.pm.asyncBytes {
						entry.bytesOutUDP.Add(uint64(n))
					} else {
						telemetry.AddTunnelBytesSet(context.Background(), int64(n), entry.attrOutUDP)
					}
				}
			}
		}
	}
}

// extractTCPPayload extracts the TCP payload from an IP packet
func (h *DynamicProxyHandler) extractTCPPayload(info netstack2.PacketInfo) []byte {
	var ipHeaderLen int
	if info.IsIPv4 {
		ipHeaderLen = int(info.Data[0]&0x0f) * 4
	} else {
		ipHeaderLen = 40 // IPv6 fixed header
	}

	if len(info.Data) < ipHeaderLen+20 {
		return nil
	}

	tcpHeaderLen := int(info.Data[ipHeaderLen+12]>>4) * 4
	totalHeaderLen := ipHeaderLen + tcpHeaderLen

	if len(info.Data) <= totalHeaderLen {
		return nil
	}

	return info.Data[totalHeaderLen:]
}

// extractUDPPayload extracts the UDP payload from an IP packet
func (h *DynamicProxyHandler) extractUDPPayload(info netstack2.PacketInfo) []byte {
	var ipHeaderLen int
	if info.IsIPv4 {
		ipHeaderLen = int(info.Data[0]&0x0f) * 4
	} else {
		ipHeaderLen = 40 // IPv6 fixed header
	}

	udpHeaderLen := 8
	totalHeaderLen := ipHeaderLen + udpHeaderLen

	if len(info.Data) <= totalHeaderLen {
		return nil
	}

	return info.Data[totalHeaderLen:]
}

// buildTCPPacket constructs a TCP packet with proper headers
func (h *DynamicProxyHandler) buildTCPPacket(srcAddr, dstAddr netip.AddrPort, payload []byte, isSYN, isFIN bool) []byte {
	isIPv4 := srcAddr.Addr().Is4()

	// Calculate lengths
	ipHeaderLen := 20
	if !isIPv4 {
		ipHeaderLen = 40
	}
	tcpHeaderLen := 20 // No options for simplicity
	totalLen := ipHeaderLen + tcpHeaderLen + len(payload)

	packet := make([]byte, totalLen)

	if isIPv4 {
		// IPv4 header
		packet[0] = 0x45 // Version 4, header length 5
		packet[1] = 0x00 // DSCP/ECN
		binary.BigEndian.PutUint16(packet[2:4], uint16(totalLen))
		binary.BigEndian.PutUint16(packet[4:6], 0)      // ID
		binary.BigEndian.PutUint16(packet[6:8], 0x4000) // Flags: DF
		packet[8] = 64                                  // TTL
		packet[9] = 6                                   // Protocol: TCP
		// Checksum at 10:12 - calculate later
		copy(packet[12:16], srcAddr.Addr().AsSlice())
		copy(packet[16:20], dstAddr.Addr().AsSlice())

		// Calculate IP checksum
		ipChecksum := calculateChecksum(packet[:ipHeaderLen])
		binary.BigEndian.PutUint16(packet[10:12], ipChecksum)
	} else {
		// IPv6 header
		packet[0] = 0x60                                                           // Version 6
		binary.BigEndian.PutUint16(packet[4:6], uint16(tcpHeaderLen+len(payload))) // Payload length
		packet[6] = 6                                                              // Next header: TCP
		packet[7] = 64                                                             // Hop limit
		copy(packet[8:24], srcAddr.Addr().AsSlice())
		copy(packet[24:40], dstAddr.Addr().AsSlice())
	}

	// TCP header
	tcpStart := ipHeaderLen
	binary.BigEndian.PutUint16(packet[tcpStart:tcpStart+2], srcAddr.Port())
	binary.BigEndian.PutUint16(packet[tcpStart+2:tcpStart+4], dstAddr.Port())
	binary.BigEndian.PutUint32(packet[tcpStart+4:tcpStart+8], 0)  // Seq num (simplified)
	binary.BigEndian.PutUint32(packet[tcpStart+8:tcpStart+12], 0) // Ack num (simplified)
	packet[tcpStart+12] = 0x50                                    // Data offset: 5 (20 bytes)

	// Flags
	var flags uint8 = 0x10 // ACK
	if isSYN {
		flags |= 0x02
	}
	if isFIN {
		flags |= 0x01
	}
	packet[tcpStart+13] = flags

	binary.BigEndian.PutUint16(packet[tcpStart+14:tcpStart+16], 65535) // Window size
	// Checksum at tcpStart+16:tcpStart+18 - calculate later
	binary.BigEndian.PutUint16(packet[tcpStart+18:tcpStart+20], 0) // Urgent pointer

	// Copy payload
	copy(packet[tcpStart+tcpHeaderLen:], payload)

	// Calculate TCP checksum
	tcpChecksum := h.calculateTCPChecksum(srcAddr.Addr(), dstAddr.Addr(), packet[tcpStart:])
	binary.BigEndian.PutUint16(packet[tcpStart+16:tcpStart+18], tcpChecksum)

	return packet
}

// buildUDPPacket constructs a UDP packet with proper headers
func (h *DynamicProxyHandler) buildUDPPacket(srcAddr, dstAddr netip.AddrPort, payload []byte) []byte {
	isIPv4 := srcAddr.Addr().Is4()

	// Calculate lengths
	ipHeaderLen := 20
	if !isIPv4 {
		ipHeaderLen = 40
	}
	udpHeaderLen := 8
	totalLen := ipHeaderLen + udpHeaderLen + len(payload)

	packet := make([]byte, totalLen)

	if isIPv4 {
		// IPv4 header
		packet[0] = 0x45 // Version 4, header length 5
		packet[1] = 0x00 // DSCP/ECN
		binary.BigEndian.PutUint16(packet[2:4], uint16(totalLen))
		binary.BigEndian.PutUint16(packet[4:6], 0)      // ID
		binary.BigEndian.PutUint16(packet[6:8], 0x4000) // Flags: DF
		packet[8] = 64                                  // TTL
		packet[9] = 17                                  // Protocol: UDP
		// Checksum at 10:12 - calculate later
		copy(packet[12:16], srcAddr.Addr().AsSlice())
		copy(packet[16:20], dstAddr.Addr().AsSlice())

		// Calculate IP checksum
		ipChecksum := calculateChecksum(packet[:ipHeaderLen])
		binary.BigEndian.PutUint16(packet[10:12], ipChecksum)
	} else {
		// IPv6 header
		packet[0] = 0x60                                                           // Version 6
		binary.BigEndian.PutUint16(packet[4:6], uint16(udpHeaderLen+len(payload))) // Payload length
		packet[6] = 17                                                             // Next header: UDP
		packet[7] = 64                                                             // Hop limit
		copy(packet[8:24], srcAddr.Addr().AsSlice())
		copy(packet[24:40], dstAddr.Addr().AsSlice())
	}

	// UDP header
	udpStart := ipHeaderLen
	binary.BigEndian.PutUint16(packet[udpStart:udpStart+2], srcAddr.Port())
	binary.BigEndian.PutUint16(packet[udpStart+2:udpStart+4], dstAddr.Port())
	binary.BigEndian.PutUint16(packet[udpStart+4:udpStart+6], uint16(udpHeaderLen+len(payload)))
	// Checksum at udpStart+6:udpStart+8 - calculate later

	// Copy payload
	copy(packet[udpStart+udpHeaderLen:], payload)

	// Calculate UDP checksum
	udpChecksum := h.calculateUDPChecksum(srcAddr.Addr(), dstAddr.Addr(), packet[udpStart:])
	binary.BigEndian.PutUint16(packet[udpStart+6:udpStart+8], udpChecksum)

	return packet
}

// sendTCPReset sends a TCP RST packet back to the client
func (h *DynamicProxyHandler) sendTCPReset(info netstack2.PacketInfo) {
	srcAddr := netip.AddrPortFrom(info.DstAddr, info.DstPort)
	dstAddr := netip.AddrPortFrom(info.SrcAddr, info.SrcPort)

	// Build RST packet (no payload)
	packet := h.buildTCPResetPacket(srcAddr, dstAddr)

	if err := h.netstack.InjectPacket(packet); err != nil {
		logger.Error("Failed to inject TCP RST: %v", err)
	}
}

// buildTCPResetPacket constructs a TCP RST packet
func (h *DynamicProxyHandler) buildTCPResetPacket(srcAddr, dstAddr netip.AddrPort) []byte {
	isIPv4 := srcAddr.Addr().Is4()

	ipHeaderLen := 20
	if !isIPv4 {
		ipHeaderLen = 40
	}
	tcpHeaderLen := 20
	totalLen := ipHeaderLen + tcpHeaderLen

	packet := make([]byte, totalLen)

	if isIPv4 {
		// IPv4 header
		packet[0] = 0x45
		packet[1] = 0x00
		binary.BigEndian.PutUint16(packet[2:4], uint16(totalLen))
		binary.BigEndian.PutUint16(packet[4:6], 0)
		binary.BigEndian.PutUint16(packet[6:8], 0x4000)
		packet[8] = 64
		packet[9] = 6
		copy(packet[12:16], srcAddr.Addr().AsSlice())
		copy(packet[16:20], dstAddr.Addr().AsSlice())

		ipChecksum := calculateChecksum(packet[:ipHeaderLen])
		binary.BigEndian.PutUint16(packet[10:12], ipChecksum)
	} else {
		// IPv6 header
		packet[0] = 0x60
		binary.BigEndian.PutUint16(packet[4:6], uint16(tcpHeaderLen))
		packet[6] = 6
		packet[7] = 64
		copy(packet[8:24], srcAddr.Addr().AsSlice())
		copy(packet[24:40], dstAddr.Addr().AsSlice())
	}

	// TCP header with RST flag
	tcpStart := ipHeaderLen
	binary.BigEndian.PutUint16(packet[tcpStart:tcpStart+2], srcAddr.Port())
	binary.BigEndian.PutUint16(packet[tcpStart+2:tcpStart+4], dstAddr.Port())
	binary.BigEndian.PutUint32(packet[tcpStart+4:tcpStart+8], 0)
	binary.BigEndian.PutUint32(packet[tcpStart+8:tcpStart+12], 0)
	packet[tcpStart+12] = 0x50
	packet[tcpStart+13] = 0x14 // RST + ACK flags
	binary.BigEndian.PutUint16(packet[tcpStart+14:tcpStart+16], 0)
	binary.BigEndian.PutUint16(packet[tcpStart+18:tcpStart+20], 0)

	tcpChecksum := h.calculateTCPChecksum(srcAddr.Addr(), dstAddr.Addr(), packet[tcpStart:])
	binary.BigEndian.PutUint16(packet[tcpStart+16:tcpStart+18], tcpChecksum)

	return packet
}

// calculateChecksum calculates the Internet checksum
func calculateChecksum(data []byte) uint16 {
	sum := uint32(0)

	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}

	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}

	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	return ^uint16(sum)
}

// calculateTCPChecksum calculates the TCP checksum including pseudo-header
func (h *DynamicProxyHandler) calculateTCPChecksum(srcIP, dstIP netip.Addr, tcpPacket []byte) uint16 {
	isIPv4 := srcIP.Is4()

	// Build pseudo-header
	var pseudoHeader []byte
	if isIPv4 {
		pseudoHeader = make([]byte, 12+len(tcpPacket))
		copy(pseudoHeader[0:4], srcIP.AsSlice())
		copy(pseudoHeader[4:8], dstIP.AsSlice())
		pseudoHeader[8] = 0
		pseudoHeader[9] = 6 // TCP protocol
		binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(len(tcpPacket)))
		copy(pseudoHeader[12:], tcpPacket)
	} else {
		pseudoHeader = make([]byte, 40+len(tcpPacket))
		copy(pseudoHeader[0:16], srcIP.AsSlice())
		copy(pseudoHeader[16:32], dstIP.AsSlice())
		binary.BigEndian.PutUint32(pseudoHeader[32:36], uint32(len(tcpPacket)))
		pseudoHeader[36] = 0
		pseudoHeader[37] = 0
		pseudoHeader[38] = 0
		pseudoHeader[39] = 6 // TCP protocol
		copy(pseudoHeader[40:], tcpPacket)
	}

	return calculateChecksum(pseudoHeader)
}

// calculateUDPChecksum calculates the UDP checksum including pseudo-header
func (h *DynamicProxyHandler) calculateUDPChecksum(srcIP, dstIP netip.Addr, udpPacket []byte) uint16 {
	isIPv4 := srcIP.Is4()

	// Build pseudo-header
	var pseudoHeader []byte
	if isIPv4 {
		pseudoHeader = make([]byte, 12+len(udpPacket))
		copy(pseudoHeader[0:4], srcIP.AsSlice())
		copy(pseudoHeader[4:8], dstIP.AsSlice())
		pseudoHeader[8] = 0
		pseudoHeader[9] = 17 // UDP protocol
		binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(len(udpPacket)))
		copy(pseudoHeader[12:], udpPacket)
	} else {
		pseudoHeader = make([]byte, 40+len(udpPacket))
		copy(pseudoHeader[0:16], srcIP.AsSlice())
		copy(pseudoHeader[16:32], dstIP.AsSlice())
		binary.BigEndian.PutUint32(pseudoHeader[32:36], uint32(len(udpPacket)))
		pseudoHeader[36] = 0
		pseudoHeader[37] = 0
		pseudoHeader[38] = 0
		pseudoHeader[39] = 17 // UDP protocol
		copy(pseudoHeader[40:], udpPacket)
	}

	checksum := calculateChecksum(pseudoHeader)
	if checksum == 0 {
		return 0xffff // UDP uses 0xffff to represent 0
	}
	return checksum
}

// cleanupLoop periodically removes stale connections
func (h *DynamicProxyHandler) cleanupLoop() {
	ticker := time.NewTicker(h.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			h.cleanupStaleConnections()
		case <-h.stopCleanup:
			return
		}
	}
}

// cleanupStaleConnections removes connections that haven't been active
func (h *DynamicProxyHandler) cleanupStaleConnections() {
	now := time.Now()
	tcpTimeout := 5 * time.Minute
	udpTimeout := 30 * time.Second

	// Cleanup TCP connections
	h.mu.Lock()
	for key, conn := range h.tcpConns {
		conn.mu.Lock()
		if now.Sub(conn.lastActive) > tcpTimeout && !conn.closed {
			logger.Debug("Closing stale TCP connection: %s", key)
			conn.targetConn.Close()
			conn.closed = true
			delete(h.tcpConns, key)

			// Update metrics
			if h.pm.currentTunnelID != "" {
				telemetry.IncProxyConnectionEvent(context.Background(), h.pm.currentTunnelID, "tcp", telemetry.ProxyConnectionClosed)
				if entry := h.pm.getEntry(h.pm.currentTunnelID); entry != nil {
					entry.activeTCP.Add(-1)
				}
			}
		}
		conn.mu.Unlock()
	}
	h.mu.Unlock()

	// Cleanup UDP connections
	h.mu.Lock()
	for key, conn := range h.udpConns {
		conn.mu.Lock()
		if now.Sub(conn.lastActive) > udpTimeout && !conn.closed {
			logger.Debug("Closing stale UDP connection: %s", key)
			conn.targetConn.Close()
			conn.closed = true
			delete(h.udpConns, key)

			// Update metrics
			if h.pm.currentTunnelID != "" {
				telemetry.IncProxyConnectionEvent(context.Background(), h.pm.currentTunnelID, "udp", telemetry.ProxyConnectionClosed)
				if entry := h.pm.getEntry(h.pm.currentTunnelID); entry != nil {
					entry.activeUDP.Add(-1)
				}
			}
		}
		conn.mu.Unlock()
	}
	h.mu.Unlock()
}

// cleanupTCPConn removes a TCP connection from tracking
func (h *DynamicProxyHandler) cleanupTCPConn(key string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if conn, ok := h.tcpConns[key]; ok {
		delete(h.tcpConns, key)

		// Update metrics
		if h.pm.currentTunnelID != "" {
			telemetry.IncProxyConnectionEvent(context.Background(), h.pm.currentTunnelID, "tcp", telemetry.ProxyConnectionClosed)
			if entry := h.pm.getEntry(h.pm.currentTunnelID); entry != nil {
				entry.activeTCP.Add(-1)
			}
		}

		conn.mu.Lock()
		if !conn.closed {
			conn.targetConn.Close()
			conn.closed = true
		}
		conn.mu.Unlock()
	}
}

// cleanupUDPConn removes a UDP connection from tracking
func (h *DynamicProxyHandler) cleanupUDPConn(key string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if conn, ok := h.udpConns[key]; ok {
		delete(h.udpConns, key)

		// Update metrics
		if h.pm.currentTunnelID != "" {
			telemetry.IncProxyConnectionEvent(context.Background(), h.pm.currentTunnelID, "udp", telemetry.ProxyConnectionClosed)
			if entry := h.pm.getEntry(h.pm.currentTunnelID); entry != nil {
				entry.activeUDP.Add(-1)
			}
		}

		conn.mu.Lock()
		if !conn.closed {
			conn.targetConn.Close()
			conn.closed = true
		}
		conn.mu.Unlock()
	}
}

// Stop stops the dynamic proxy handler
func (h *DynamicProxyHandler) Stop() {
	close(h.stopCleanup)

	// Close all connections
	h.mu.Lock()
	defer h.mu.Unlock()

	for _, conn := range h.tcpConns {
		conn.mu.Lock()
		if !conn.closed {
			conn.targetConn.Close()
			conn.closed = true
		}
		conn.mu.Unlock()
	}

	for _, conn := range h.udpConns {
		conn.mu.Lock()
		if !conn.closed {
			conn.targetConn.Close()
			conn.closed = true
		}
		conn.mu.Unlock()
	}

	h.tcpConns = make(map[string]*dynamicTCPConn)
	h.udpConns = make(map[string]*dynamicUDPConn)
}
