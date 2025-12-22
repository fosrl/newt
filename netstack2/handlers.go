/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package netstack2

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os/exec"
	"sync"
	"time"

	"github.com/fosrl/newt/logger"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	// defaultWndSize if set to zero, the default
	// receive window buffer size is used instead.
	defaultWndSize = 0

	// maxConnAttempts specifies the maximum number
	// of in-flight tcp connection attempts.
	maxConnAttempts = 2 << 10

	// tcpKeepaliveCount is the maximum number of
	// TCP keep-alive probes to send before giving up
	// and killing the connection if no response is
	// obtained from the other end.
	tcpKeepaliveCount = 9

	// tcpKeepaliveIdle specifies the time a connection
	// must remain idle before the first TCP keepalive
	// packet is sent. Once this time is reached,
	// tcpKeepaliveInterval option is used instead.
	tcpKeepaliveIdle = 60 * time.Second

	// tcpKeepaliveInterval specifies the interval
	// time between sending TCP keepalive packets.
	tcpKeepaliveInterval = 30 * time.Second

	// tcpConnectTimeout is the default timeout for TCP handshakes.
	tcpConnectTimeout = 5 * time.Second

	// tcpWaitTimeout implements a TCP half-close timeout.
	tcpWaitTimeout = 60 * time.Second

	// udpSessionTimeout is the default timeout for UDP sessions.
	udpSessionTimeout = 60 * time.Second

	// Buffer size for copying data
	bufferSize = 32 * 1024

	// icmpTimeout is the default timeout for ICMP ping requests.
	icmpTimeout = 5 * time.Second
)

// TCPHandler handles TCP connections from netstack
type TCPHandler struct {
	stack        *stack.Stack
	proxyHandler *ProxyHandler
}

// UDPHandler handles UDP connections from netstack
type UDPHandler struct {
	stack        *stack.Stack
	proxyHandler *ProxyHandler
}

// ICMPHandler handles ICMP packets from netstack
type ICMPHandler struct {
	stack        *stack.Stack
	proxyHandler *ProxyHandler
}

// NewTCPHandler creates a new TCP handler
func NewTCPHandler(s *stack.Stack, ph *ProxyHandler) *TCPHandler {
	return &TCPHandler{stack: s, proxyHandler: ph}
}

// NewUDPHandler creates a new UDP handler
func NewUDPHandler(s *stack.Stack, ph *ProxyHandler) *UDPHandler {
	return &UDPHandler{stack: s, proxyHandler: ph}
}

// NewICMPHandler creates a new ICMP handler
func NewICMPHandler(s *stack.Stack, ph *ProxyHandler) *ICMPHandler {
	return &ICMPHandler{stack: s, proxyHandler: ph}
}

// InstallTCPHandler installs the TCP forwarder on the stack
func (h *TCPHandler) InstallTCPHandler() error {
	tcpForwarder := tcp.NewForwarder(h.stack, defaultWndSize, maxConnAttempts, func(r *tcp.ForwarderRequest) {
		var (
			wq  waiter.Queue
			ep  tcpip.Endpoint
			err tcpip.Error
			id  = r.ID()
		)

		// Perform a TCP three-way handshake
		ep, err = r.CreateEndpoint(&wq)
		if err != nil {
			// RST: prevent potential half-open TCP connection leak
			r.Complete(true)
			return
		}
		defer r.Complete(false)

		// Set socket options
		setTCPSocketOptions(h.stack, ep)

		// Create TCP connection from netstack endpoint
		netstackConn := gonet.NewTCPConn(&wq, ep)

		// Handle the connection in a goroutine
		go h.handleTCPConn(netstackConn, id)
	})

	h.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
	return nil
}

// handleTCPConn handles a TCP connection by proxying it to the actual target
func (h *TCPHandler) handleTCPConn(netstackConn *gonet.TCPConn, id stack.TransportEndpointID) {
	defer netstackConn.Close()

	// Extract source and target address from the connection ID
	srcIP := id.RemoteAddress.String()
	srcPort := id.RemotePort
	dstIP := id.LocalAddress.String()
	dstPort := id.LocalPort

	logger.Info("TCP Forwarder: Handling connection %s:%d -> %s:%d", srcIP, srcPort, dstIP, dstPort)

	// Check if there's a destination rewrite for this connection (e.g., localhost targets)
	actualDstIP := dstIP
	if h.proxyHandler != nil {
		if rewrittenAddr, ok := h.proxyHandler.LookupDestinationRewrite(srcIP, dstIP, dstPort, uint8(tcp.ProtocolNumber)); ok {
			actualDstIP = rewrittenAddr.String()
			logger.Info("TCP Forwarder: Using rewritten destination %s (original: %s)", actualDstIP, dstIP)
		}
	}

	targetAddr := fmt.Sprintf("%s:%d", actualDstIP, dstPort)

	// Create context with timeout for connection establishment
	ctx, cancel := context.WithTimeout(context.Background(), tcpConnectTimeout)
	defer cancel()

	// Dial the actual target using standard net package
	var d net.Dialer
	targetConn, err := d.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		logger.Info("TCP Forwarder: Failed to connect to %s: %v", targetAddr, err)
		// Connection failed, netstack will handle RST
		return
	}
	defer targetConn.Close()

	logger.Info("TCP Forwarder: Successfully connected to %s, starting bidirectional copy", targetAddr)

	// Bidirectional copy between netstack and target
	pipeTCP(netstackConn, targetConn)
}

// pipeTCP copies data bidirectionally between two connections
func pipeTCP(origin, remote net.Conn) {
	wg := sync.WaitGroup{}
	wg.Add(2)

	go unidirectionalStreamTCP(remote, origin, "origin->remote", &wg)
	go unidirectionalStreamTCP(origin, remote, "remote->origin", &wg)

	wg.Wait()
}

// unidirectionalStreamTCP copies data in one direction
func unidirectionalStreamTCP(dst, src net.Conn, dir string, wg *sync.WaitGroup) {
	defer wg.Done()

	buf := make([]byte, bufferSize)
	_, _ = io.CopyBuffer(dst, src, buf)

	// Do the upload/download side TCP half-close
	if cr, ok := src.(interface{ CloseRead() error }); ok {
		cr.CloseRead()
	}
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}

	// Set TCP half-close timeout
	dst.SetReadDeadline(time.Now().Add(tcpWaitTimeout))
}

// setTCPSocketOptions sets TCP socket options for better performance
func setTCPSocketOptions(s *stack.Stack, ep tcpip.Endpoint) {
	// TCP keepalive options
	ep.SocketOptions().SetKeepAlive(true)

	idle := tcpip.KeepaliveIdleOption(tcpKeepaliveIdle)
	ep.SetSockOpt(&idle)

	interval := tcpip.KeepaliveIntervalOption(tcpKeepaliveInterval)
	ep.SetSockOpt(&interval)

	ep.SetSockOptInt(tcpip.KeepaliveCountOption, tcpKeepaliveCount)

	// TCP send/recv buffer size
	var ss tcpip.TCPSendBufferSizeRangeOption
	if err := s.TransportProtocolOption(tcp.ProtocolNumber, &ss); err == nil {
		ep.SocketOptions().SetSendBufferSize(int64(ss.Default), false)
	}

	var rs tcpip.TCPReceiveBufferSizeRangeOption
	if err := s.TransportProtocolOption(tcp.ProtocolNumber, &rs); err == nil {
		ep.SocketOptions().SetReceiveBufferSize(int64(rs.Default), false)
	}
}

// InstallUDPHandler installs the UDP forwarder on the stack
func (h *UDPHandler) InstallUDPHandler() error {
	udpForwarder := udp.NewForwarder(h.stack, func(r *udp.ForwarderRequest) {
		var (
			wq waiter.Queue
			id = r.ID()
		)

		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			return
		}

		// Create UDP connection from netstack endpoint
		netstackConn := gonet.NewUDPConn(&wq, ep)

		// Handle the connection in a goroutine
		go h.handleUDPConn(netstackConn, id)
	})

	h.stack.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)
	return nil
}

// handleUDPConn handles a UDP connection by proxying it to the actual target
func (h *UDPHandler) handleUDPConn(netstackConn *gonet.UDPConn, id stack.TransportEndpointID) {
	defer netstackConn.Close()

	// Extract source and target address from the connection ID
	srcIP := id.RemoteAddress.String()
	srcPort := id.RemotePort
	dstIP := id.LocalAddress.String()
	dstPort := id.LocalPort

	logger.Info("UDP Forwarder: Handling connection %s:%d -> %s:%d", srcIP, srcPort, dstIP, dstPort)

	// Check if there's a destination rewrite for this connection (e.g., localhost targets)
	actualDstIP := dstIP
	if h.proxyHandler != nil {
		if rewrittenAddr, ok := h.proxyHandler.LookupDestinationRewrite(srcIP, dstIP, dstPort, uint8(udp.ProtocolNumber)); ok {
			actualDstIP = rewrittenAddr.String()
			logger.Info("UDP Forwarder: Using rewritten destination %s (original: %s)", actualDstIP, dstIP)
		}
	}

	targetAddr := fmt.Sprintf("%s:%d", actualDstIP, dstPort)

	// Resolve target address
	remoteUDPAddr, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		logger.Info("UDP Forwarder: Failed to resolve %s: %v", targetAddr, err)
		return
	}

	// Resolve client address (for sending responses back)
	clientAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", srcIP, srcPort))
	if err != nil {
		logger.Info("UDP Forwarder: Failed to resolve client %s:%d: %v", srcIP, srcPort, err)
		return
	}

	// Create unconnected UDP socket (so we can use WriteTo)
	targetConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		logger.Info("UDP Forwarder: Failed to create UDP socket: %v", err)
		return
	}
	defer targetConn.Close()

	logger.Info("UDP Forwarder: Successfully created UDP socket for %s, starting bidirectional copy", targetAddr)

	// Bidirectional copy between netstack and target
	pipeUDP(netstackConn, targetConn, remoteUDPAddr, clientAddr, udpSessionTimeout)
}

// pipeUDP copies UDP packets bidirectionally
func pipeUDP(origin, remote net.PacketConn, serverAddr, clientAddr net.Addr, timeout time.Duration) {
	wg := sync.WaitGroup{}
	wg.Add(2)

	// Read from origin (netstack), write to remote (target server)
	go unidirectionalPacketStream(remote, origin, serverAddr, "origin->remote", &wg, timeout)
	// Read from remote (target server), write to origin (netstack) with client address
	go unidirectionalPacketStream(origin, remote, clientAddr, "remote->origin", &wg, timeout)

	wg.Wait()
}

// unidirectionalPacketStream copies packets in one direction
func unidirectionalPacketStream(dst, src net.PacketConn, to net.Addr, dir string, wg *sync.WaitGroup, timeout time.Duration) {
	defer wg.Done()

	logger.Info("UDP %s: Starting packet stream (to=%v)", dir, to)
	err := copyPacketData(dst, src, to, timeout)
	if err != nil {
		logger.Info("UDP %s: Stream ended with error: %v", dir, err)
	} else {
		logger.Info("UDP %s: Stream ended (timeout)", dir)
	}
}

// copyPacketData copies UDP packet data with timeout
func copyPacketData(dst, src net.PacketConn, to net.Addr, timeout time.Duration) error {
	buf := make([]byte, 65535) // Max UDP packet size

	for {
		src.SetReadDeadline(time.Now().Add(timeout))
		n, srcAddr, err := src.ReadFrom(buf)
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return nil // ignore I/O timeout
		} else if err == io.EOF {
			return nil // ignore EOF
		} else if err != nil {
			return err
		}

		logger.Info("UDP copyPacketData: Read %d bytes from %v", n, srcAddr)

		// Determine write destination
		writeAddr := to
		if writeAddr == nil {
			// If no destination specified, use the source address from the packet
			writeAddr = srcAddr
		}

		written, err := dst.WriteTo(buf[:n], writeAddr)
		if err != nil {
			logger.Info("UDP copyPacketData: Write error to %v: %v", writeAddr, err)
			return err
		}
		logger.Info("UDP copyPacketData: Wrote %d bytes to %v", written, writeAddr)

		dst.SetReadDeadline(time.Now().Add(timeout))
	}
}

// InstallICMPHandler installs the ICMP handler on the stack
func (h *ICMPHandler) InstallICMPHandler() error {
	h.stack.SetTransportProtocolHandler(header.ICMPv4ProtocolNumber, h.handleICMPPacket)
	logger.Debug("ICMP Handler: Installed ICMP protocol handler")
	return nil
}

// handleICMPPacket handles incoming ICMP packets
func (h *ICMPHandler) handleICMPPacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	logger.Debug("ICMP Handler: Received ICMP packet from %s to %s", id.RemoteAddress, id.LocalAddress)

	// Get the ICMP header from the packet
	icmpData := pkt.TransportHeader().Slice()
	if len(icmpData) < header.ICMPv4MinimumSize {
		logger.Debug("ICMP Handler: Packet too small for ICMP header: %d bytes", len(icmpData))
		return false
	}

	icmpHdr := header.ICMPv4(icmpData)
	icmpType := icmpHdr.Type()
	icmpCode := icmpHdr.Code()

	logger.Debug("ICMP Handler: Type=%d, Code=%d, Ident=%d, Seq=%d",
		icmpType, icmpCode, icmpHdr.Ident(), icmpHdr.Sequence())

	// Only handle Echo Request (ping)
	if icmpType != header.ICMPv4Echo {
		logger.Debug("ICMP Handler: Ignoring non-echo ICMP type: %d", icmpType)
		return false
	}

	// Extract source and destination addresses
	srcIP := id.RemoteAddress.String()
	dstIP := id.LocalAddress.String()

	logger.Info("ICMP Handler: Echo Request from %s to %s (ident=%d, seq=%d)",
		srcIP, dstIP, icmpHdr.Ident(), icmpHdr.Sequence())

	// Convert to netip.Addr for subnet matching
	srcAddr, err := netip.ParseAddr(srcIP)
	if err != nil {
		logger.Debug("ICMP Handler: Failed to parse source IP %s: %v", srcIP, err)
		return false
	}
	dstAddr, err := netip.ParseAddr(dstIP)
	if err != nil {
		logger.Debug("ICMP Handler: Failed to parse dest IP %s: %v", dstIP, err)
		return false
	}

	// Check subnet rules (use port 0 for ICMP since it doesn't have ports)
	if h.proxyHandler == nil {
		logger.Debug("ICMP Handler: No proxy handler configured")
		return false
	}

	matchedRule := h.proxyHandler.subnetLookup.Match(srcAddr, dstAddr, 0, header.ICMPv4ProtocolNumber)
	if matchedRule == nil {
		logger.Debug("ICMP Handler: No matching subnet rule for %s -> %s", srcIP, dstIP)
		return false
	}

	logger.Info("ICMP Handler: Matched subnet rule for %s -> %s", srcIP, dstIP)

	// Determine actual destination (with possible rewrite)
	actualDstIP := dstIP
	if matchedRule.RewriteTo != "" {
		resolvedAddr, err := h.proxyHandler.resolveRewriteAddress(matchedRule.RewriteTo)
		if err != nil {
			logger.Info("ICMP Handler: Failed to resolve rewrite address %s: %v", matchedRule.RewriteTo, err)
		} else {
			actualDstIP = resolvedAddr.String()
			logger.Info("ICMP Handler: Using rewritten destination %s (original: %s)", actualDstIP, dstIP)
		}
	}

	// Get the full ICMP payload (including the data after the header)
	icmpPayload := pkt.Data().AsRange().ToSlice()

	// Handle the ping in a goroutine to avoid blocking
	go h.proxyPing(srcIP, dstIP, actualDstIP, icmpHdr.Ident(), icmpHdr.Sequence(), icmpPayload)

	return true
}

// proxyPing sends a ping to the actual destination and injects the reply back
func (h *ICMPHandler) proxyPing(srcIP, originalDstIP, actualDstIP string, ident, seq uint16, payload []byte) {
	logger.Debug("ICMP Handler: Proxying ping from %s to %s (actual: %s), ident=%d, seq=%d",
		srcIP, originalDstIP, actualDstIP, ident, seq)

	// Try three methods in order: ip4:icmp -> udp4 -> ping command
	// Track which method succeeded so we can handle identifier matching correctly
	method, success := h.tryICMPMethods(actualDstIP, ident, seq, payload)

	if !success {
		logger.Info("ICMP Handler: All ping methods failed for %s", actualDstIP)
		return
	}

	logger.Info("ICMP Handler: Ping successful to %s using %s, injecting reply (ident=%d, seq=%d)",
		actualDstIP, method, ident, seq)

	// Build the reply packet to inject back into the netstack
	// The reply should appear to come from the original destination (before rewrite)
	h.injectICMPReply(srcIP, originalDstIP, ident, seq, payload)
}

// tryICMPMethods tries all available ICMP methods in order
func (h *ICMPHandler) tryICMPMethods(actualDstIP string, ident, seq uint16, payload []byte) (string, bool) {
	if h.tryRawICMP(actualDstIP, ident, seq, payload, false) {
		return "raw ICMP", true
	}
	if h.tryUnprivilegedICMP(actualDstIP, ident, seq, payload) {
		return "unprivileged ICMP", true
	}
	if h.tryPingCommand(actualDstIP, ident, seq, payload) {
		return "ping command", true
	}
	return "", false
}

// tryRawICMP attempts to ping using raw ICMP sockets (requires CAP_NET_RAW or root)
func (h *ICMPHandler) tryRawICMP(actualDstIP string, ident, seq uint16, payload []byte, ignoreIdent bool) bool {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		logger.Debug("ICMP Handler: Raw ICMP socket not available: %v", err)
		return false
	}
	defer conn.Close()

	logger.Debug("ICMP Handler: Using raw ICMP socket")
	return h.sendAndReceiveICMP(conn, actualDstIP, ident, seq, payload, false, ignoreIdent)
}

// tryUnprivilegedICMP attempts to ping using unprivileged ICMP (requires ping_group_range configured)
func (h *ICMPHandler) tryUnprivilegedICMP(actualDstIP string, ident, seq uint16, payload []byte) bool {
	conn, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		logger.Debug("ICMP Handler: Unprivileged ICMP socket not available: %v", err)
		return false
	}
	defer conn.Close()

	logger.Debug("ICMP Handler: Using unprivileged ICMP socket")
	// Unprivileged ICMP doesn't let us control the identifier, so we ignore it in matching
	return h.sendAndReceiveICMP(conn, actualDstIP, ident, seq, payload, true, true)
}

// sendAndReceiveICMP sends an ICMP echo request and waits for the reply
func (h *ICMPHandler) sendAndReceiveICMP(conn *icmp.PacketConn, actualDstIP string, ident, seq uint16, payload []byte, isUnprivileged bool, ignoreIdent bool) bool {
	// Build the ICMP echo request message
	echoMsg := &icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   int(ident),
			Seq:  int(seq),
			Data: payload,
		},
	}

	msgBytes, err := echoMsg.Marshal(nil)
	if err != nil {
		logger.Debug("ICMP Handler: Failed to marshal ICMP message: %v", err)
		return false
	}

	// Resolve destination address based on socket type
	var writeErr error
	if isUnprivileged {
		// For unprivileged ICMP, use UDP-style addressing
		udpAddr := &net.UDPAddr{IP: net.ParseIP(actualDstIP)}
		logger.Debug("ICMP Handler: Sending ping to %s (unprivileged)", udpAddr.String())
		conn.SetDeadline(time.Now().Add(icmpTimeout))
		_, writeErr = conn.WriteTo(msgBytes, udpAddr)
	} else {
		// For raw ICMP, use IP addressing
		dst, err := net.ResolveIPAddr("ip4", actualDstIP)
		if err != nil {
			logger.Debug("ICMP Handler: Failed to resolve destination %s: %v", actualDstIP, err)
			return false
		}
		logger.Debug("ICMP Handler: Sending ping to %s (raw)", dst.String())
		conn.SetDeadline(time.Now().Add(icmpTimeout))
		_, writeErr = conn.WriteTo(msgBytes, dst)
	}

	if writeErr != nil {
		logger.Debug("ICMP Handler: Failed to send ping to %s: %v", actualDstIP, writeErr)
		return false
	}

	logger.Debug("ICMP Handler: Ping sent to %s, waiting for reply (ident=%d, seq=%d)", actualDstIP, ident, seq)

	// Wait for reply - loop to filter out non-matching packets
	replyBuf := make([]byte, 1500)

	for {
		n, peer, err := conn.ReadFrom(replyBuf)
		if err != nil {
			logger.Debug("ICMP Handler: Failed to receive ping reply from %s: %v", actualDstIP, err)
			return false
		}

		logger.Debug("ICMP Handler: Received %d bytes from %s", n, peer.String())

		// Parse the reply
		replyMsg, err := icmp.ParseMessage(1, replyBuf[:n])
		if err != nil {
			logger.Debug("ICMP Handler: Failed to parse ICMP message: %v", err)
			continue
		}

		// Check if it's an echo reply (type 0), not an echo request (type 8)
		if replyMsg.Type != ipv4.ICMPTypeEchoReply {
			logger.Debug("ICMP Handler: Received non-echo-reply type: %v, continuing to wait", replyMsg.Type)
			continue
		}

		reply, ok := replyMsg.Body.(*icmp.Echo)
		if !ok {
			logger.Debug("ICMP Handler: Invalid echo reply body type, continuing to wait")
			continue
		}

		// Verify the sequence matches what we sent
		// For unprivileged ICMP, the kernel controls the identifier, so we only check sequence
		if reply.Seq != int(seq) {
			logger.Debug("ICMP Handler: Reply seq mismatch: got seq=%d, want seq=%d", reply.Seq, seq)
			continue
		}

		if !ignoreIdent && reply.ID != int(ident) {
			logger.Debug("ICMP Handler: Reply ident mismatch: got ident=%d, want ident=%d", reply.ID, ident)
			continue
		}

		// Found matching reply
		logger.Debug("ICMP Handler: Received valid echo reply")
		return true
	}
}

// tryPingCommand attempts to ping using the system ping command (always works, but less control)
func (h *ICMPHandler) tryPingCommand(actualDstIP string, ident, seq uint16, payload []byte) bool {
	logger.Debug("ICMP Handler: Attempting to use system ping command")

	ctx, cancel := context.WithTimeout(context.Background(), icmpTimeout)
	defer cancel()

	// Send one ping with timeout
	// -c 1: count = 1 packet
	// -W 5: timeout = 5 seconds
	// -q: quiet output (just summary)
	cmd := exec.CommandContext(ctx, "ping", "-c", "1", "-W", "5", "-q", actualDstIP)
	output, err := cmd.CombinedOutput()

	if err != nil {
		logger.Debug("ICMP Handler: System ping command failed: %v, output: %s", err, string(output))
		return false
	}

	logger.Debug("ICMP Handler: System ping command succeeded")
	return true
}

// injectICMPReply creates an ICMP echo reply packet and queues it to be sent back through the tunnel
func (h *ICMPHandler) injectICMPReply(dstIP, srcIP string, ident, seq uint16, payload []byte) {
	logger.Debug("ICMP Handler: Creating reply from %s to %s (ident=%d, seq=%d)",
		srcIP, dstIP, ident, seq)

	// Parse addresses
	srcAddr, err := netip.ParseAddr(srcIP)
	if err != nil {
		logger.Info("ICMP Handler: Failed to parse source IP for reply: %v", err)
		return
	}
	dstAddr, err := netip.ParseAddr(dstIP)
	if err != nil {
		logger.Info("ICMP Handler: Failed to parse dest IP for reply: %v", err)
		return
	}

	// Calculate total packet size
	ipHeaderLen := header.IPv4MinimumSize
	icmpHeaderLen := header.ICMPv4MinimumSize
	totalLen := ipHeaderLen + icmpHeaderLen + len(payload)

	// Create the packet buffer
	pkt := make([]byte, totalLen)

	// Build IPv4 header
	ipHdr := header.IPv4(pkt[:ipHeaderLen])
	ipHdr.Encode(&header.IPv4Fields{
		TotalLength: uint16(totalLen),
		TTL:         64,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4(srcAddr.As4()),
		DstAddr:     tcpip.AddrFrom4(dstAddr.As4()),
	})
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())

	// Build ICMP header
	icmpHdr := header.ICMPv4(pkt[ipHeaderLen : ipHeaderLen+icmpHeaderLen])
	icmpHdr.SetType(header.ICMPv4EchoReply)
	icmpHdr.SetCode(0)
	icmpHdr.SetIdent(ident)
	icmpHdr.SetSequence(seq)

	// Copy payload
	copy(pkt[ipHeaderLen+icmpHeaderLen:], payload)

	// Calculate ICMP checksum (covers ICMP header + payload)
	icmpHdr.SetChecksum(0)
	icmpData := pkt[ipHeaderLen:]
	icmpHdr.SetChecksum(^checksum.Checksum(icmpData, 0))

	logger.Debug("ICMP Handler: Built reply packet, total length=%d", totalLen)

	// Queue the packet to be sent back through the tunnel
	if h.proxyHandler != nil {
		if h.proxyHandler.QueueICMPReply(pkt) {
			logger.Info("ICMP Handler: Queued echo reply packet for transmission")
		} else {
			logger.Info("ICMP Handler: Failed to queue echo reply packet")
		}
	} else {
		logger.Info("ICMP Handler: Cannot queue reply - proxy handler not available")
	}
}
