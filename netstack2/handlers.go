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
	"sync"
	"time"

	"github.com/fosrl/newt/logger"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
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
)

// TCPHandler handles TCP connections from netstack
type TCPHandler struct {
	stack *stack.Stack
}

// UDPHandler handles UDP connections from netstack
type UDPHandler struct {
	stack *stack.Stack
}

// NewTCPHandler creates a new TCP handler
func NewTCPHandler(s *stack.Stack) *TCPHandler {
	return &TCPHandler{stack: s}
}

// NewUDPHandler creates a new UDP handler
func NewUDPHandler(s *stack.Stack) *UDPHandler {
	return &UDPHandler{stack: s}
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

	targetAddr := fmt.Sprintf("%s:%d", dstIP, dstPort)

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

	targetAddr := fmt.Sprintf("%s:%d", dstIP, dstPort)

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
