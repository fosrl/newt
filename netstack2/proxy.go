package netstack2

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/fosrl/newt/logger"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// PortRange represents an allowed range of ports (inclusive) with optional protocol filtering
// Protocol can be "tcp", "udp", or "" (empty string means both protocols)
type PortRange struct {
	Min      uint16
	Max      uint16
	Protocol string // "tcp", "udp", or "" for both
}

// SubnetRule represents a subnet with optional port restrictions and source address
// When RewriteTo is set, DNAT (Destination Network Address Translation) is performed:
//   - Incoming packets: destination IP is rewritten to the resolved RewriteTo address
//   - Outgoing packets: source IP is rewritten back to the original destination
//
// RewriteTo can be either:
//   - An IP address with CIDR notation (e.g., "192.168.1.1/32")
//   - A domain name (e.g., "example.com") which will be resolved at request time
//
// This allows transparent proxying where traffic appears to come from the rewritten address
type SubnetRule struct {
	SourcePrefix netip.Prefix // Source IP prefix (who is sending)
	DestPrefix   netip.Prefix // Destination IP prefix (where it's going)
	DisableIcmp  bool         // If true, ICMP traffic is blocked for this subnet
	RewriteTo    string       // Optional rewrite address for DNAT - can be IP/CIDR or domain name
	PortRanges   []PortRange  // empty slice means all ports allowed
}

// ruleKey is used as a map key for fast O(1) lookups
type ruleKey struct {
	sourcePrefix string
	destPrefix   string
}

// SubnetLookup provides fast IP subnet and port matching with O(1) lookup performance
type SubnetLookup struct {
	mu    sync.RWMutex
	rules map[ruleKey]*SubnetRule // Map for O(1) lookups by prefix combination
}

// NewSubnetLookup creates a new subnet lookup table
func NewSubnetLookup() *SubnetLookup {
	return &SubnetLookup{
		rules: make(map[ruleKey]*SubnetRule),
	}
}

// AddSubnet adds a subnet rule with source and destination prefixes and optional port restrictions
// If portRanges is nil or empty, all ports are allowed for this subnet
// rewriteTo can be either an IP/CIDR (e.g., "192.168.1.1/32") or a domain name (e.g., "example.com")
func (sl *SubnetLookup) AddSubnet(sourcePrefix, destPrefix netip.Prefix, rewriteTo string, portRanges []PortRange, disableIcmp bool) {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	key := ruleKey{
		sourcePrefix: sourcePrefix.String(),
		destPrefix:   destPrefix.String(),
	}

	sl.rules[key] = &SubnetRule{
		SourcePrefix: sourcePrefix,
		DestPrefix:   destPrefix,
		DisableIcmp:  disableIcmp,
		RewriteTo:    rewriteTo,
		PortRanges:   portRanges,
	}
}

// RemoveSubnet removes a subnet rule from the lookup table
func (sl *SubnetLookup) RemoveSubnet(sourcePrefix, destPrefix netip.Prefix) {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	key := ruleKey{
		sourcePrefix: sourcePrefix.String(),
		destPrefix:   destPrefix.String(),
	}

	delete(sl.rules, key)
}

// GetAllRules returns a copy of all subnet rules
func (sl *SubnetLookup) GetAllRules() []SubnetRule {
	sl.mu.RLock()
	defer sl.mu.RUnlock()

	rules := make([]SubnetRule, 0, len(sl.rules))
	for _, rule := range sl.rules {
		rules = append(rules, *rule)
	}
	return rules
}

// Match checks if a source IP, destination IP, port, and protocol match any subnet rule
// Returns the matched rule if ALL of these conditions are met:
//   - The source IP is in the rule's source prefix
//   - The destination IP is in the rule's destination prefix
//   - The port is in an allowed range (or no port restrictions exist)
//   - The protocol matches (or the port range allows both protocols)
//
// proto should be header.TCPProtocolNumber or header.UDPProtocolNumber
// Returns nil if no rule matches
func (sl *SubnetLookup) Match(srcIP, dstIP netip.Addr, port uint16, proto tcpip.TransportProtocolNumber) *SubnetRule {
	sl.mu.RLock()
	defer sl.mu.RUnlock()

	// Iterate through all rules to find matching source and destination prefixes
	// This is O(n) but necessary since we need to check prefix containment, not exact match
	for _, rule := range sl.rules {
		// Check if source and destination IPs match their respective prefixes
		if !rule.SourcePrefix.Contains(srcIP) {
			continue
		}
		if !rule.DestPrefix.Contains(dstIP) {
			continue
		}

		if rule.DisableIcmp && (proto == header.ICMPv4ProtocolNumber || proto == header.ICMPv6ProtocolNumber) {
		    // ICMP is disabled for this subnet
			return nil
		}

		// Both IPs match - now check port restrictions
		// If no port ranges specified, all ports are allowed
		if len(rule.PortRanges) == 0 {
			return rule
		}

		// Check if port and protocol are in any of the allowed ranges
		for _, pr := range rule.PortRanges {
			if port >= pr.Min && port <= pr.Max {
				// Check protocol compatibility
				if pr.Protocol == "" {
					// Empty protocol means allow both TCP and UDP
					return rule
				}
				// Check if the packet protocol matches the port range protocol
				if (pr.Protocol == "tcp" && proto == header.TCPProtocolNumber) ||
					(pr.Protocol == "udp" && proto == header.UDPProtocolNumber) {
					return rule
				}
				// Port matches but protocol doesn't - continue checking other ranges
			}
		}
	}

	return nil
}

// connKey uniquely identifies a connection for NAT tracking
type connKey struct {
	srcIP   string
	srcPort uint16
	dstIP   string
	dstPort uint16
	proto   uint8
}

// destKey identifies a destination for handler lookups (without source port since it may change)
type destKey struct {
	srcIP   string
	dstIP   string
	dstPort uint16
	proto   uint8
}

// natState tracks NAT translation state for reverse translation
type natState struct {
	originalDst netip.Addr // Original destination before DNAT
	rewrittenTo netip.Addr // The address we rewrote to
}

// ProxyHandler handles packet injection and extraction for promiscuous mode
type ProxyHandler struct {
	proxyStack        *stack.Stack
	proxyEp           *channel.Endpoint
	proxyNotifyHandle *channel.NotificationHandle
	tcpHandler        *TCPHandler
	udpHandler        *UDPHandler
	icmpHandler       *ICMPHandler
	subnetLookup      *SubnetLookup
	natTable          map[connKey]*natState
	destRewriteTable  map[destKey]netip.Addr // Maps original dest to rewritten dest for handler lookups
	natMu             sync.RWMutex
	enabled           bool
	icmpReplies       chan []byte          // Channel for ICMP reply packets to be sent back through the tunnel
	notifiable        channel.Notification // Notification handler for triggering reads
}

// ProxyHandlerOptions configures the proxy handler
type ProxyHandlerOptions struct {
	EnableTCP  bool
	EnableUDP  bool
	EnableICMP bool
	MTU        int
}

// NewProxyHandler creates a new proxy handler for promiscuous mode
func NewProxyHandler(options ProxyHandlerOptions) (*ProxyHandler, error) {
	if !options.EnableTCP && !options.EnableUDP && !options.EnableICMP {
		return nil, nil // No proxy needed
	}

	handler := &ProxyHandler{
		enabled:          true,
		subnetLookup:     NewSubnetLookup(),
		natTable:         make(map[connKey]*natState),
		destRewriteTable: make(map[destKey]netip.Addr),
		icmpReplies:      make(chan []byte, 256), // Buffer for ICMP reply packets
		proxyEp:          channel.New(1024, uint32(options.MTU), ""),
		proxyStack: stack.New(stack.Options{
			NetworkProtocols: []stack.NetworkProtocolFactory{
				ipv4.NewProtocol,
				ipv6.NewProtocol,
			},
			TransportProtocols: []stack.TransportProtocolFactory{
				tcp.NewProtocol,
				udp.NewProtocol,
				icmp.NewProtocol4,
				icmp.NewProtocol6,
			},
		}),
	}

	// Initialize TCP handler if enabled
	if options.EnableTCP {
		handler.tcpHandler = NewTCPHandler(handler.proxyStack, handler)
		if err := handler.tcpHandler.InstallTCPHandler(); err != nil {
			return nil, fmt.Errorf("failed to install TCP handler: %v", err)
		}
	}

	// Initialize UDP handler if enabled
	if options.EnableUDP {
		handler.udpHandler = NewUDPHandler(handler.proxyStack, handler)
		if err := handler.udpHandler.InstallUDPHandler(); err != nil {
			return nil, fmt.Errorf("failed to install UDP handler: %v", err)
		}
	}

	// Initialize ICMP handler if enabled
	if options.EnableICMP {
		handler.icmpHandler = NewICMPHandler(handler.proxyStack, handler)
		if err := handler.icmpHandler.InstallICMPHandler(); err != nil {
			return nil, fmt.Errorf("failed to install ICMP handler: %v", err)
		}
		logger.Debug("ProxyHandler: ICMP handler enabled")
	}

	// // Example 1: Add a rule with no port restrictions (all ports allowed)
	// // This accepts all traffic FROM 10.0.0.0/24 TO 10.20.20.0/24
	// sourceSubnet := netip.MustParsePrefix("10.0.0.0/24")
	// destSubnet := netip.MustParsePrefix("10.20.20.0/24")
	// handler.AddSubnetRule(sourceSubnet, destSubnet, nil)

	// // Example 2: Add a rule with specific port ranges
	// // This accepts traffic FROM 10.0.0.5/32 TO 10.20.21.21/32 only on ports 80, 443, and 8000-9000
	// sourceIP := netip.MustParsePrefix("10.0.0.5/32")
	// destIP := netip.MustParsePrefix("10.20.21.21/32")
	// handler.AddSubnetRule(sourceIP, destIP, []PortRange{
	// 	{Min: 80, Max: 80},
	// 	{Min: 443, Max: 443},
	// 	{Min: 8000, Max: 9000},
	// })

	return handler, nil
}

// AddSubnetRule adds a subnet with optional port restrictions to the proxy handler
// sourcePrefix: The IP prefix of the peer sending the data
// destPrefix: The IP prefix of the destination
// rewriteTo: Optional address to rewrite destination to - can be IP/CIDR or domain name
// If portRanges is nil or empty, all ports are allowed for this subnet
func (p *ProxyHandler) AddSubnetRule(sourcePrefix, destPrefix netip.Prefix, rewriteTo string, portRanges []PortRange, disableIcmp bool) {
	if p == nil || !p.enabled {
		return
	}
	p.subnetLookup.AddSubnet(sourcePrefix, destPrefix, rewriteTo, portRanges, disableIcmp)
}

// RemoveSubnetRule removes a subnet from the proxy handler
func (p *ProxyHandler) RemoveSubnetRule(sourcePrefix, destPrefix netip.Prefix) {
	if p == nil || !p.enabled {
		return
	}
	p.subnetLookup.RemoveSubnet(sourcePrefix, destPrefix)
}

// GetAllRules returns all subnet rules from the proxy handler
func (p *ProxyHandler) GetAllRules() []SubnetRule {
	if p == nil || !p.enabled {
		return nil
	}
	return p.subnetLookup.GetAllRules()
}

// LookupDestinationRewrite looks up the rewritten destination for a connection
// This is used by TCP/UDP handlers to find the actual target address
func (p *ProxyHandler) LookupDestinationRewrite(srcIP, dstIP string, dstPort uint16, proto uint8) (netip.Addr, bool) {
	if p == nil || !p.enabled {
		return netip.Addr{}, false
	}

	key := destKey{
		srcIP:   srcIP,
		dstIP:   dstIP,
		dstPort: dstPort,
		proto:   proto,
	}

	p.natMu.RLock()
	defer p.natMu.RUnlock()

	addr, ok := p.destRewriteTable[key]
	return addr, ok
}

// resolveRewriteAddress resolves a rewrite address which can be either:
// - An IP address with CIDR notation (e.g., "192.168.1.1/32") - returns the IP directly
// - A plain IP address (e.g., "192.168.1.1") - returns the IP directly
// - A domain name (e.g., "example.com") - performs DNS lookup
func (p *ProxyHandler) resolveRewriteAddress(rewriteTo string) (netip.Addr, error) {
	logger.Debug("Resolving rewrite address: %s", rewriteTo)

	// First, try to parse as a CIDR prefix (e.g., "192.168.1.1/32")
	if prefix, err := netip.ParsePrefix(rewriteTo); err == nil {
		return prefix.Addr(), nil
	}

	// Try to parse as a plain IP address (e.g., "192.168.1.1")
	if addr, err := netip.ParseAddr(rewriteTo); err == nil {
		return addr, nil
	}

	// Not an IP address, treat as domain name - perform DNS lookup
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", rewriteTo)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("failed to resolve domain %s: %w", rewriteTo, err)
	}

	if len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("no IP addresses found for domain %s", rewriteTo)
	}

	// Use the first resolved IP address
	ip := ips[0]
	if ip4 := ip.To4(); ip4 != nil {
		addr := netip.AddrFrom4([4]byte{ip4[0], ip4[1], ip4[2], ip4[3]})
		logger.Debug("Resolved %s to %s", rewriteTo, addr)
		return addr, nil
	}

	return netip.Addr{}, fmt.Errorf("no IPv4 address found for domain %s", rewriteTo)
}

// Initialize sets up the promiscuous NIC with the netTun's notification system
func (p *ProxyHandler) Initialize(notifiable channel.Notification) error {
	if p == nil || !p.enabled {
		return nil
	}

	// Store notifiable for triggering notifications on ICMP replies
	p.notifiable = notifiable

	// Add notification handler
	p.proxyNotifyHandle = p.proxyEp.AddNotify(notifiable)

	// Create NIC with promiscuous mode
	tcpipErr := p.proxyStack.CreateNICWithOptions(1, p.proxyEp, stack.NICOptions{
		Disabled: false,
		QDisc:    nil,
	})
	if tcpipErr != nil {
		return fmt.Errorf("CreateNIC (proxy): %v", tcpipErr)
	}

	// Enable promiscuous mode - accepts packets for any destination IP
	if tcpipErr := p.proxyStack.SetPromiscuousMode(1, true); tcpipErr != nil {
		return fmt.Errorf("SetPromiscuousMode: %v", tcpipErr)
	}

	// Enable spoofing - allows sending packets from any source IP
	if tcpipErr := p.proxyStack.SetSpoofing(1, true); tcpipErr != nil {
		return fmt.Errorf("SetSpoofing: %v", tcpipErr)
	}

	// Add default route
	p.proxyStack.AddRoute(tcpip.Route{
		Destination: header.IPv4EmptySubnet,
		NIC:         1,
	})

	return nil
}

// HandleIncomingPacket processes incoming packets and determines if they should
// be injected into the proxy stack
func (p *ProxyHandler) HandleIncomingPacket(packet []byte) bool {
	if p == nil || !p.enabled {
		return false
	}

	// Check minimum packet size
	if len(packet) < header.IPv4MinimumSize {
		return false
	}

	// Only handle IPv4 for now
	if packet[0]>>4 != 4 {
		return false
	}

	// Parse IPv4 header
	ipv4Header := header.IPv4(packet)
	srcIP := ipv4Header.SourceAddress()
	dstIP := ipv4Header.DestinationAddress()

	// Convert gvisor tcpip.Address to netip.Addr
	srcBytes := srcIP.As4()
	srcAddr := netip.AddrFrom4(srcBytes)
	dstBytes := dstIP.As4()
	dstAddr := netip.AddrFrom4(dstBytes)

	// Parse transport layer to get destination port
	var dstPort uint16
	protocol := ipv4Header.TransportProtocol()
	headerLen := int(ipv4Header.HeaderLength())

	// Extract port based on protocol
	switch protocol {
	case header.TCPProtocolNumber:
		if len(packet) < headerLen+header.TCPMinimumSize {
			return false
		}
		tcpHeader := header.TCP(packet[headerLen:])
		dstPort = tcpHeader.DestinationPort()
	case header.UDPProtocolNumber:
		if len(packet) < headerLen+header.UDPMinimumSize {
			return false
		}
		udpHeader := header.UDP(packet[headerLen:])
		dstPort = udpHeader.DestinationPort()
	case header.ICMPv4ProtocolNumber:
		// ICMP doesn't have ports, use port 0 (must match rules with no port restrictions)
		dstPort = 0
		logger.Debug("HandleIncomingPacket: ICMP packet from %s to %s", srcAddr, dstAddr)
	default:
		// For other protocols, use port 0 (must match rules with no port restrictions)
		dstPort = 0
		logger.Debug("HandleIncomingPacket: Unknown protocol %d from %s to %s", protocol, srcAddr, dstAddr)
	}

	// Check if the source IP, destination IP, port, and protocol match any subnet rule
	matchedRule := p.subnetLookup.Match(srcAddr, dstAddr, dstPort, protocol)
	if matchedRule != nil {
		logger.Debug("HandleIncomingPacket: Matched rule for %s -> %s (proto=%d, port=%d)",
			srcAddr, dstAddr, protocol, dstPort)
		// Check if we need to perform DNAT
		if matchedRule.RewriteTo != "" {
			// Create connection tracking key using original destination
			// This allows us to check if we've already resolved for this connection
			var srcPort uint16
			switch protocol {
			case header.TCPProtocolNumber:
				tcpHeader := header.TCP(packet[headerLen:])
				srcPort = tcpHeader.SourcePort()
			case header.UDPProtocolNumber:
				udpHeader := header.UDP(packet[headerLen:])
				srcPort = udpHeader.SourcePort()
			}

			// Key using original destination to track the connection
			key := connKey{
				srcIP:   srcAddr.String(),
				srcPort: srcPort,
				dstIP:   dstAddr.String(),
				dstPort: dstPort,
				proto:   uint8(protocol),
			}

			// Key for handler lookups (doesn't include srcPort for flexibility)
			dKey := destKey{
				srcIP:   srcAddr.String(),
				dstIP:   dstAddr.String(),
				dstPort: dstPort,
				proto:   uint8(protocol),
			}

			// Check if we already have a NAT entry for this connection
			p.natMu.RLock()
			existingEntry, exists := p.natTable[key]
			p.natMu.RUnlock()

			var newDst netip.Addr
			if exists {
				// Use the previously resolved address for this connection
				newDst = existingEntry.rewrittenTo
				logger.Debug("Using existing NAT entry for connection: %s -> %s", dstAddr, newDst)
			} else {
				// New connection - resolve the rewrite address
				var err error
				newDst, err = p.resolveRewriteAddress(matchedRule.RewriteTo)
				if err != nil {
					// Failed to resolve, skip DNAT but still proxy the packet
					logger.Debug("Failed to resolve rewrite address: %v", err)
					pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
						Payload: buffer.MakeWithData(packet),
					})
					p.proxyEp.InjectInbound(header.IPv4ProtocolNumber, pkb)
					return true
				}

				// Store NAT state for this connection
				p.natMu.Lock()
				p.natTable[key] = &natState{
					originalDst: dstAddr,
					rewrittenTo: newDst,
				}
				// Store destination rewrite for handler lookups
				p.destRewriteTable[dKey] = newDst
				p.natMu.Unlock()
				logger.Debug("New NAT entry for connection: %s -> %s", dstAddr, newDst)
			}

			// Check if target is loopback - if so, don't rewrite packet destination
			// as gVisor will drop martian packets. Instead, the handlers will use
			// destRewriteTable to find the actual target address.
			if !newDst.IsLoopback() {
				// Rewrite the packet only for non-loopback destinations
				packet = p.rewritePacketDestination(packet, newDst)
				if packet == nil {
					return false
				}
			} else {
				logger.Debug("Target is loopback, not rewriting packet - handlers will use rewrite table")
			}
		}

		// Inject into proxy stack
		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(packet),
		})
		p.proxyEp.InjectInbound(header.IPv4ProtocolNumber, pkb)
		logger.Debug("HandleIncomingPacket: Injected packet into proxy stack (proto=%d)", protocol)
		return true
	}

	// logger.Debug("HandleIncomingPacket: No matching rule for %s -> %s (proto=%d, port=%d)",
		// srcAddr, dstAddr, protocol, dstPort)
	return false
}

// rewritePacketDestination rewrites the destination IP in a packet and recalculates checksums
func (p *ProxyHandler) rewritePacketDestination(packet []byte, newDst netip.Addr) []byte {
	if len(packet) < header.IPv4MinimumSize {
		return nil
	}

	// Make a copy to avoid modifying the original
	pkt := make([]byte, len(packet))
	copy(pkt, packet)

	ipv4Header := header.IPv4(pkt)
	headerLen := int(ipv4Header.HeaderLength())

	// Rewrite destination IP
	newDstBytes := newDst.As4()
	newDstAddr := tcpip.AddrFrom4(newDstBytes)
	ipv4Header.SetDestinationAddress(newDstAddr)

	// Recalculate IP checksum
	ipv4Header.SetChecksum(0)
	ipv4Header.SetChecksum(^ipv4Header.CalculateChecksum())

	// Update transport layer checksum if needed
	protocol := ipv4Header.TransportProtocol()
	switch protocol {
	case header.TCPProtocolNumber:
		if len(pkt) >= headerLen+header.TCPMinimumSize {
			tcpHeader := header.TCP(pkt[headerLen:])
			tcpHeader.SetChecksum(0)
			xsum := header.PseudoHeaderChecksum(
				header.TCPProtocolNumber,
				ipv4Header.SourceAddress(),
				ipv4Header.DestinationAddress(),
				uint16(len(pkt)-headerLen),
			)
			xsum = checksum.Checksum(pkt[headerLen:], xsum)
			tcpHeader.SetChecksum(^xsum)
		}
	case header.UDPProtocolNumber:
		if len(pkt) >= headerLen+header.UDPMinimumSize {
			udpHeader := header.UDP(pkt[headerLen:])
			udpHeader.SetChecksum(0)
			xsum := header.PseudoHeaderChecksum(
				header.UDPProtocolNumber,
				ipv4Header.SourceAddress(),
				ipv4Header.DestinationAddress(),
				uint16(len(pkt)-headerLen),
			)
			xsum = checksum.Checksum(pkt[headerLen:], xsum)
			udpHeader.SetChecksum(^xsum)
		}
	}

	return pkt
}

// rewritePacketSource rewrites the source IP in a packet and recalculates checksums (for reverse NAT)
func (p *ProxyHandler) rewritePacketSource(packet []byte, newSrc netip.Addr) []byte {
	if len(packet) < header.IPv4MinimumSize {
		return nil
	}

	// Make a copy to avoid modifying the original
	pkt := make([]byte, len(packet))
	copy(pkt, packet)

	ipv4Header := header.IPv4(pkt)
	headerLen := int(ipv4Header.HeaderLength())

	// Rewrite source IP
	newSrcBytes := newSrc.As4()
	newSrcAddr := tcpip.AddrFrom4(newSrcBytes)
	ipv4Header.SetSourceAddress(newSrcAddr)

	// Recalculate IP checksum
	ipv4Header.SetChecksum(0)
	ipv4Header.SetChecksum(^ipv4Header.CalculateChecksum())

	// Update transport layer checksum if needed
	protocol := ipv4Header.TransportProtocol()
	switch protocol {
	case header.TCPProtocolNumber:
		if len(pkt) >= headerLen+header.TCPMinimumSize {
			tcpHeader := header.TCP(pkt[headerLen:])
			tcpHeader.SetChecksum(0)
			xsum := header.PseudoHeaderChecksum(
				header.TCPProtocolNumber,
				ipv4Header.SourceAddress(),
				ipv4Header.DestinationAddress(),
				uint16(len(pkt)-headerLen),
			)
			xsum = checksum.Checksum(pkt[headerLen:], xsum)
			tcpHeader.SetChecksum(^xsum)
		}
	case header.UDPProtocolNumber:
		if len(pkt) >= headerLen+header.UDPMinimumSize {
			udpHeader := header.UDP(pkt[headerLen:])
			udpHeader.SetChecksum(0)
			xsum := header.PseudoHeaderChecksum(
				header.UDPProtocolNumber,
				ipv4Header.SourceAddress(),
				ipv4Header.DestinationAddress(),
				uint16(len(pkt)-headerLen),
			)
			xsum = checksum.Checksum(pkt[headerLen:], xsum)
			udpHeader.SetChecksum(^xsum)
		}
	}

	return pkt
}

// ReadOutgoingPacket reads packets from the proxy stack that need to be
// sent back through the tunnel
func (p *ProxyHandler) ReadOutgoingPacket() *buffer.View {
	if p == nil || !p.enabled {
		return nil
	}

	// First check for ICMP reply packets (non-blocking)
	select {
	case icmpReply := <-p.icmpReplies:
		logger.Debug("ReadOutgoingPacket: Returning ICMP reply packet (%d bytes)", len(icmpReply))
		return buffer.NewViewWithData(icmpReply)
	default:
		// No ICMP reply available, continue to check proxy endpoint
	}

	pkt := p.proxyEp.Read()
	if pkt != nil {
		view := pkt.ToView()
		pkt.DecRef()

		// Check if we need to perform reverse NAT
		packet := view.AsSlice()
		if len(packet) >= header.IPv4MinimumSize && packet[0]>>4 == 4 {
			ipv4Header := header.IPv4(packet)
			srcIP := ipv4Header.SourceAddress()
			dstIP := ipv4Header.DestinationAddress()
			protocol := ipv4Header.TransportProtocol()
			headerLen := int(ipv4Header.HeaderLength())

			// Extract ports
			var srcPort, dstPort uint16
			switch protocol {
			case header.TCPProtocolNumber:
				if len(packet) >= headerLen+header.TCPMinimumSize {
					tcpHeader := header.TCP(packet[headerLen:])
					srcPort = tcpHeader.SourcePort()
					dstPort = tcpHeader.DestinationPort()
				}
			case header.UDPProtocolNumber:
				if len(packet) >= headerLen+header.UDPMinimumSize {
					udpHeader := header.UDP(packet[headerLen:])
					srcPort = udpHeader.SourcePort()
					dstPort = udpHeader.DestinationPort()
				}
			case header.ICMPv4ProtocolNumber:
				// ICMP packets don't need NAT translation in our implementation
				// since we construct reply packets with the correct addresses
				logger.Debug("ReadOutgoingPacket: ICMP packet from %s to %s", srcIP, dstIP)
				return view
			}

			// Look up NAT state for reverse translation
			// The key uses the original dst (before rewrite), so for replies we need to
			// find the entry where the rewritten address matches the current source
			p.natMu.RLock()
			var natEntry *natState
			for k, entry := range p.natTable {
				// Match: reply's dst should be original src, reply's src should be rewritten dst
				if k.srcIP == dstIP.String() && k.srcPort == dstPort &&
					entry.rewrittenTo.String() == srcIP.String() && k.dstPort == srcPort &&
					k.proto == uint8(protocol) {
					natEntry = entry
					break
				}
			}
			p.natMu.RUnlock()

			if natEntry != nil {
				// Perform reverse NAT - rewrite source to original destination
				packet = p.rewritePacketSource(packet, natEntry.originalDst)
				if packet != nil {
					return buffer.NewViewWithData(packet)
				}
			}
		}

		return view
	}

	return nil
}

// QueueICMPReply queues an ICMP reply packet to be sent back through the tunnel
func (p *ProxyHandler) QueueICMPReply(packet []byte) bool {
	if p == nil || !p.enabled {
		return false
	}

	select {
	case p.icmpReplies <- packet:
		logger.Debug("QueueICMPReply: Queued ICMP reply packet (%d bytes)", len(packet))
		// Trigger notification so WriteNotify picks up the packet
		if p.notifiable != nil {
			p.notifiable.WriteNotify()
		}
		return true
	default:
		logger.Info("QueueICMPReply: ICMP reply channel full, dropping packet")
		return false
	}
}

// Close cleans up the proxy handler resources
func (p *ProxyHandler) Close() error {
	if p == nil || !p.enabled {
		return nil
	}

	// Close ICMP replies channel
	if p.icmpReplies != nil {
		close(p.icmpReplies)
	}

	if p.proxyStack != nil {
		p.proxyStack.RemoveNIC(1)
		p.proxyStack.Close()
	}

	if p.proxyEp != nil {
		if p.proxyNotifyHandle != nil {
			p.proxyEp.RemoveNotify(p.proxyNotifyHandle)
		}
		p.proxyEp.Close()
	}

	return nil
}
