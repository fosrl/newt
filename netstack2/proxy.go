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

// PortRange represents an allowed range of ports (inclusive)
type PortRange struct {
	Min uint16
	Max uint16
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
func (sl *SubnetLookup) AddSubnet(sourcePrefix, destPrefix netip.Prefix, rewriteTo string, portRanges []PortRange) {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	key := ruleKey{
		sourcePrefix: sourcePrefix.String(),
		destPrefix:   destPrefix.String(),
	}

	sl.rules[key] = &SubnetRule{
		SourcePrefix: sourcePrefix,
		DestPrefix:   destPrefix,
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

// Match checks if a source IP, destination IP, and port match any subnet rule
// Returns the matched rule if BOTH:
//   - The source IP is in the rule's source prefix
//   - The destination IP is in the rule's destination prefix
//   - The port is in an allowed range (or no port restrictions exist)
//
// Returns nil if no rule matches
func (sl *SubnetLookup) Match(srcIP, dstIP netip.Addr, port uint16) *SubnetRule {
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

		// Both IPs match - now check port restrictions
		// If no port ranges specified, all ports are allowed
		if len(rule.PortRanges) == 0 {
			return rule
		}

		// Check if port is in any of the allowed ranges
		for _, pr := range rule.PortRanges {
			if port >= pr.Min && port <= pr.Max {
				return rule
			}
		}
	}

	return nil
}

// connKey uniquely identifies a connection for NAT tracking (forward direction)
type connKey struct {
	srcIP   string
	srcPort uint16
	dstIP   string
	dstPort uint16
	proto   uint8
}

// reverseConnKey uniquely identifies a connection for reverse NAT lookup (reply direction)
// Key structure: (rewrittenTo, originalSrcIP, originalSrcPort, originalDstPort, proto)
// This allows O(1) lookup of NAT entries for reply packets
type reverseConnKey struct {
	rewrittenTo     string // The address we rewrote to (becomes src in replies)
	originalSrcIP   string // Original source IP (becomes dst in replies)
	originalSrcPort uint16 // Original source port (becomes dst port in replies)
	originalDstPort uint16 // Original destination port (becomes src port in replies)
	proto           uint8
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
	subnetLookup      *SubnetLookup
	natTable          map[connKey]*natState
	reverseNatTable   map[reverseConnKey]*natState // Reverse lookup map for O(1) reply packet NAT
	destRewriteTable  map[destKey]netip.Addr       // Maps original dest to rewritten dest for handler lookups
	natMu             sync.RWMutex
	enabled           bool
}

// ProxyHandlerOptions configures the proxy handler
type ProxyHandlerOptions struct {
	EnableTCP bool
	EnableUDP bool
	MTU       int
}

// NewProxyHandler creates a new proxy handler for promiscuous mode
func NewProxyHandler(options ProxyHandlerOptions) (*ProxyHandler, error) {
	if !options.EnableTCP && !options.EnableUDP {
		return nil, nil // No proxy needed
	}

	handler := &ProxyHandler{
		enabled:          true,
		subnetLookup:     NewSubnetLookup(),
		natTable:         make(map[connKey]*natState),
		reverseNatTable:  make(map[reverseConnKey]*natState),
		destRewriteTable: make(map[destKey]netip.Addr),
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
func (p *ProxyHandler) AddSubnetRule(sourcePrefix, destPrefix netip.Prefix, rewriteTo string, portRanges []PortRange) {
	if p == nil || !p.enabled {
		return
	}
	p.subnetLookup.AddSubnet(sourcePrefix, destPrefix, rewriteTo, portRanges)
}

// RemoveSubnetRule removes a subnet from the proxy handler
func (p *ProxyHandler) RemoveSubnetRule(sourcePrefix, destPrefix netip.Prefix) {
	if p == nil || !p.enabled {
		return
	}
	p.subnetLookup.RemoveSubnet(sourcePrefix, destPrefix)
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
	default:
		// For other protocols (ICMP, etc.), use port 0 (must match rules with no port restrictions)
		dstPort = 0
	}

	// Check if the source IP, destination IP, and port match any subnet rule
	matchedRule := p.subnetLookup.Match(srcAddr, dstAddr, dstPort)
	if matchedRule != nil {
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
				natEntry := &natState{
					originalDst: dstAddr,
					rewrittenTo: newDst,
				}
				p.natTable[key] = natEntry

				// Create reverse lookup key for O(1) reply packet lookups
				// Key: (rewrittenTo, originalSrcIP, originalSrcPort, originalDstPort, proto)
				reverseKey := reverseConnKey{
					rewrittenTo:     newDst.String(),
					originalSrcIP:   srcAddr.String(),
					originalSrcPort: srcPort,
					originalDstPort: dstPort,
					proto:           uint8(protocol),
				}
				p.reverseNatTable[reverseKey] = natEntry

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
		return true
	}

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
			}

			// Look up NAT state for reverse translation using O(1) reverse lookup map
			// Key: (rewrittenTo, originalSrcIP, originalSrcPort, originalDstPort, proto)
			// For reply packets:
			// - reply's srcIP = rewrittenTo (the address we rewrote to)
			// - reply's dstIP = originalSrcIP (original source IP)
			// - reply's srcPort = originalDstPort (original destination port)
			// - reply's dstPort = originalSrcPort (original source port)
			p.natMu.RLock()
			reverseKey := reverseConnKey{
				rewrittenTo:     srcIP.String(), // Reply's source is the rewritten address
				originalSrcIP:   dstIP.String(), // Reply's destination is the original source
				originalSrcPort: dstPort,        // Reply's destination port is the original source port
				originalDstPort: srcPort,        // Reply's source port is the original destination port
				proto:           uint8(protocol),
			}
			natEntry := p.reverseNatTable[reverseKey]
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

// Close cleans up the proxy handler resources
func (p *ProxyHandler) Close() error {
	if p == nil || !p.enabled {
		return nil
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
