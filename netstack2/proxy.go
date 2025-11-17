package netstack2

import (
	"fmt"
	"net/netip"
	"sync"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
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

// SubnetRule represents a subnet with optional port restrictions
type SubnetRule struct {
	Prefix     netip.Prefix
	PortRanges []PortRange // empty slice means all ports allowed
}

// SubnetLookup provides fast IP subnet and port matching
type SubnetLookup struct {
	mu    sync.RWMutex
	rules []SubnetRule
}

// NewSubnetLookup creates a new subnet lookup table
func NewSubnetLookup() *SubnetLookup {
	return &SubnetLookup{
		rules: make([]SubnetRule, 0),
	}
}

// AddSubnet adds a subnet to the lookup table with optional port restrictions
// If portRanges is nil or empty, all ports are allowed for this subnet
func (sl *SubnetLookup) AddSubnet(prefix netip.Prefix, portRanges []PortRange) {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	sl.rules = append(sl.rules, SubnetRule{
		Prefix:     prefix,
		PortRanges: portRanges,
	})
}

// RemoveSubnet removes a subnet from the lookup table
func (sl *SubnetLookup) RemoveSubnet(prefix netip.Prefix) {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	for i, rule := range sl.rules {
		if rule.Prefix == prefix {
			sl.rules = append(sl.rules[:i], sl.rules[i+1:]...)
			return
		}
	}
}

// Match checks if an IP and port match any subnet rule
// Returns true if the IP is in a matching subnet AND the port is in an allowed range
func (sl *SubnetLookup) Match(ip netip.Addr, port uint16) bool {
	sl.mu.RLock()
	defer sl.mu.RUnlock()

	for _, rule := range sl.rules {
		if rule.Prefix.Contains(ip) {
			// If no port ranges specified, all ports are allowed
			if len(rule.PortRanges) == 0 {
				return true
			}

			// Check if port is in any of the allowed ranges
			for _, pr := range rule.PortRanges {
				if port >= pr.Min && port <= pr.Max {
					return true
				}
			}
		}
	}

	return false
}

// ProxyHandler handles packet injection and extraction for promiscuous mode
type ProxyHandler struct {
	proxyStack        *stack.Stack
	proxyEp           *channel.Endpoint
	proxyNotifyHandle *channel.NotificationHandle
	tcpHandler        *TCPHandler
	udpHandler        *UDPHandler
	subnetLookup      *SubnetLookup
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
		enabled:      true,
		subnetLookup: NewSubnetLookup(),
		proxyEp:      channel.New(1024, uint32(options.MTU), ""),
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
		handler.tcpHandler = NewTCPHandler(handler.proxyStack)
		if err := handler.tcpHandler.InstallTCPHandler(); err != nil {
			return nil, fmt.Errorf("failed to install TCP handler: %v", err)
		}
	}

	// Initialize UDP handler if enabled
	if options.EnableUDP {
		handler.udpHandler = NewUDPHandler(handler.proxyStack)
		if err := handler.udpHandler.InstallUDPHandler(); err != nil {
			return nil, fmt.Errorf("failed to install UDP handler: %v", err)
		}
	}

	// // Example 1: Add a subnet with no port restrictions (all ports allowed)
	// // This accepts all traffic to 10.20.20.0/24
	// subnet1 := netip.MustParsePrefix("10.20.20.0/24")
	// handler.AddSubnetRule(subnet1, nil)

	// // Example 2: Add a subnet with specific port ranges
	// // This accepts traffic to 192.168.1.0/24 only on ports 80, 443, and 8000-9000
	// subnet2 := netip.MustParsePrefix("10.20.21.21/32")
	// handler.AddSubnetRule(subnet2, []PortRange{
	// 	{Min: 12000, Max: 12001},
	// 	{Min: 8000, Max: 8000},
	// })

	return handler, nil
}

// AddSubnetRule adds a subnet with optional port restrictions to the proxy handler
// If portRanges is nil or empty, all ports are allowed for this subnet
func (p *ProxyHandler) AddSubnetRule(prefix netip.Prefix, portRanges []PortRange) {
	if p == nil || !p.enabled {
		return
	}
	p.subnetLookup.AddSubnet(prefix, portRanges)
}

// RemoveSubnetRule removes a subnet from the proxy handler
func (p *ProxyHandler) RemoveSubnetRule(prefix netip.Prefix) {
	if p == nil || !p.enabled {
		return
	}
	p.subnetLookup.RemoveSubnet(prefix)
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
	dstIP := ipv4Header.DestinationAddress()

	// Convert gvisor tcpip.Address to netip.Addr
	dstBytes := dstIP.As4()
	addr := netip.AddrFrom4(dstBytes)

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

	// Check if the destination IP and port match any subnet rule
	if p.subnetLookup.Match(addr, dstPort) {
		// Inject into proxy stack
		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(packet),
		})
		p.proxyEp.InjectInbound(header.IPv4ProtocolNumber, pkb)
		return true
	}

	return false
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
