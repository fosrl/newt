package netstack2

import (
	"net/netip"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// clientPrefix is the shared SourcePrefix used across these tests, mirroring
// how the server always assigns a /32 per client (server/lib/ip.ts).
var clientPrefix = netip.MustParsePrefix("10.0.0.5/32")
var clientIP = clientPrefix.Addr()

func TestMatch_SpecificResourceRejectsPort_DoesNotFallThroughToExitNode(t *testing.T) {
	sl := NewSubnetLookup()

	// A specific /24 resource restricted to port 443 only.
	sl.AddSubnet(SubnetRule{
		SourcePrefix: clientPrefix,
		DestPrefix:   netip.MustParsePrefix("192.168.1.0/24"),
		PortRanges:   []PortRange{{Min: 443, Max: 443, Protocol: "tcp"}},
		ResourceId:   100,
	})

	// A 0.0.0.0/0 exit-node rule with no port restriction.
	sl.AddSubnet(SubnetRule{
		SourcePrefix: clientPrefix,
		DestPrefix:   netip.MustParsePrefix("0.0.0.0/0"),
		ResourceId:   999,
	})

	inCIDR := netip.MustParseAddr("192.168.1.50")

	// Disallowed port on the in-CIDR destination must be denied outright,
	// not rescued by the exit node's permissive catch-all.
	if rule := sl.Match(clientIP, inCIDR, 22, header.TCPProtocolNumber); rule != nil {
		t.Fatalf("expected deny for disallowed port via specific resource, got rule with ResourceId=%d", rule.ResourceId)
	}

	// Allowed port on the in-CIDR destination must match the specific resource.
	rule := sl.Match(clientIP, inCIDR, 443, header.TCPProtocolNumber)
	if rule == nil {
		t.Fatal("expected match for allowed port on specific resource, got nil")
	}
	if rule.ResourceId != 100 {
		t.Fatalf("expected ResourceId=100 (specific resource), got %d", rule.ResourceId)
	}

	// A destination outside the /24 has no specific resource covering it,
	// so the exit node must still catch it normally.
	outsideCIDR := netip.MustParseAddr("8.8.8.8")
	rule = sl.Match(clientIP, outsideCIDR, 22, header.TCPProtocolNumber)
	if rule == nil {
		t.Fatal("expected exit-node match for destination outside the specific resource, got nil")
	}
	if rule.ResourceId != 999 {
		t.Fatalf("expected ResourceId=999 (exit node), got %d", rule.ResourceId)
	}
}

func TestMatch_NonCatchAllFallthroughStillWorks(t *testing.T) {
	sl := NewSubnetLookup()

	// A very specific /32 limited to SSH only.
	sl.AddSubnet(SubnetRule{
		SourcePrefix: clientPrefix,
		DestPrefix:   netip.MustParsePrefix("192.168.1.50/32"),
		PortRanges:   []PortRange{{Min: 22, Max: 22, Protocol: "tcp"}},
		ResourceId:   1,
	})

	// A broader /24 (non-catch-all) that allows HTTP.
	sl.AddSubnet(SubnetRule{
		SourcePrefix: clientPrefix,
		DestPrefix:   netip.MustParsePrefix("192.168.1.0/24"),
		PortRanges:   []PortRange{{Min: 80, Max: 80, Protocol: "tcp"}},
		ResourceId:   2,
	})

	ip := netip.MustParseAddr("192.168.1.50")

	// Port 80 doesn't match the /32's SSH-only rule, so it must still fall
	// through to the broader /24 rule that allows it (non-catch-all
	// fallthrough is preserved).
	rule := sl.Match(clientIP, ip, 80, header.TCPProtocolNumber)
	if rule == nil {
		t.Fatal("expected fallthrough match on broader /24 rule, got nil")
	}
	if rule.ResourceId != 2 {
		t.Fatalf("expected ResourceId=2 (broader /24 resource), got %d", rule.ResourceId)
	}

	// Port 22 matches the /32 directly.
	rule = sl.Match(clientIP, ip, 22, header.TCPProtocolNumber)
	if rule == nil {
		t.Fatal("expected match on specific /32 rule, got nil")
	}
	if rule.ResourceId != 1 {
		t.Fatalf("expected ResourceId=1 (specific /32 resource), got %d", rule.ResourceId)
	}
}

func TestMatch_ICMPDisabledOnSpecificResource_HardDeniesRegardlessOfExitNode(t *testing.T) {
	sl := NewSubnetLookup()

	sl.AddSubnet(SubnetRule{
		SourcePrefix: clientPrefix,
		DestPrefix:   netip.MustParsePrefix("192.168.1.0/24"),
		DisableIcmp:  true,
		ResourceId:   100,
	})

	sl.AddSubnet(SubnetRule{
		SourcePrefix: clientPrefix,
		DestPrefix:   netip.MustParsePrefix("0.0.0.0/0"),
		ResourceId:   999,
	})

	ip := netip.MustParseAddr("192.168.1.50")

	if rule := sl.Match(clientIP, ip, 0, header.ICMPv4ProtocolNumber); rule != nil {
		t.Fatalf("expected ICMP deny on specific resource, got rule with ResourceId=%d", rule.ResourceId)
	}
}

func TestMatch_ExitNodeOnlyMatchesWhenNoSpecificResourceCovers(t *testing.T) {
	sl := NewSubnetLookup()

	sl.AddSubnet(SubnetRule{
		SourcePrefix: clientPrefix,
		DestPrefix:   netip.MustParsePrefix("0.0.0.0/0"),
		ResourceId:   999,
	})

	ip := netip.MustParseAddr("1.2.3.4")
	rule := sl.Match(clientIP, ip, 443, header.TCPProtocolNumber)
	if rule == nil {
		t.Fatal("expected exit-node match when no specific resource exists, got nil")
	}
	if rule.ResourceId != 999 {
		t.Fatalf("expected ResourceId=999, got %d", rule.ResourceId)
	}
}
