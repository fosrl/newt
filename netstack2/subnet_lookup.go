package netstack2

import (
	"net/netip"
	"sync"

	"github.com/gaissmai/bart"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// SubnetLookup provides fast IP subnet and port matching using BART (Binary Aggregated Range Tree)
// This uses BART Table for O(log n) prefix matching with Supernets() for efficient lookups
//
// Architecture:
// - Two-level BART structure for matching both source AND destination prefixes
// - Level 1: Source prefix -> Level 2 (destination prefix -> rules)
// - This reduces search space: only check destination prefixes for matching source prefixes
type SubnetLookup struct {
	mu sync.RWMutex
	// Two-level BART structure:
	// Level 1: Source prefix -> Level 2 (destination prefix -> rules)
	// This allows us to first match source prefix, then only check destination prefixes
	// for matching source prefixes, reducing the search space significantly
	sourceTrie *bart.Table[*destTrie]
}

// destTrie is a BART for destination prefixes, containing the actual rules
type destTrie struct {
	trie  *bart.Table[[]*SubnetRule]
	rules []*SubnetRule // All rules for this source prefix (for iteration if needed)
}

// NewSubnetLookup creates a new subnet lookup table using BART
func NewSubnetLookup() *SubnetLookup {
	return &SubnetLookup{
		sourceTrie: &bart.Table[*destTrie]{},
	}
}

// prefixEqual compares two prefixes after masking to handle host bits correctly.
// For example, 10.0.0.5/24 and 10.0.0.0/24 are treated as equal.
func prefixEqual(a, b netip.Prefix) bool {
	return a.Masked() == b.Masked()
}

// AddSubnet adds a subnet rule with source and destination prefixes and optional port restrictions
// If portRanges is nil or empty, all ports are allowed for this subnet
// rewriteTo can be either an IP/CIDR (e.g., "192.168.1.1/32") or a domain name (e.g., "example.com")
func (sl *SubnetLookup) AddSubnet(sourcePrefix, destPrefix netip.Prefix, rewriteTo string, portRanges []PortRange, disableIcmp bool) {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	rule := &SubnetRule{
		SourcePrefix: sourcePrefix,
		DestPrefix:   destPrefix,
		DisableIcmp:  disableIcmp,
		RewriteTo:    rewriteTo,
		PortRanges:   portRanges,
	}

	// Canonicalize source prefix to handle host bits correctly
	canonicalSourcePrefix := sourcePrefix.Masked()

	// Get or create destination trie for this source prefix
	destTriePtr, exists := sl.sourceTrie.Get(canonicalSourcePrefix)
	if !exists {
		// Create new destination trie for this source prefix
		destTriePtr = &destTrie{
			trie:  &bart.Table[[]*SubnetRule]{},
			rules: make([]*SubnetRule, 0),
		}
		sl.sourceTrie.Insert(canonicalSourcePrefix, destTriePtr)
	}

	// Canonicalize destination prefix to handle host bits correctly
	// BART masks prefixes internally, so we need to match that behavior in our bookkeeping
	canonicalDestPrefix := destPrefix.Masked()

	// Add rule to destination trie
	// Original behavior: overwrite if same (sourcePrefix, destPrefix) exists
	// Store as single-element slice to match original overwrite behavior
	destTriePtr.trie.Insert(canonicalDestPrefix, []*SubnetRule{rule})

	// Update destTriePtr.rules - remove old rule with same canonical prefix if exists, then add new one
	// Use canonical comparison to handle cases like 10.0.0.5/24 vs 10.0.0.0/24
	newRules := make([]*SubnetRule, 0, len(destTriePtr.rules)+1)
	for _, r := range destTriePtr.rules {
		if !prefixEqual(r.DestPrefix, canonicalDestPrefix) || !prefixEqual(r.SourcePrefix, canonicalSourcePrefix) {
			newRules = append(newRules, r)
		}
	}
	newRules = append(newRules, rule)
	destTriePtr.rules = newRules
}

// RemoveSubnet removes a subnet rule from the lookup table
func (sl *SubnetLookup) RemoveSubnet(sourcePrefix, destPrefix netip.Prefix) {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	// Canonicalize prefixes to handle host bits correctly
	canonicalSourcePrefix := sourcePrefix.Masked()
	canonicalDestPrefix := destPrefix.Masked()

	destTriePtr, exists := sl.sourceTrie.Get(canonicalSourcePrefix)
	if !exists {
		return
	}

	// Remove the rule - original behavior: delete exact (sourcePrefix, destPrefix) combination
	// BART masks prefixes internally, so Delete works with canonical form
	destTriePtr.trie.Delete(canonicalDestPrefix)

	// Also remove from destTriePtr.rules using canonical comparison
	// This ensures we remove rules even if they were added with host bits set
	newDestRules := make([]*SubnetRule, 0, len(destTriePtr.rules))
	for _, r := range destTriePtr.rules {
		if !prefixEqual(r.DestPrefix, canonicalDestPrefix) || !prefixEqual(r.SourcePrefix, canonicalSourcePrefix) {
			newDestRules = append(newDestRules, r)
		}
	}
	destTriePtr.rules = newDestRules

	// Check if the trie is actually empty using BART's Size() method
	// This is more efficient than iterating and ensures we clean up empty tries
	// even if there were stale entries in the rules slice (which shouldn't happen
	// with proper canonicalization, but this provides a definitive check)
	if destTriePtr.trie.Size() == 0 {
		sl.sourceTrie.Delete(canonicalSourcePrefix)
	}
}

// Match checks if a source IP, destination IP, port, and protocol match any subnet rule
// Returns the matched rule if ALL of these conditions are met:
//   - The source IP is in the rule's source prefix
//   - The destination IP is in the rule's destination prefix
//   - The port is in an allowed range (or no port restrictions exist)
//   - The protocol matches (or the port range allows both protocols)
//
// proto should be header.TCPProtocolNumber, header.UDPProtocolNumber, or header.ICMPv4ProtocolNumber
// Returns nil if no rule matches
// This uses BART's Supernets() for O(log n) prefix matching instead of O(n) iteration
func (sl *SubnetLookup) Match(srcIP, dstIP netip.Addr, port uint16, proto tcpip.TransportProtocolNumber) *SubnetRule {
	sl.mu.RLock()
	defer sl.mu.RUnlock()

	// Convert IP addresses to /32 (IPv4) or /128 (IPv6) prefixes
	// Supernets() finds all prefixes that contain this IP (i.e., are supernets of /32 or /128)
	srcPrefix := netip.PrefixFrom(srcIP, srcIP.BitLen())
	dstPrefix := netip.PrefixFrom(dstIP, dstIP.BitLen())

	// Step 1: Find all source prefixes that contain srcIP using BART's Supernets
	// This is O(log n) instead of O(n) iteration
	// Supernets returns all prefixes that are supernets (contain) the given prefix
	for _, destTriePtr := range sl.sourceTrie.Supernets(srcPrefix) {
		if destTriePtr == nil {
			continue
		}

		// Step 2: Find all destination prefixes that contain dstIP
		// This is also O(log n) for each matching source prefix
		for _, rules := range destTriePtr.trie.Supernets(dstPrefix) {
			if rules == nil {
				continue
			}

			// Step 3: Check each rule for ICMP and port restrictions
			for _, rule := range rules {
				// Check if ICMP is disabled for this rule
				if rule.DisableIcmp && (proto == header.ICMPv4ProtocolNumber || proto == header.ICMPv6ProtocolNumber) {
					// ICMP is disabled for this subnet
					return nil
				}

				// Check port restrictions
				if len(rule.PortRanges) == 0 {
					// No port restrictions, match!
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
		}
	}

	return nil
}
