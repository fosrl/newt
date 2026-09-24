package util

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	mathrand "math/rand/v2"

	"github.com/fosrl/newt/logger"
	"golang.zx2c4.com/wireguard/device"
)

// splitDomainHostPort strips a protocol prefix/trailing slash from domain and
// separates it into host and port (port may be ""). If host is already a
// literal IP address (v4 or v6, brackets stripped), literalIP is non-nil and
// resolution can be skipped entirely.
func splitDomainHostPort(domain string) (host, port string, literalIP net.IP) {
	domain = strings.TrimSpace(domain)
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimSuffix(domain, "/")

	host, port, err := net.SplitHostPort(domain)
	if err != nil {
		// No port found, use the domain as is
		host = domain
		port = ""
	}

	// Check if host is already an IP address (IPv4 or IPv6)
	// For IPv6, the host from SplitHostPort will already have brackets stripped
	// but if there was no port, we need to handle bracketed IPv6 addresses
	cleanHost := strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	return host, port, net.ParseIP(cleanHost)
}

// resolveIPs looks up every address (all families) for host, preferring the
// given upstream DNS servers (each queried directly over UDP) when provided.
// If every upstream server is unreachable - e.g. the only configured/system
// DNS server is only reachable over an address family this process's own
// socket path doesn't currently have a route for (IPv6-only mobile networks
// commonly hand out IPv6-only resolvers) - this falls back to the platform's
// own resolver, which routes independently of our socket path and reliably
// works even then. See https://github.com/fosrl/android/issues/42 and
// https://github.com/fosrl/pangolin/issues/3471.
func resolveIPs(host string, publicDNS []string) ([]net.IP, error) {
	if len(publicDNS) == 0 {
		return net.LookupIP(host)
	}

	var lastErr error
	for _, server := range publicDNS {
		// Ensure the upstream DNS address has a port
		dnsAddr := server
		if _, _, err := net.SplitHostPort(dnsAddr); err != nil {
			// No port specified, default to 53
			dnsAddr = net.JoinHostPort(server, "53")
		}

		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{}
				return d.DialContext(ctx, "udp", dnsAddr)
			},
		}
		ips, err := resolver.LookupIP(context.Background(), "ip", host)
		if err == nil {
			return ips, nil
		}
		lastErr = err
	}

	if ips, err := net.LookupIP(host); err == nil {
		logger.Debug("All upstream DNS servers failed to resolve %s (%v), falling back to platform resolver", host, lastErr)
		return ips, nil
	}

	return nil, fmt.Errorf("DNS lookup failed using all upstream servers: %v", lastErr)
}

// pickAddr chooses a single address from ips, preferring IPv4 for
// backward-compatible callers that only ever use one address (e.g. a
// WireGuard peer endpoint). Returns "" if ips is empty.
func pickAddr(ips []net.IP) string {
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4.String()
		}
	}
	if len(ips) == 0 {
		return ""
	}
	return ips[0].String()
}

func ResolveDomainUpstream(domain string, publicDNS []string) (string, error) {
	host, port, literalIP := splitDomainHostPort(domain)
	if literalIP != nil {
		if port != "" {
			return net.JoinHostPort(literalIP.String(), port), nil
		}
		return literalIP.String(), nil
	}

	ips, err := resolveIPs(host, publicDNS)
	if err != nil {
		return "", err
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("no IP addresses found for domain %s", host)
	}

	ipAddr := pickAddr(ips)
	if port != "" {
		ipAddr = net.JoinHostPort(ipAddr, port)
	}
	return ipAddr, nil
}

func ResolveDomain(domain string) (string, error) {
	return ResolveDomainUpstream(domain, nil)
}

// ResolveDomainAllUpstream resolves domain to every candidate address (all
// families, deduplicated), each formatted as "ip:port" (or bare ip if domain
// had no port). Unlike ResolveDomainUpstream, which collapses to a single
// IPv4-preferred address, this lets a caller that can try more than one
// candidate (e.g. UDP hole punching) reach the destination over whichever
// address family the local network path actually has a route for, instead of
// always preferring an IPv4 address that may be completely unreachable (e.g.
// on an IPv6-only/NAT64 network). See
// https://github.com/fosrl/olm/issues/108.
func ResolveDomainAllUpstream(domain string, publicDNS []string) ([]string, error) {
	host, port, literalIP := splitDomainHostPort(domain)
	if literalIP != nil {
		if port != "" {
			return []string{net.JoinHostPort(literalIP.String(), port)}, nil
		}
		return []string{literalIP.String()}, nil
	}

	ips, err := resolveIPs(host, publicDNS)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses found for domain %s", host)
	}

	seen := make(map[string]bool, len(ips))
	results := make([]string, 0, len(ips))
	for _, ip := range ips {
		s := ip.String()
		if seen[s] {
			continue
		}
		seen[s] = true
		if port != "" {
			s = net.JoinHostPort(s, port)
		}
		results = append(results, s)
	}
	return results, nil
}

// ResolveDomainAll is ResolveDomainAllUpstream using only the system/platform
// resolver (no explicit upstream DNS servers).
func ResolveDomainAll(domain string) ([]string, error) {
	return ResolveDomainAllUpstream(domain, nil)
}

func ParseLogLevel(level string) logger.LogLevel {
	switch strings.ToUpper(level) {
	case "DEBUG":
		return logger.DEBUG
	case "INFO":
		return logger.INFO
	case "WARN":
		return logger.WARN
	case "ERROR":
		return logger.ERROR
	case "FATAL":
		return logger.FATAL
	default:
		return logger.INFO // default to INFO if invalid level provided
	}
}

// find an available UDP port in the range [minPort, maxPort] and also the next port for the wgtester
func FindAvailableUDPPort(minPort, maxPort uint16) (uint16, error) {
	if maxPort < minPort {
		return 0, fmt.Errorf("invalid port range: min=%d, max=%d", minPort, maxPort)
	}

	// We need to check port+1 as well, so adjust the max port to avoid going out of range
	adjustedMaxPort := maxPort - 1
	if adjustedMaxPort < minPort {
		return 0, fmt.Errorf("insufficient port range to find consecutive ports: min=%d, max=%d", minPort, maxPort)
	}

	// Create a slice of all ports in the range (excluding the last one)
	portRange := make([]uint16, adjustedMaxPort-minPort+1)
	for i := range portRange {
		portRange[i] = minPort + uint16(i)
	}

	// Fisher-Yates shuffle to randomize the port order
	for i := len(portRange) - 1; i > 0; i-- {
		j := mathrand.IntN(i + 1)
		portRange[i], portRange[j] = portRange[j], portRange[i]
	}

	// Try each port in the randomized order
	for _, port := range portRange {
		// Check if port is available
		addr1 := &net.UDPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: int(port),
		}
		conn1, err1 := net.ListenUDP("udp", addr1)
		if err1 != nil {
			continue // Port is in use or there was an error, try next port
		}

		conn1.Close()
		return port, nil
	}

	return 0, fmt.Errorf("no available consecutive UDP ports found in range %d-%d", minPort, maxPort)
}

func FixKey(key string) string {
	// Remove any whitespace
	key = strings.TrimSpace(key)

	// Decode from base64
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		logger.Fatal("Error decoding base64: %v", err)
	}

	// Convert to hex
	return hex.EncodeToString(decoded)
}

// this is the opposite of FixKey
func UnfixKey(hexKey string) string {
	// Decode from hex
	decoded, err := hex.DecodeString(hexKey)
	if err != nil {
		logger.Fatal("Error decoding hex: %v", err)
	}

	// Convert to base64
	return base64.StdEncoding.EncodeToString(decoded)
}

func MapToWireGuardLogLevel(level logger.LogLevel) int {
	switch level {
	case logger.DEBUG:
		return device.LogLevelVerbose
	// case logger.INFO:
	// return device.LogLevel
	case logger.WARN:
		return device.LogLevelError
	case logger.ERROR, logger.FATAL:
		return device.LogLevelSilent
	default:
		return device.LogLevelSilent
	}
}

// GetProtocol returns protocol number from IPv4 packet (fast path)
func GetProtocol(packet []byte) (uint8, bool) {
	if len(packet) < 20 {
		return 0, false
	}
	version := packet[0] >> 4
	if version == 4 {
		return packet[9], true
	} else if version == 6 {
		if len(packet) < 40 {
			return 0, false
		}
		return packet[6], true
	}
	return 0, false
}

// GetDestPort returns destination port from TCP/UDP packet (fast path)
func GetDestPort(packet []byte) (uint16, bool) {
	if len(packet) < 20 {
		return 0, false
	}

	version := packet[0] >> 4
	var headerLen int

	if version == 4 {
		ihl := packet[0] & 0x0F
		headerLen = int(ihl) * 4
		if len(packet) < headerLen+4 {
			return 0, false
		}
	} else if version == 6 {
		headerLen = 40
		if len(packet) < headerLen+4 {
			return 0, false
		}
	} else {
		return 0, false
	}

	// Destination port is at bytes 2-3 of TCP/UDP header
	port := binary.BigEndian.Uint16(packet[headerLen+2 : headerLen+4])
	return port, true
}
