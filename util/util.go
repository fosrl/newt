package util

import (
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

func ResolveDomain(domain string) (string, error) {
	// trim whitespace
	domain = strings.TrimSpace(domain)

	// Remove any protocol prefix if present (do this first, before splitting host/port)
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")

	// if there are any trailing slashes, remove them
	domain = strings.TrimSuffix(domain, "/")

	// Check if there's a port in the domain
	host, port, err := net.SplitHostPort(domain)
	if err != nil {
		// No port found, use the domain as is
		host = domain
		port = ""
	}

	// Lookup IP addresses
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", fmt.Errorf("DNS lookup failed: %v", err)
	}

	if len(ips) == 0 {
		return "", fmt.Errorf("no IP addresses found for domain %s", host)
	}

	// Get the first IPv4 address if available
	var ipAddr string
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			ipAddr = ipv4.String()
			break
		}
	}

	// If no IPv4 found, use the first IP (might be IPv6)
	if ipAddr == "" {
		ipAddr = ips[0].String()
	}

	// Add port back if it existed
	if port != "" {
		ipAddr = net.JoinHostPort(ipAddr, port)
	}

	return ipAddr, nil
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
