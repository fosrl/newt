package util

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	mathrand "math/rand/v2"

	"github.com/fosrl/newt/logger"
	"golang.zx2c4.com/wireguard/device"
)

func ResolveDomain(domain string) (string, error) {
	// Check if there's a port in the domain
	host, port, err := net.SplitHostPort(domain)
	if err != nil {
		// No port found, use the domain as is
		host = domain
		port = ""
	}

	// Remove any protocol prefix if present
	if strings.HasPrefix(host, "http://") {
		host = strings.TrimPrefix(host, "http://")
	} else if strings.HasPrefix(host, "https://") {
		host = strings.TrimPrefix(host, "https://")
	}

	// if there are any trailing slashes, remove them
	host = strings.TrimSuffix(host, "/")

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
