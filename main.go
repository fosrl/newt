package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/proxy"
	"github.com/fosrl/newt/websocket"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type WgData struct {
	Endpoint  string        `json:"endpoint"`
	PublicKey string        `json:"publicKey"`
	ServerIP  string        `json:"serverIP"`
	TunnelIP  string        `json:"tunnelIP"`
	Targets   TargetsByType `json:"targets"`
}

type TargetsByType struct {
	UDP []string `json:"udp"`
	TCP []string `json:"tcp"`
}

type TargetData struct {
	Targets []string `json:"targets"`
}

func fixKey(key string) string {
	// Remove any whitespace
	key = strings.TrimSpace(key)

	// Decode from base64
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		logger.Fatal("Error decoding base64:", err)
	}

	// Convert to hex
	return hex.EncodeToString(decoded)
}

func ping(tnet *netstack.Net, dst string) error {
	logger.Info("Pinging %s", dst)
	socket, err := tnet.Dial("ping4", dst)
	if err != nil {
		return fmt.Errorf("failed to create ICMP socket: %w", err)
	}
	defer socket.Close()

	requestPing := icmp.Echo{
		Seq:  rand.Intn(1 << 16),
		Data: []byte("gopher burrow"),
	}

	icmpBytes, err := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: &requestPing}).Marshal(nil)
	if err != nil {
		return fmt.Errorf("failed to marshal ICMP message: %w", err)
	}

	if err := socket.SetReadDeadline(time.Now().Add(time.Second * 10)); err != nil {
		return fmt.Errorf("failed to set read deadline: %w", err)
	}

	start := time.Now()
	_, err = socket.Write(icmpBytes)
	if err != nil {
		return fmt.Errorf("failed to write ICMP packet: %w", err)
	}

	n, err := socket.Read(icmpBytes[:])
	if err != nil {
		return fmt.Errorf("failed to read ICMP packet: %w", err)
	}

	replyPacket, err := icmp.ParseMessage(1, icmpBytes[:n])
	if err != nil {
		return fmt.Errorf("failed to parse ICMP packet: %w", err)
	}

	replyPing, ok := replyPacket.Body.(*icmp.Echo)
	if !ok {
		return fmt.Errorf("invalid reply type: got %T, want *icmp.Echo", replyPacket.Body)
	}

	if !bytes.Equal(replyPing.Data, requestPing.Data) || replyPing.Seq != requestPing.Seq {
		return fmt.Errorf("invalid ping reply: got seq=%d data=%q, want seq=%d data=%q",
			replyPing.Seq, replyPing.Data, requestPing.Seq, requestPing.Data)
	}

	logger.Info("Ping latency: %v", time.Since(start))
	return nil
}

func pingWithRetry(tnet *netstack.Net, dst string) error {
	const (
		maxAttempts = 5
		retryDelay  = 2 * time.Second
	)

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		logger.Info("Ping attempt %d of %d", attempt, maxAttempts)

		if err := ping(tnet, dst); err != nil {
			lastErr = err
			logger.Warn("Ping attempt %d failed: %v", attempt, err)

			if attempt < maxAttempts {
				time.Sleep(retryDelay)
				continue
			}
			return fmt.Errorf("all ping attempts failed after %d tries, last error: %w",
				maxAttempts, lastErr)
		}

		// Successful ping
		return nil
	}

	// This shouldn't be reached due to the return in the loop, but added for completeness
	return fmt.Errorf("unexpected error: all ping attempts failed")
}

func parseLogLevel(level string) logger.LogLevel {
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

func mapToWireGuardLogLevel(level logger.LogLevel) int {
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

func resolveDomain(domain string) (string, error) {
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

func getEnvWithDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func main() {
	var (
		endpoint   string
		id         string
		secret     string
		dns        string
		privateKey wgtypes.Key
		err        error
		logLevel   string
	)

	// Define CLI flags with default values from environment variables
	flag.StringVar(&endpoint, "endpoint", os.Getenv("PANGOLIN_ENDPOINT"), "Endpoint of your pangolin server")
	flag.StringVar(&id, "id", os.Getenv("NEWT_ID"), "Newt ID")
	flag.StringVar(&secret, "secret", os.Getenv("NEWT_SECRET"), "Newt secret")
	flag.StringVar(&dns, "dns", getEnvWithDefault("DEFAULT_DNS", "8.8.8.8"), "DNS server to use")
	flag.StringVar(&logLevel, "log-level", getEnvWithDefault("LOG_LEVEL", "INFO"), "Log level (DEBUG, INFO, WARN, ERROR, FATAL)")
	flag.Parse()

	logger.Init()
	loggerLevel := parseLogLevel(logLevel)
	logger.GetLogger().SetLevel(parseLogLevel(logLevel))

	// Validate required fields
	if endpoint == "" || id == "" || secret == "" {
		logger.Fatal("endpoint, id, and secret are required either via CLI flags or environment variables")
	}

	privateKey, err = wgtypes.GeneratePrivateKey()
	if err != nil {
		logger.Fatal("Failed to generate private key: %v", err)
	}

	// Create a new client
	client, err := websocket.NewClient(
		id,     // CLI arg takes precedence
		secret, // CLI arg takes precedence
		endpoint,
	)
	if err != nil {
		logger.Fatal("Failed to create client: %v", err)
	}

	// Create TUN device and network stack
	var tun tun.Device
	var tnet *netstack.Net
	var dev *device.Device
	var pm *proxy.ProxyManager
	var connected bool
	var wgData WgData

	client.RegisterHandler("newt/terminate", func(msg websocket.WSMessage) {
		logger.Info("Received terminate message")
		if pm != nil {
			pm.Stop()
		}
		if dev != nil {
			dev.Close()
		}
		client.Close()
	})

	// Register handlers for different message types
	client.RegisterHandler("newt/wg/connect", func(msg websocket.WSMessage) {
		logger.Info("Received registration message")

		if connected {
			logger.Info("Already connected! Put I will send a ping anyway...")
			// ping(tnet, wgData.ServerIP)
			err = pingWithRetry(tnet, wgData.ServerIP)
			if err != nil {
				// Handle complete failure after all retries
				logger.Error("Failed to ping %s: %v", wgData.ServerIP, err)
			}
			return
		}

		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Info("Error marshaling data: %v", err)
			return
		}

		if err := json.Unmarshal(jsonData, &wgData); err != nil {
			logger.Info("Error unmarshaling target data: %v", err)
			return
		}

		logger.Info("Received: %+v", msg)
		tun, tnet, err = netstack.CreateNetTUN(
			[]netip.Addr{netip.MustParseAddr(wgData.TunnelIP)},
			[]netip.Addr{netip.MustParseAddr(dns)},
			1420)
		if err != nil {
			logger.Error("Failed to create TUN device: %v", err)
		}

		// Create WireGuard device
		dev = device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(
			mapToWireGuardLogLevel(loggerLevel),
			"wireguard: ",
		))

		endpoint, err := resolveDomain(wgData.Endpoint)
		if err != nil {
			logger.Error("Failed to resolve endpoint: %v", err)
			return
		}

		// Configure WireGuard
		config := fmt.Sprintf(`private_key=%s
public_key=%s
allowed_ip=%s/32
endpoint=%s
persistent_keepalive_interval=5`, fixKey(fmt.Sprintf("%s", privateKey)), fixKey(wgData.PublicKey), wgData.ServerIP, endpoint)

		err = dev.IpcSet(config)
		if err != nil {
			logger.Error("Failed to configure WireGuard device: %v", err)
		}

		// Bring up the device
		err = dev.Up()
		if err != nil {
			logger.Error("Failed to bring up WireGuard device: %v", err)
		}

		logger.Info("WireGuard device created. Lets ping the server now...")
		// Ping to bring the tunnel up on the server side quickly
		// ping(tnet, wgData.ServerIP)
		err = pingWithRetry(tnet, wgData.ServerIP)
		if err != nil {
			// Handle complete failure after all retries
			logger.Error("Failed to ping %s: %v", wgData.ServerIP, err)
		}

		// Create proxy manager
		pm = proxy.NewProxyManager(tnet)

		connected = true

		// add the targets if there are any
		if len(wgData.Targets.TCP) > 0 {
			updateTargets(pm, "add", wgData.TunnelIP, "tcp", TargetData{Targets: wgData.Targets.TCP})
		}

		if len(wgData.Targets.UDP) > 0 {
			updateTargets(pm, "add", wgData.TunnelIP, "udp", TargetData{Targets: wgData.Targets.UDP})
		}

		err = pm.Start()
		if err != nil {
			logger.Error("Failed to start proxy manager: %v", err)
		}
	})

	client.RegisterHandler("newt/tcp/add", func(msg websocket.WSMessage) {
		logger.Info("Received: %+v", msg)

		// if there is no wgData or pm, we can't add targets
		if wgData.TunnelIP == "" || pm == nil {
			logger.Info("No tunnel IP or proxy manager available")
			return
		}

		targetData, err := parseTargetData(msg.Data)
		if err != nil {
			logger.Info("Error parsing target data: %v", err)
			return
		}

		if len(targetData.Targets) > 0 {
			updateTargets(pm, "add", wgData.TunnelIP, "tcp", targetData)
		}

		err = pm.Start()
		if err != nil {
			logger.Error("Failed to start proxy manager: %v", err)
		}
	})

	client.RegisterHandler("newt/udp/add", func(msg websocket.WSMessage) {
		logger.Info("Received: %+v", msg)

		// if there is no wgData or pm, we can't add targets
		if wgData.TunnelIP == "" || pm == nil {
			logger.Info("No tunnel IP or proxy manager available")
			return
		}

		targetData, err := parseTargetData(msg.Data)
		if err != nil {
			logger.Info("Error parsing target data: %v", err)
			return
		}

		if len(targetData.Targets) > 0 {
			updateTargets(pm, "add", wgData.TunnelIP, "udp", targetData)
		}

		err = pm.Start()
		if err != nil {
			logger.Error("Failed to start proxy manager: %v", err)
		}
	})

	client.RegisterHandler("newt/udp/remove", func(msg websocket.WSMessage) {
		logger.Info("Received: %+v", msg)

		// if there is no wgData or pm, we can't add targets
		if wgData.TunnelIP == "" || pm == nil {
			logger.Info("No tunnel IP or proxy manager available")
			return
		}

		targetData, err := parseTargetData(msg.Data)
		if err != nil {
			logger.Info("Error parsing target data: %v", err)
			return
		}

		if len(targetData.Targets) > 0 {
			updateTargets(pm, "remove", wgData.TunnelIP, "udp", targetData)
		}
	})

	client.RegisterHandler("newt/tcp/remove", func(msg websocket.WSMessage) {
		logger.Info("Received: %+v", msg)

		// if there is no wgData or pm, we can't add targets
		if wgData.TunnelIP == "" || pm == nil {
			logger.Info("No tunnel IP or proxy manager available")
			return
		}

		targetData, err := parseTargetData(msg.Data)
		if err != nil {
			logger.Info("Error parsing target data: %v", err)
			return
		}

		if len(targetData.Targets) > 0 {
			updateTargets(pm, "remove", wgData.TunnelIP, "tcp", targetData)
		}
	})

	client.OnConnect(func() error {
		publicKey := privateKey.PublicKey()
		logger.Debug("Public key: %s", publicKey)

		err := client.SendMessage("newt/wg/register", map[string]interface{}{
			"publicKey": fmt.Sprintf("%s", publicKey),
		})
		if err != nil {
			logger.Error("Failed to send registration message: %v", err)
			return err
		}

		logger.Info("Sent registration message")
		return nil
	})

	// Connect to the WebSocket server
	if err := client.Connect(); err != nil {
		logger.Fatal("Failed to connect to server: %v", err)
	}
	defer client.Close()

	// Wait for interrupt signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	// Cleanup
	dev.Close()
}

func parseTargetData(data interface{}) (TargetData, error) {
	var targetData TargetData
	jsonData, err := json.Marshal(data)
	if err != nil {
		logger.Info("Error marshaling data: %v", err)
		return targetData, err
	}

	if err := json.Unmarshal(jsonData, &targetData); err != nil {
		logger.Info("Error unmarshaling target data: %v", err)
		return targetData, err
	}
	return targetData, nil
}

func updateTargets(pm *proxy.ProxyManager, action string, tunnelIP string, proto string, targetData TargetData) error {
	for _, t := range targetData.Targets {
		// Split the first number off of the target with : separator and use as the port
		parts := strings.Split(t, ":")
		if len(parts) != 3 {
			logger.Info("Invalid target format: %s", t)
			continue
		}

		// Get the port as an int
		port := 0
		_, err := fmt.Sscanf(parts[0], "%d", &port)
		if err != nil {
			logger.Info("Invalid port: %s", parts[0])
			continue
		}

		if action == "add" {
			target := parts[1] + ":" + parts[2]
			// Only remove the specific target if it exists
			err := pm.RemoveTarget(proto, tunnelIP, port)
			if err != nil {
				// Ignore "target not found" errors as this is expected for new targets
				if !strings.Contains(err.Error(), "target not found") {
					logger.Error("Failed to remove existing target: %v", err)
				}
			}

			// Add the new target
			pm.AddTarget(proto, tunnelIP, port, target)

		} else if action == "remove" {
			logger.Info("Removing target with port %d", port)
			err := pm.RemoveTarget(proto, tunnelIP, port)
			if err != nil {
				logger.Error("Failed to remove target: %v", err)
				return err
			}
		}
	}

	return nil
}
