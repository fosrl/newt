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
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fosrl/newt/docker"
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
		logger.Fatal("Error decoding base64: %v", err)
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

func startPingCheck(tnet *netstack.Net, serverIP string, stopChan chan struct{}) {
	initialInterval := 10 * time.Second
	maxInterval := 60 * time.Second
	currentInterval := initialInterval
	consecutiveFailures := 0

	ticker := time.NewTicker(currentInterval)
	defer ticker.Stop()

	go func() {
		for {
			select {
			case <-ticker.C:
				err := ping(tnet, serverIP)
				if err != nil {
					consecutiveFailures++
					logger.Warn("Periodic ping failed (%d consecutive failures): %v",
						consecutiveFailures, err)
					logger.Warn("HINT: Do you have UDP port 51820 (or the port in config.yml) open on your Pangolin server?")

					// Increase interval if we have consistent failures, with a maximum cap
					if consecutiveFailures >= 3 && currentInterval < maxInterval {
						// Increase by 50% each time, up to the maximum
						currentInterval = time.Duration(float64(currentInterval) * 1.5)
						if currentInterval > maxInterval {
							currentInterval = maxInterval
						}
						ticker.Reset(currentInterval)
						logger.Info("Increased ping check interval to %v due to consecutive failures",
							currentInterval)
					}
				} else {
					// On success, if we've backed off, gradually return to normal interval
					if currentInterval > initialInterval {
						currentInterval = time.Duration(float64(currentInterval) * 0.8)
						if currentInterval < initialInterval {
							currentInterval = initialInterval
						}
						ticker.Reset(currentInterval)
						logger.Info("Decreased ping check interval to %v after successful ping",
							currentInterval)
					}
					consecutiveFailures = 0
				}
			case <-stopChan:
				logger.Info("Stopping ping check")
				return
			}
		}
	}()
}

// Function to track connection status and trigger reconnection as needed
func monitorConnectionStatus(tnet *netstack.Net, serverIP string, client *websocket.Client) {
	const checkInterval = 30 * time.Second
	connectionLost := false
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Try a ping to see if connection is alive
			err := ping(tnet, serverIP)

			if err != nil && !connectionLost {
				// We just lost connection
				connectionLost = true
				logger.Warn("Connection to server lost. Continuous reconnection attempts will be made.")

				// Notify the user they might need to check their network
				logger.Warn("Please check your internet connection and ensure the Pangolin server is online.")
				logger.Warn("Newt will continue reconnection attempts automatically when connectivity is restored.")
			} else if err == nil && connectionLost {
				// Connection has been restored
				connectionLost = false
				logger.Info("Connection to server restored!")

				// Tell the server we're back
				err := client.SendMessage("newt/wg/register", map[string]interface{}{
					"publicKey": privateKey.PublicKey().String(),
				})

				if err != nil {
					logger.Error("Failed to send registration message after reconnection: %v", err)
				} else {
					logger.Info("Successfully re-registered with server after reconnection")
				}
			}
		}
	}
}

func pingWithRetry(tnet *netstack.Net, dst string) error {
	const (
		initialMaxAttempts = 15
		initialRetryDelay  = 2 * time.Second
		maxRetryDelay      = 60 * time.Second // Cap the maximum delay
	)

	attempt := 1
	retryDelay := initialRetryDelay

	// First try with the initial parameters
	logger.Info("Ping attempt %d", attempt)
	if err := ping(tnet, dst); err == nil {
		// Successful ping
		return nil
	} else {
		logger.Warn("Ping attempt %d failed: %v", attempt, err)
	}

	// Start a goroutine that will attempt pings indefinitely with increasing delays
	go func() {
		attempt = 2 // Continue from attempt 2

		for {
			logger.Info("Ping attempt %d", attempt)

			if err := ping(tnet, dst); err != nil {
				logger.Warn("Ping attempt %d failed: %v", attempt, err)

				// Increase delay after certain thresholds but cap it
				if attempt%5 == 0 && retryDelay < maxRetryDelay {
					retryDelay = time.Duration(float64(retryDelay) * 1.5)
					if retryDelay > maxRetryDelay {
						retryDelay = maxRetryDelay
					}
					logger.Info("Increasing ping retry delay to %v", retryDelay)
				}

				time.Sleep(retryDelay)
				attempt++
			} else {
				// Successful ping
				logger.Info("Ping succeeded after %d attempts", attempt)
				return
			}
		}
	}()

	// Return an error for the first batch of attempts (to maintain compatibility with existing code)
	return fmt.Errorf("initial ping attempts failed, continuing in background")
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

var (
	endpoint              string
	id                    string
	secret                string
	mtu                   string
	mtuInt                int
	dns                   string
	privateKey            wgtypes.Key
	err                   error
	logLevel              string
	updownScript          string
	tlsPrivateKey         string
	dockerSocket          string
	dockerLabelEnable     string
	dockerLabelEnableBool bool
)

func main() {
	// if PANGOLIN_ENDPOINT, NEWT_ID, and NEWT_SECRET are set as environment variables, they will be used as default values
	endpoint = os.Getenv("PANGOLIN_ENDPOINT")
	id = os.Getenv("NEWT_ID")
	secret = os.Getenv("NEWT_SECRET")
	mtu = os.Getenv("MTU")
	dns = os.Getenv("DNS")
	logLevel = os.Getenv("LOG_LEVEL")
	updownScript = os.Getenv("UPDOWN_SCRIPT")
	tlsPrivateKey = os.Getenv("TLS_CLIENT_CERT")
	dockerSocket = os.Getenv("DOCKER_SOCKET")
	dockerLabelEnable = os.Getenv("DOCKER_LABEL_ENABLE")

	if endpoint == "" {
		flag.StringVar(&endpoint, "endpoint", "", "Endpoint of your pangolin server")
	}
	if id == "" {
		flag.StringVar(&id, "id", "", "Newt ID")
	}
	if secret == "" {
		flag.StringVar(&secret, "secret", "", "Newt secret")
	}
	if mtu == "" {
		flag.StringVar(&mtu, "mtu", "1280", "MTU to use")
	}
	if dns == "" {
		flag.StringVar(&dns, "dns", "8.8.8.8", "DNS server to use")
	}
	if logLevel == "" {
		flag.StringVar(&logLevel, "log-level", "DEBUG", "Log level (DEBUG, INFO, WARN, ERROR, FATAL)")
	}
	if updownScript == "" {
		flag.StringVar(&updownScript, "updown", "", "Path to updown script to be called when targets are added or removed")
	}
	if tlsPrivateKey == "" {
		flag.StringVar(&tlsPrivateKey, "tls-client-cert", "", "Path to client certificate used for mTLS")
	}
	if dockerSocket == "" {
		flag.StringVar(&dockerSocket, "docker-socket", "", "Path to Docker socket (typically /var/run/docker.sock)")
	}
	if dockerLabelEnable == "" {
		flag.StringVar(&dockerLabelEnable, "docker-label-enable", "", "Enable functionality to opt-in containers by label that are sent to Pangolin")
	}

	// do a --version check
	version := flag.Bool("version", false, "Print the version")

	flag.Parse()

	newtVersion := "Newt version replaceme"
	if *version {
		fmt.Println(newtVersion)
		os.Exit(0)
	} else {
		logger.Info(newtVersion)
	}

	logger.Init()
	loggerLevel := parseLogLevel(logLevel)
	logger.GetLogger().SetLevel(parseLogLevel(logLevel))

	// parse the mtu string into an int
	mtuInt, err = strconv.Atoi(mtu)
	if err != nil {
		logger.Fatal("Failed to parse MTU: %v", err)
	}

	// parse the docker label enable string to a bool
	if dockerLabelEnable != "" {
		dockerLabelEnableBool, err = strconv.ParseBool(dockerLabelEnable)
		if err != nil {
			logger.Fatal("Failed to parse DOCKER_LABEL_ENABLE: %v", err)
		}
	}

	privateKey, err = wgtypes.GeneratePrivateKey()
	if err != nil {
		logger.Fatal("Failed to generate private key: %v", err)
	}
	var opt websocket.ClientOption
	if tlsPrivateKey != "" {
		opt = websocket.WithTLSConfig(tlsPrivateKey)
	}
	// Create a new client
	client, err := websocket.NewClient(
		id,     // CLI arg takes precedence
		secret, // CLI arg takes precedence
		endpoint,
		opt,
	)
	if err != nil {
		logger.Fatal("Failed to create client: %v", err)
	}

	// output env var values if set
	logger.Debug("Endpoint: %v", endpoint)
	logger.Debug("Log Level: %v", logLevel)
	logger.Debug("Docker Label Enable Set: %v", dockerLabelEnableBool)
	logger.Debug("TLS Private Key Set: %v", tlsPrivateKey != "")
	if dns != "" {
		logger.Debug("Dns: %v", dns)
	}
	if dockerSocket != "" {
		logger.Debug("Docker Socket: %v", dockerSocket)
	}
	if mtu != "" {
		logger.Debug("MTU: %v", mtu)
	}
	if updownScript != "" {
		logger.Debug("Up Down Script: %v", updownScript)
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

	pingStopChan := make(chan struct{})
	defer close(pingStopChan)

	// Register handlers for different message types
	client.RegisterHandler("newt/wg/connect", func(msg websocket.WSMessage) {
		logger.Info("Received registration message")

		if connected {
			logger.Info("Already connected! But I will send a ping anyway...")
			// Even if pingWithRetry returns an error, it will continue trying in the background
			_ = pingWithRetry(tnet, wgData.ServerIP) // Ignoring initial error as pings will continue
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
			mtuInt)
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
persistent_keepalive_interval=5`, fixKey(privateKey.String()), fixKey(wgData.PublicKey), wgData.ServerIP, endpoint)

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

		// Even if pingWithRetry returns an error, it will continue trying in the background
		_ = pingWithRetry(tnet, wgData.ServerIP)

		// Always mark as connected and start the proxy manager regardless of initial ping result
		// as the pings will continue in the background
		if !connected {
			logger.Info("Starting ping check")
			startPingCheck(tnet, wgData.ServerIP, pingStopChan)

			// Start connection monitoring in a separate goroutine
			go monitorConnectionStatus(tnet, wgData.ServerIP, client)
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

	// Register handler for Docker socket check
	client.RegisterHandler("newt/socket/check", func(msg websocket.WSMessage) {
		logger.Info("Received Docker socket check request")

		if dockerSocket == "" {
			logger.Info("Docker socket path is not set")
			err := client.SendMessage("newt/socket/status", map[string]interface{}{
				"available":  false,
				"socketPath": dockerSocket,
			})
			if err != nil {
				logger.Error("Failed to send Docker socket check response: %v", err)
			}
			return
		}

		// Check if Docker socket is available
		isAvailable := docker.CheckSocket(dockerSocket)

		// Send response back to server
		err := client.SendMessage("newt/socket/status", map[string]interface{}{
			"available":  isAvailable,
			"socketPath": dockerSocket,
		})
		if err != nil {
			logger.Error("Failed to send Docker socket check response: %v", err)
		} else {
			logger.Info("Docker socket check response sent: available=%t", isAvailable)
		}
	})

	// Register handler for Docker container listing
	client.RegisterHandler("newt/socket/fetch", func(msg websocket.WSMessage) {
		logger.Info("Received Docker container fetch request")

		if dockerSocket == "" {
			logger.Info("Docker socket path is not set")
			return
		}

		// List Docker containers
		containers, err := docker.ListContainers(dockerSocket, dockerLabelEnableBool)
		if err != nil {
			logger.Error("Failed to list Docker containers: %v", err)
			return
		}

		// Send container list back to server
		err = client.SendMessage("newt/socket/containers", map[string]interface{}{
			"containers": containers,
		})
		if err != nil {
			logger.Error("Failed to send Docker container list: %v", err)
		} else {
			logger.Info("Docker container list sent, count: %d", len(containers))
		}
	})

	client.OnConnect(func() error {
		publicKey := privateKey.PublicKey()
		logger.Debug("Public key: %s", publicKey)

		err := client.SendMessage("newt/wg/register", map[string]interface{}{
			"publicKey": publicKey.String(),
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
	sigReceived := <-sigCh

	// Cleanup
	logger.Info("Received %s signal, stopping", sigReceived.String())
	if dev != nil {
		dev.Close()
	}
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

			// Call updown script if provided
			processedTarget := target
			if updownScript != "" {
				newTarget, err := executeUpdownScript(action, proto, target)
				if err != nil {
					logger.Warn("Updown script error: %v", err)
				} else if newTarget != "" {
					processedTarget = newTarget
				}
			}

			// Only remove the specific target if it exists
			err := pm.RemoveTarget(proto, tunnelIP, port)
			if err != nil {
				// Ignore "target not found" errors as this is expected for new targets
				if !strings.Contains(err.Error(), "target not found") {
					logger.Error("Failed to remove existing target: %v", err)
				}
			}

			// Add the new target
			pm.AddTarget(proto, tunnelIP, port, processedTarget)

		} else if action == "remove" {
			logger.Info("Removing target with port %d", port)

			target := parts[1] + ":" + parts[2]

			// Call updown script if provided
			if updownScript != "" {
				_, err := executeUpdownScript(action, proto, target)
				if err != nil {
					logger.Warn("Updown script error: %v", err)
				}
			}

			err := pm.RemoveTarget(proto, tunnelIP, port)
			if err != nil {
				logger.Error("Failed to remove target: %v", err)
				return err
			}
		}
	}

	return nil
}

func executeUpdownScript(action, proto, target string) (string, error) {
	if updownScript == "" {
		return target, nil
	}

	// Split the updownScript in case it contains spaces (like "/usr/bin/python3 script.py")
	parts := strings.Fields(updownScript)
	if len(parts) == 0 {
		return target, fmt.Errorf("invalid updown script command")
	}

	var cmd *exec.Cmd
	if len(parts) == 1 {
		// If it's a single executable
		logger.Info("Executing updown script: %s %s %s %s", updownScript, action, proto, target)
		cmd = exec.Command(parts[0], action, proto, target)
	} else {
		// If it includes interpreter and script
		args := append(parts[1:], action, proto, target)
		logger.Info("Executing updown script: %s %s %s %s %s", parts[0], strings.Join(parts[1:], " "), action, proto, target)
		cmd = exec.Command(parts[0], args...)
	}

	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("updown script execution failed (exit code %d): %s",
				exitErr.ExitCode(), string(exitErr.Stderr))
		}
		return "", fmt.Errorf("updown script execution failed: %v", err)
	}

	// If the script returns a new target, use it
	newTarget := strings.TrimSpace(string(output))
	if newTarget != "" {
		logger.Info("Updown script returned new target: %s", newTarget)
		return newTarget, nil
	}

	return target, nil
}
