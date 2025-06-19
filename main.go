package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fosrl/newt/docker"
	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/proxy"
	"github.com/fosrl/newt/websocket"
	"github.com/fosrl/newt/wg"
	"github.com/fosrl/newt/wgtester"

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

type ExitNodeData struct {
	ExitNodes []ExitNode `json:"exitNodes"`
}

// ExitNode represents an exit node with an ID, endpoint, and weight.
type ExitNode struct {
	ID                     int     `json:"exitNodeId"`
	Name                   string  `json:"exitNodeName"`
	Endpoint               string  `json:"endpoint"`
	Weight                 float64 `json:"weight"`
	WasPreviouslyConnected bool    `json:"wasPreviouslyConnected"`
}

type ExitNodePingResult struct {
	ExitNodeID             int     `json:"exitNodeId"`
	LatencyMs              int64   `json:"latencyMs"`
	Weight                 float64 `json:"weight"`
	Error                  string  `json:"error,omitempty"`
	Name                   string  `json:"exitNodeName"`
	Endpoint               string  `json:"endpoint"`
	WasPreviouslyConnected bool    `json:"wasPreviouslyConnected"`
}

var (
	endpoint             string
	id                   string
	secret               string
	mtu                  string
	mtuInt               int
	dns                  string
	privateKey           wgtypes.Key
	err                  error
	logLevel             string
	interfaceName        string
	generateAndSaveKeyTo string
	rm                   bool
	acceptClients        bool
	updownScript         string
	tlsPrivateKey        string
	dockerSocket         string
	pingInterval         = 1 * time.Second
	pingTimeout          = 2 * time.Second
	publicKey            wgtypes.Key
	pingStopChan         chan struct{}
	stopFunc             func()
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
	interfaceName = os.Getenv("INTERFACE")
	generateAndSaveKeyTo = os.Getenv("GENERATE_AND_SAVE_KEY_TO")
	rm = os.Getenv("RM") == "true"
	acceptClients = os.Getenv("ACCEPT_CLIENTS") == "true"
	tlsPrivateKey = os.Getenv("TLS_CLIENT_CERT")
	dockerSocket = os.Getenv("DOCKER_SOCKET")
	pingIntervalStr := os.Getenv("PING_INTERVAL")
	pingTimeoutStr := os.Getenv("PING_TIMEOUT")

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
		flag.StringVar(&logLevel, "log-level", "INFO", "Log level (DEBUG, INFO, WARN, ERROR, FATAL)")
	}
	if updownScript == "" {
		flag.StringVar(&updownScript, "updown", "", "Path to updown script to be called when targets are added or removed")
	}
	if interfaceName == "" {
		flag.StringVar(&interfaceName, "interface", "wg1", "Name of the WireGuard interface")
	}
	if generateAndSaveKeyTo == "" {
		flag.StringVar(&generateAndSaveKeyTo, "generateAndSaveKeyTo", "/tmp/newtkey", "Path to save generated private key")
	}
	flag.BoolVar(&rm, "rm", false, "Remove the WireGuard interface")
	flag.BoolVar(&acceptClients, "accept-clients", false, "Accept clients on the WireGuard interface")
	if tlsPrivateKey == "" {
		flag.StringVar(&tlsPrivateKey, "tls-client-cert", "", "Path to client certificate used for mTLS")
	}
	if dockerSocket == "" {
		flag.StringVar(&dockerSocket, "docker-socket", "", "Path to Docker socket (typically /var/run/docker.sock)")
	}
	if pingIntervalStr == "" {
		flag.StringVar(&pingIntervalStr, "ping-interval", "1s", "Interval for pinging the server (default 1s)")
	}
	if pingTimeoutStr == "" {
		flag.StringVar(&pingTimeoutStr, "ping-timeout", "2s", "	Timeout for each ping (default 2s)")
	}

	if pingIntervalStr != "" {
		pingInterval, err = time.ParseDuration(pingIntervalStr)
		if err != nil {
			fmt.Printf("Invalid PING_INTERVAL value: %s, using default 1 second\n", pingIntervalStr)
			pingInterval = 1 * time.Second
		}
	}

	if pingTimeoutStr != "" {
		pingTimeout, err = time.ParseDuration(pingTimeoutStr)
		if err != nil {
			fmt.Printf("Invalid PING_TIMEOUT value: %s, using default 2 seconds\n", pingTimeoutStr)
			pingTimeout = 2 * time.Second
		}
	}

	// do a --version check
	version := flag.Bool("version", false, "Print the version")

	flag.Parse()

	logger.Init()
	loggerLevel := parseLogLevel(logLevel)
	logger.GetLogger().SetLevel(parseLogLevel(logLevel))

	newtVersion := "version_replaceme"
	if *version {
		fmt.Println("Newt version " + newtVersion)
		os.Exit(0)
	} else {
		logger.Info("Newt version " + newtVersion)
	}

	if err := CheckForUpdate("fosrl", "newt", newtVersion); err != nil {
		logger.Error("Error checking for updates: %v\n", err)
	}

	// parse the mtu string into an int
	mtuInt, err = strconv.Atoi(mtu)
	if err != nil {
		logger.Fatal("Failed to parse MTU: %v", err)
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
		pingInterval,
		pingTimeout,
		opt,
	)
	if err != nil {
		logger.Fatal("Failed to create client: %v", err)
	}

	var wgService *wg.WireGuardService
	// Create TUN device and network stack
	var tun tun.Device
	var tnet *netstack.Net
	var dev *device.Device
	var pm *proxy.ProxyManager
	var connected bool
	var wgData WgData
	var wgTesterServer *wgtester.Server

	if acceptClients {
		// make sure we are running on linux
		if runtime.GOOS != "linux" {
			logger.Fatal("Tunnel management is only supported on Linux right now!")
			os.Exit(1)
		}

		var host = endpoint
		if strings.HasPrefix(host, "http://") {
			host = strings.TrimPrefix(host, "http://")
		} else if strings.HasPrefix(host, "https://") {
			host = strings.TrimPrefix(host, "https://")
		}

		host = strings.TrimSuffix(host, "/")

		// Create WireGuard service
		wgService, err = wg.NewWireGuardService(interfaceName, mtuInt, generateAndSaveKeyTo, host, id, client)
		if err != nil {
			logger.Fatal("Failed to create WireGuard service: %v", err)
		}
		defer wgService.Close(rm)

		wgTesterServer = wgtester.NewServer("0.0.0.0", wgService.Port, id) // TODO: maybe make this the same ip of the wg server?
		err := wgTesterServer.Start()
		if err != nil {
			logger.Error("Failed to start WireGuard tester server: %v", err)
		} else {
			// Make sure to stop the server on exit
			defer wgTesterServer.Stop()
		}
	}

	// Register handlers for different message types
	client.RegisterHandler("newt/wg/connect", func(msg websocket.WSMessage) {
		logger.Info("Received registration message")
		if stopFunc != nil {
			stopFunc()     // stop the ws from sending more requests
			stopFunc = nil // reset stopFunc to nil to avoid double stopping
		}

		if connected {
			if pingStopChan != nil {
				// Stop the ping check
				close(pingStopChan)
				pingStopChan = nil
			}

			// Stop proxy manager if running
			if pm != nil {
				pm.Stop()
				pm = nil
			}

			// Close WireGuard device first - this will automatically close the TUN device
			if dev != nil {
				dev.Close()
				dev = nil
			}

			// Clear references but don't manually close since dev.Close() already did it
			if tnet != nil {
				tnet = nil
			}
			if tun != nil {
				tun = nil // Don't call tun.Close() here since dev.Close() already closed it
			}

			// Mark as disconnected
			connected = false
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

		if wgService != nil {
			wgService.SetServerPubKey(wgData.PublicKey)
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
		_ = pingWithRetry(tnet, wgData.ServerIP, pingTimeout)

		// Always mark as connected and start the proxy manager regardless of initial ping result
		// as the pings will continue in the background
		if !connected {
			logger.Info("Starting ping check")
			pingStopChan = startPingCheck(tnet, wgData.ServerIP, client)
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

		// first make sure the wpgService has a port
		if wgService != nil {
			// add a udp proxy for localost and the wgService port
			// TODO: make sure this port is not used in a target
			pm.AddTarget("udp", wgData.TunnelIP, int(wgService.Port), fmt.Sprintf("127.0.0.1:%d", wgService.Port))
		}

		err = pm.Start()
		if err != nil {
			logger.Error("Failed to start proxy manager: %v", err)
		}
	})

	client.RegisterHandler("newt/wg/reconnect", func(msg websocket.WSMessage) {
		logger.Info("Received reconnect message")

		if pingStopChan != nil {
			// Stop the ping check
			close(pingStopChan)
			pingStopChan = nil
		}

		// Stop proxy manager if running
		if pm != nil {
			pm.Stop()
			pm = nil
		}

		// Close WireGuard device first - this will automatically close the TUN device
		if dev != nil {
			dev.Close()
			dev = nil
		}

		// Clear references but don't manually close since dev.Close() already did it
		if tnet != nil {
			tnet = nil
		}
		if tun != nil {
			tun = nil // Don't call tun.Close() here since dev.Close() already closed it
		}

		// Mark as disconnected
		connected = false

		// start asking for the exit nodes again
		if stopFunc != nil {
			stopFunc()     // stop the ws from sending more requests
			stopFunc = nil // reset stopFunc to nil to avoid double stopping
		}

		// Request exit nodes from the server
		stopFunc = client.SendMessageInterval("newt/ping/request", map[string]interface{}{}, 3*time.Second)

		logger.Info("Tunnel destroyed, ready for reconnection")
	})

	client.RegisterHandler("newt/ping/exitNodes", func(msg websocket.WSMessage) {
		logger.Info("Received ping message")
		if stopFunc != nil {
			stopFunc()     // stop the ws from sending more requests
			stopFunc = nil // reset stopFunc to nil to avoid double stopping
		}

		// Parse the incoming list of exit nodes
		var exitNodeData ExitNodeData

		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Info("Error marshaling data: %v", err)
			return
		}
		if err := json.Unmarshal(jsonData, &exitNodeData); err != nil {
			logger.Info("Error unmarshaling exit node data: %v", err)
			return
		}
		exitNodes := exitNodeData.ExitNodes

		if len(exitNodes) == 0 {
			logger.Info("No exit nodes provided")
			return
		}

		type nodeResult struct {
			Node    ExitNode
			Latency time.Duration
			Err     error
		}

		results := make([]nodeResult, len(exitNodes))
		const pingAttempts = 3
		for i, node := range exitNodes {
			if connected && node.WasPreviouslyConnected {
				logger.Info("Skipping ping for previously connected exit node so we pick another %d (%s)", node.ID, node.Endpoint)
				continue
			}

			var totalLatency time.Duration
			var lastErr error
			successes := 0
			client := &http.Client{
				Timeout: 5 * time.Second,
			}
			url := node.Endpoint
			if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
				url = "http://" + url
			}
			if !strings.HasSuffix(url, "/ping") {
				url = strings.TrimRight(url, "/") + "/ping"
			}
			for j := 0; j < pingAttempts; j++ {
				start := time.Now()
				resp, err := client.Get(url)
				latency := time.Since(start)
				if err != nil {
					lastErr = err
					logger.Warn("Failed to ping exit node %d (%s) attempt %d: %v", node.ID, url, j+1, err)
					continue
				}
				resp.Body.Close()
				totalLatency += latency
				successes++
			}
			var avgLatency time.Duration
			if successes > 0 {
				avgLatency = totalLatency / time.Duration(successes)
			}
			if successes == 0 {
				results[i] = nodeResult{Node: node, Latency: 0, Err: lastErr}
			} else {
				results[i] = nodeResult{Node: node, Latency: avgLatency, Err: nil}
			}
		}

		// Prepare data to send to the cloud for selection
		var pingResults []ExitNodePingResult
		for _, res := range results {
			errMsg := ""
			if res.Err != nil {
				errMsg = res.Err.Error()
			}
			pingResults = append(pingResults, ExitNodePingResult{
				ExitNodeID:             res.Node.ID,
				LatencyMs:              res.Latency.Milliseconds(),
				Weight:                 res.Node.Weight,
				Error:                  errMsg,
				Name:                   res.Node.Name,
				Endpoint:               res.Node.Endpoint,
				WasPreviouslyConnected: res.Node.WasPreviouslyConnected,
			})
		}

		// Send the ping results to the cloud for selection
		stopFunc = client.SendMessageInterval("newt/wg/register", map[string]interface{}{
			"publicKey":   publicKey.String(),
			"pingResults": pingResults,
			"newtVersion": newtVersion,
		}, 1*time.Second)
		logger.Info("Sent exit node ping results to cloud for selection")
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
		containers, err := docker.ListContainers(dockerSocket)
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
		publicKey = privateKey.PublicKey()
		logger.Debug("Public key: %s", publicKey)

		if !connected {
			// request from the server the list of nodes to ping at newt/ping/request
			stopFunc = client.SendMessageInterval("newt/ping/request", map[string]interface{}{}, 3*time.Second)

			// Send registration message to the server for backward compatibility
			err := client.SendMessage("newt/wg/register", map[string]interface{}{
				"publicKey":           publicKey.String(),
				"newtVersion":         newtVersion,
				"backwardsCompatible": true,
			})
			if err != nil {
				logger.Error("Failed to send registration message: %v", err)
				return err
			}
			logger.Info("Sent registration message")

			if wgService != nil {
				wgService.LoadRemoteConfig()
			}
		}

		return nil
	})

	client.OnTokenUpdate(func(token string) {
		if wgService != nil {
			wgService.SetToken(token)
		}
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

	dev.Close()

	if wgService != nil {
		wgService.Close(rm)
	}

	if wgTesterServer != nil {
		wgTesterServer.Stop()
	}

	if pm != nil {
		pm.Stop()
	}

	if client != nil {
		client.Close()
	}
	logger.Info("Exiting...")
	os.Exit(0)
}
