package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
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
	publicKey            wgtypes.Key
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

	pingStopChan := make(chan struct{})
	defer close(pingStopChan)

	// Register handlers for different message types
	client.RegisterHandler("newt/wg/connect", func(msg websocket.WSMessage) {
		logger.Info("Received registration message")

		if connected {
			// Stop proxy manager if running
			if pm != nil {
				pm.Stop()
				pm = nil
			}

			// Close WireGuard device if running
			if dev != nil {
				dev.Close()
				dev = nil
			}

			// Close TUN/netstack if running
			if tnet != nil {
				tnet = nil
			}
			if tun != nil {
				tun.Close()
				tun = nil
			}

			// Stop the ping check
			close(pingStopChan)

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
		_ = pingWithRetry(tnet, wgData.ServerIP)

		// Always mark as connected and start the proxy manager regardless of initial ping result
		// as the pings will continue in the background
		if !connected {
			logger.Info("Starting ping check")
			startPingCheck(tnet, wgData.ServerIP, client, pingStopChan)
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

	client.RegisterHandler("newt/wg/terminate", func(msg websocket.WSMessage) {
		logger.Info("Received disconnect message")

		// Stop proxy manager if running
		if pm != nil {
			pm.Stop()
			pm = nil
		}

		// Close WireGuard device if running
		if dev != nil {
			dev.Close()
			dev = nil
		}

		// Close TUN/netstack if running
		if tnet != nil {
			tnet = nil
		}
		if tun != nil {
			tun.Close()
			tun = nil
		}

		// Stop the ping check
		close(pingStopChan)

		// Mark as disconnected
		connected = false

		logger.Info("Tunnel destroyed, ready for reconnection")
	})

	client.RegisterHandler("newt/ping/exitNodes", func(msg websocket.WSMessage) {
		logger.Info("Received ping message")

		// Parse the incoming list of exit nodes
		// Exit nodes is a json
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
		for i, node := range exitNodes {
			start := time.Now()
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
			resp, err := client.Get(url)
			latency := time.Since(start)
			if err != nil {
				logger.Warn("Failed to ping exit node %s (%s): %v", node.ID, url, err)
				results[i] = nodeResult{Node: node, Latency: latency, Err: err}
				continue
			}
			resp.Body.Close()
			results[i] = nodeResult{Node: node, Latency: latency, Err: nil}
			// logger.Info("Exit node %s latency: %v", node.Name, latency)
		}

		// we will need to tweak these
		const (
			latencyPenaltyExponent = 1.5  // make latency matter more
			lastNodeScoreBoost     = 1.10 // 10% preference for the last used node
			scoreTolerancePercent  = 5.0  // allow last node if within 5% of best score
		)

		var bestNode *ExitNode
		var bestScore float64 = -1e12
		var bestLatency time.Duration = 1e12

		type ExitNodeScore struct {
			Node    ExitNode
			Score   float64
			Latency time.Duration
		}
		var candidateNodes []ExitNodeScore

		for _, res := range results {
			if res.Err != nil || res.Node.Weight <= 0 {
				continue
			}

			latencyMs := float64(res.Latency.Milliseconds())
			score := res.Node.Weight / math.Pow(latencyMs, latencyPenaltyExponent)

			// slight boost if this is the last used node
			if res.Node.WasPreviouslyConnected == true {
				score *= lastNodeScoreBoost
			}

			logger.Info("Exit node %s with score: %.2f (latency: %dms, weight: %.2f)", res.Node.Name, score, res.Latency.Milliseconds(), res.Node.Weight)

			candidateNodes = append(candidateNodes, ExitNodeScore{Node: res.Node, Score: score, Latency: res.Latency})

			if score > bestScore {
				bestScore = score
				bestLatency = res.Latency
				bestNode = &res.Node
			} else if score == bestScore && res.Latency < bestLatency {
				bestLatency = res.Latency
				bestNode = &res.Node
			}
		}

		// check if last used node is close enough in score
		for _, cand := range candidateNodes {
			if cand.Node.WasPreviouslyConnected {
				if bestScore-cand.Score <= bestScore*(scoreTolerancePercent/100.0) {
					logger.Info("Sticking with last used exit node: %s (%s), score close enough to best", cand.Node.Name, cand.Node.Endpoint)
					bestNode = &cand.Node
				}
				break
			}
		}

		if bestNode == nil {
			logger.Warn("No suitable exit node found")
			return
		}

		logger.Info("Selected exit node: %s (%s)", bestNode.Name, bestNode.Endpoint)

		err = client.SendMessage("newt/wg/register", map[string]interface{}{
			"publicKey":  publicKey.String(),
			"exitNodeId": bestNode.ID,
		})
		if err != nil {
			logger.Error("Failed to send registration message: %v", err)
			return
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

		// request from the server the list of nodes to ping at newt/ping/request
		err := client.SendMessage("newt/ping/request", map[string]interface{}{})
		if err != nil {
			logger.Error("Failed to send ping request: %v", err)
		}

		if wgService != nil {
			wgService.LoadRemoteConfig()
		}

		logger.Info("Sent registration message")
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

func startPingCheck(tnet *netstack.Net, serverIP string, client *websocket.Client, stopChan chan struct{}) {
	initialInterval := 10 * time.Second
	maxInterval := 60 * time.Second
	currentInterval := initialInterval
	consecutiveFailures := 0
	connectionLost := false
	ticker := time.NewTicker(currentInterval)
	defer ticker.Stop()

	go func() {
		for {
			select {
			case <-ticker.C:
				_, err := ping(tnet, serverIP)
				if err != nil {
					consecutiveFailures++

					// Check if this is the first failure (connection just lost)
					if !connectionLost {
						connectionLost = true
						logger.Warn("Connection to server lost. Continuous reconnection attempts will be made.")
						logger.Warn("Please check your internet connection and ensure the Pangolin server is online.")
						logger.Warn("Newt will continue reconnection attempts automatically when connectivity is restored.")
					}

					logger.Warn("Periodic ping failed (%d consecutive failures): %v",
						consecutiveFailures, err)
					logger.Warn("HINT: Do you have UDP port 51820 (or the port in config.yml) open on your Pangolin server?")

					// Increase interval if we have consistent failures, with a maximum cap
					if consecutiveFailures >= 5 && currentInterval < maxInterval {
						// Increase by 50% each time, up to the maximum
						currentInterval = time.Duration(float64(currentInterval) * 1.5)
						if currentInterval > maxInterval {
							currentInterval = maxInterval
						}
						ticker.Reset(currentInterval)
						logger.Debug("Increased ping check interval to %v due to consecutive failures",
							currentInterval)

						// Restart the connection flow
						err := client.SendMessage("newt/ping/request", map[string]interface{}{})
						if err != nil {
							logger.Error("Failed to send ping request: %v", err)
						}
					}
				} else {
					// Check if connection was previously lost and is now restored
					if connectionLost {
						connectionLost = false
						logger.Info("Connection to server restored!")
					}

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
