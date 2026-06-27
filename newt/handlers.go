package newt

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/fosrl/newt/authdaemon"
	"github.com/fosrl/newt/browsergateway"
	newtDevice "github.com/fosrl/newt/device"
	"github.com/fosrl/newt/docker"
	"github.com/fosrl/newt/healthcheck"
	"github.com/fosrl/newt/internal/state"
	"github.com/fosrl/newt/internal/telemetry"
	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/network"
	"github.com/fosrl/newt/proxy"
	"github.com/fosrl/newt/util"
	"github.com/fosrl/newt/websocket"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	wtun "golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const (
	fmtErrMarshaling        = "Error marshaling data: %v"
	fmtReceivedMsg          = "Received: %+v"
	topicWGRegister         = "newt/wg/register"
	msgNoTunnelOrProxy      = "No tunnel IP or proxy manager available"
	fmtErrParsingTargetData = "Error parsing target data: %v"
)

func (n *Newt) registerHandlers(ctx context.Context) {
	n.client.RegisterHandler("newt/wg/connect", func(msg websocket.WSMessage) {
		logger.Debug("Received registration message")
		regResult := "success"
		defer func() {
			telemetry.IncSiteRegistration(ctx, regResult)
		}()

		var chainData struct {
			ChainId string `json:"chainId"`
		}
		if jsonBytes, err := json.Marshal(msg.Data); err == nil {
			_ = json.Unmarshal(jsonBytes, &chainData)
		}
		if chainData.ChainId != "" {
			if chainData.ChainId != n.pendingRegisterChainId {
				logger.Debug("Discarding duplicate/stale newt/wg/connect (chainId=%s, expected=%s)", chainData.ChainId, n.pendingRegisterChainId)
				return
			}
			n.pendingRegisterChainId = ""
		}

		if n.stopFunc != nil {
			n.stopFunc()
			n.stopFunc = nil
		}

		if n.connected {
			n.closeWgTunnel()
			n.connected = false
		}

		logger.Debug("Received registration message data: %+v", msg.Data)

		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Info(fmtErrMarshaling, err)
			regResult = "failure"
			return
		}

		if err := json.Unmarshal(jsonData, &n.wgData); err != nil {
			logger.Info("Error unmarshaling target data: %v", err)
			regResult = "failure"
			return
		}

		logger.Debug(fmtReceivedMsg, msg)

		if n.config.UseNativeMainInterface {
			mainIfName := n.config.NativeMainInterfaceName
			if runtime.GOOS == "darwin" {
				mainIfName, err = network.FindUnusedUTUN()
				if err != nil {
					logger.Error("Failed to find unused utun for main tunnel: %v", err)
					regResult = "failure"
					return
				}
			}
			n.tun, err = wtun.CreateTUN(mainIfName, n.config.MTU)
			if err != nil {
				logger.Error("Failed to create native main TUN device: %v", err)
				regResult = "failure"
				return
			}
			if realName, nameErr := n.tun.Name(); nameErr == nil {
				mainIfName = realName
			}
			n.tnet = nil
			n.config.NativeMainInterfaceName = mainIfName
		} else {
			n.tun, n.tnet, err = netstack.CreateNetTUN(
				[]netip.Addr{netip.MustParseAddr(n.wgData.TunnelIP)},
				[]netip.Addr{netip.MustParseAddr(n.config.DNS)},
				n.config.MTU)
			if err != nil {
				logger.Error("Failed to create TUN device: %v", err)
				regResult = "failure"
			}
		}

		n.setDownstreamTNetstack(n.tnet)

		n.dev = device.NewDevice(n.tun, conn.NewDefaultBind(), device.NewLogger(
			util.MapToWireGuardLogLevel(n.loggerLevel),
			"gerbil-wireguard: ",
		))

		host, _, err := net.SplitHostPort(n.wgData.Endpoint)
		if err != nil {
			logger.Error("Failed to split endpoint: %v", err)
			regResult = "failure"
			return
		}

		logger.Info("Connecting to endpoint: %s", host)

		resolvedEndpoint, err := util.ResolveDomain(n.wgData.Endpoint)
		if err != nil {
			logger.Error("Failed to resolve endpoint: %v", err)
			regResult = "failure"
			return
		}

		relayPort := n.wgData.RelayPort
		if relayPort == 0 {
			relayPort = 21820
		}

		n.clientsHandleNewtConnection(n.wgData.PublicKey, resolvedEndpoint, relayPort)

		wgConfig := fmt.Sprintf(`private_key=%s
public_key=%s
allowed_ip=%s/32
endpoint=%s
persistent_keepalive_interval=5`, util.FixKey(n.privateKey.String()), util.FixKey(n.wgData.PublicKey), n.wgData.ServerIP, resolvedEndpoint)

		if err = n.dev.IpcSet(wgConfig); err != nil {
			logger.Error("Failed to configure WireGuard device: %v", err)
			regResult = "failure"
		}

		if err = n.dev.Up(); err != nil {
			logger.Error("Failed to bring up WireGuard device: %v", err)
			regResult = "failure"
		}

		if n.config.UseNativeMainInterface {
			if cfgErr := network.ConfigureInterface(n.config.NativeMainInterfaceName, n.wgData.TunnelIP+"/32", n.config.MTU); cfgErr != nil {
				logger.Error("Failed to configure native main tunnel interface: %v", cfgErr)
			}
			if routeErr := network.AddRoutes([]string{n.wgData.ServerIP + "/32"}, n.config.NativeMainInterfaceName); routeErr != nil {
				logger.Warn("Failed to add route for main tunnel server IP: %v", routeErr)
			}
			if fileUAPI, uapiErr := newtDevice.UapiOpen(n.config.NativeMainInterfaceName); uapiErr != nil {
				logger.Warn("Main tunnel UAPI open error: %v", uapiErr)
			} else if uapiListener, uapiListenErr := newtDevice.UapiListen(n.config.NativeMainInterfaceName, fileUAPI); uapiListenErr != nil {
				logger.Warn("Main tunnel UAPI listen error: %v", uapiListenErr)
			} else {
				go func() {
					for {
						c, aErr := uapiListener.Accept()
						if aErr != nil {
							return
						}
						go n.dev.IpcHandle(c)
					}
				}()
				logger.Debug("Main tunnel UAPI listener started on %s", n.config.NativeMainInterfaceName)
			}
		}

		n.activeRemoteSubnets = nil
		if len(n.wgData.RemoteExitNodeSubnets) > 0 {
			for _, subnet := range n.wgData.RemoteExitNodeSubnets {
				subnetCfg := fmt.Sprintf("public_key=%s\nallowed_ip=%s", util.FixKey(n.wgData.PublicKey), subnet)
				if err := n.dev.IpcSet(subnetCfg); err != nil {
					logger.Warn("Failed to add AllowedIP %s to main tunnel: %v", subnet, err)
				}
			}
			if n.config.UseNativeMainInterface {
				if routeErr := network.AddRoutes(n.wgData.RemoteExitNodeSubnets, n.config.NativeMainInterfaceName); routeErr != nil {
					logger.Warn("Failed to add routes for remote exit node subnets: %v", routeErr)
				}
			}
			n.activeRemoteSubnets = append([]string{}, n.wgData.RemoteExitNodeSubnets...)
			logger.Debug("Added %d remote exit node subnets", len(n.wgData.RemoteExitNodeSubnets))
		}

		logger.Debug("WireGuard device created. Lets ping the server now...")

		if n.pingWithRetryStopChan != nil {
			close(n.pingWithRetryStopChan)
			n.pingWithRetryStopChan = nil
		}

		var pinger pingFunc
		if n.config.UseNativeMainInterface {
			pinger = pingNative
		} else {
			pinger = func(dst string, timeout time.Duration) (time.Duration, error) {
				return ping(n.tnet, dst, timeout)
			}
		}

		logger.Debug("Testing initial connection with reliable ping...")
		lat, err := reliablePing(pinger, n.wgData.ServerIP, n.config.PingTimeout, 5)
		if err == nil && n.wgData.PublicKey != "" {
			telemetry.ObserveTunnelLatency(ctx, n.wgData.PublicKey, "wireguard", lat.Seconds())
		}
		if err != nil {
			logger.Warn("Initial reliable ping failed, but continuing: %v", err)
			regResult = "failure"
		} else {
			logger.Debug("Initial connection test successful")
		}

		n.pingWithRetryStopChan, _ = n.pingWithRetry(pinger, n.wgData.ServerIP, n.config.PingTimeout)

		if !n.connected {
			logger.Debug("Starting ping check")
			n.pingStopChan = n.startPingCheck(pinger, n.wgData.ServerIP, n.wgData.PublicKey)
		}

		if n.config.UseNativeMainInterface {
			n.pm = proxy.NewProxyManagerNative(n.wgData.TunnelIP)
		} else {
			n.pm = proxy.NewProxyManager(n.tnet)
		}
		n.pm.SetAsyncBytes(n.config.MetricsAsyncBytes)
		n.pm.SetUDPIdleTimeout(n.config.UDPProxyIdleTimeout)
		n.pm.SetTunnelID(n.wgData.PublicKey)
		n.pm.SetBlocked(n.connectionBlocked.Load())
		n.currentPM.Store(n.pm)

		n.connected = true

		if len(n.wgData.Targets.TCP) > 0 {
			n.updateTargets(n.pm, "add", n.wgData.TunnelIP, "tcp", TargetData{Targets: n.wgData.Targets.TCP})
		}
		if len(n.wgData.Targets.UDP) > 0 {
			n.updateTargets(n.pm, "add", n.wgData.TunnelIP, "udp", TargetData{Targets: n.wgData.Targets.UDP})
		}

		if !n.config.UseNativeMainInterface {
			n.clientsStartDirectRelay(n.wgData.TunnelIP)
		}

		if err := n.healthMonitor.AddTargets(n.wgData.HealthCheckTargets); err != nil {
			logger.Error("Failed to bulk add health check targets: %v", err)
		} else {
			logger.Debug("Successfully added %d health check targets", len(n.wgData.HealthCheckTargets))
		}

		if err = n.pm.Start(); err != nil {
			logger.Error("Failed to start proxy manager: %v", err)
		}

		if len(n.wgData.BrowserGatewayTargets) > 0 {
			if n.browserGatewayStop != nil {
				n.browserGatewayStop()
				n.browserGatewayStop = nil
			}

			bgTargets := make([]browsergateway.Target, 0, len(n.wgData.BrowserGatewayTargets))
			for _, t := range n.wgData.BrowserGatewayTargets {
				bgTargets = append(bgTargets, browsergateway.Target{
					ID:              t.ID,
					Type:            t.Type,
					Destination:     t.Destination,
					DestinationPort: t.DestinationPort,
					AuthToken:       t.AuthToken,
				})
			}

			n.browserGateway = browsergateway.New(browsergateway.Config{SSHCredentials: n.sshCredStore})
			n.browserGateway.SetTargets(bgTargets)

			var ln net.Listener
			var bgErr error
			if n.config.UseNativeMainInterface {
				ln, bgErr = net.Listen("tcp", fmt.Sprintf("%s:%d", n.wgData.TunnelIP, browsergateway.ListenPort))
			} else {
				ln, bgErr = n.tnet.ListenTCP(&net.TCPAddr{Port: browsergateway.ListenPort})
			}
			if bgErr != nil {
				logger.Error("Failed to start browser gateway listener: %v", bgErr)
			} else {
				n.browserGatewayStop = func() { _ = ln.Close() }
				go func() {
					logger.Debug("Browser gateway started on port %d", browsergateway.ListenPort)
					if startErr := n.browserGateway.Start(ln); startErr != nil {
						logger.Error("Browser gateway stopped with error: %v", startErr)
					}
				}()
			}
		}
	})

	n.client.RegisterHandler("newt/wg/reconnect", func(msg websocket.WSMessage) {
		logger.Info("Received reconnect message")
		if n.wgData.PublicKey != "" {
			telemetry.IncReconnect(ctx, n.wgData.PublicKey, "server", telemetry.ReasonServerRequest)
		}

		n.closeWgTunnel()

		if n.pm != nil {
			n.pm.ClearTunnelID()
			state.Global().ClearTunnel(n.wgData.PublicKey)
		}

		n.connected = false

		if n.stopFunc != nil {
			n.stopFunc()
			n.stopFunc = nil
		}

		pingChainId := generateChainId()
		n.pendingPingChainId = pingChainId
		n.stopFunc = n.client.SendMessageInterval("newt/ping/request", map[string]interface{}{
			"noCloud": n.config.NoCloud,
			"chainId": pingChainId,
		}, 3*time.Second)

		logger.Info("Tunnel destroyed, ready for reconnection")
	})

	n.client.RegisterHandler("newt/wg/restart", func(msg websocket.WSMessage) {
		n.closeWgTunnel()
		n.closeClients()
		if n.healthMonitor != nil {
			n.healthMonitor.Stop()
		}
		n.client.Close()
		if n.config.OnRestart != nil {
			if err := n.config.OnRestart(); err != nil {
				logger.Error("Failed to restart: %v", err)
				os.Exit(1)
			}
		}
	})

	n.client.RegisterHandler("newt/wg/terminate", func(msg websocket.WSMessage) {
		logger.Info("Received termination message")
		if n.wgData.PublicKey != "" {
			telemetry.IncReconnect(ctx, n.wgData.PublicKey, "server", telemetry.ReasonServerRequest)
		}

		n.closeWgTunnel()
		n.closeClients()

		if n.stopFunc != nil {
			n.stopFunc()
			n.stopFunc = nil
		}

		n.connected = false

		logger.Info("Tunnel destroyed")
	})

	n.client.RegisterHandler("newt/ping/exitNodes", func(msg websocket.WSMessage) {
		logger.Debug("Received ping message")

		if n.stopFunc != nil {
			n.stopFunc()
			n.stopFunc = nil
		}

		var exitNodeData ExitNodeData

		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Info(fmtErrMarshaling, err)
			return
		}
		if err := json.Unmarshal(jsonData, &exitNodeData); err != nil {
			logger.Info("Error unmarshaling exit node data: %v", err)
			return
		}
		exitNodes := exitNodeData.ExitNodes

		if exitNodeData.ChainId != "" {
			if exitNodeData.ChainId != n.pendingPingChainId {
				logger.Debug("Discarding duplicate/stale newt/ping/exitNodes (chainId=%s, expected=%s)", exitNodeData.ChainId, n.pendingPingChainId)
				return
			}
			n.pendingPingChainId = ""
		}

		if len(exitNodes) == 0 {
			logger.Info("No exit nodes provided")
			return
		}

		if len(exitNodes) == 1 || n.config.PreferEndpoint != "" {
			logger.Debug("Only one exit node available, using it directly: %s", exitNodes[0].Endpoint)

			if n.config.PreferEndpoint != "" {
				for _, node := range exitNodes {
					if node.Endpoint == n.config.PreferEndpoint {
						exitNodes[0] = node
						break
					}
				}
			}

			pingResults := []ExitNodePingResult{
				{
					ExitNodeID:             exitNodes[0].ID,
					LatencyMs:              0,
					Weight:                 exitNodes[0].Weight,
					Error:                  "",
					Name:                   exitNodes[0].Name,
					Endpoint:               exitNodes[0].Endpoint,
					WasPreviouslyConnected: exitNodes[0].WasPreviouslyConnected,
				},
			}

			chainId := generateChainId()
			n.pendingRegisterChainId = chainId
			n.stopFunc = n.client.SendMessageInterval(topicWGRegister, map[string]interface{}{
				"publicKey":   n.publicKey.String(),
				"pingResults": pingResults,
				"newtVersion": n.config.Version,
				"chainId":     chainId,
			}, 2*time.Second)

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
			var totalLatency time.Duration
			var lastErr error
			successes := 0
			httpClient := &http.Client{
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
				resp, err := httpClient.Get(url)
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

		if n.connected {
			var filteredPingResults []ExitNodePingResult
			previouslyConnectedNodeIdx := -1
			for i, res := range pingResults {
				if res.WasPreviouslyConnected {
					previouslyConnectedNodeIdx = i
				}
			}
			goodNodeCount := 0
			for i, res := range pingResults {
				if i != previouslyConnectedNodeIdx && res.LatencyMs > 0 && res.Error == "" {
					goodNodeCount++
				}
			}
			if previouslyConnectedNodeIdx != -1 && goodNodeCount > 0 {
				for i, res := range pingResults {
					if i != previouslyConnectedNodeIdx {
						filteredPingResults = append(filteredPingResults, res)
					}
				}
				pingResults = filteredPingResults
				logger.Info("Excluding previously connected exit node from ping results due to other available nodes")
			}
		}

		chainId := generateChainId()
		n.pendingRegisterChainId = chainId
		n.stopFunc = n.client.SendMessageInterval(topicWGRegister, map[string]interface{}{
			"publicKey":   n.publicKey.String(),
			"pingResults": pingResults,
			"newtVersion": n.config.Version,
			"chainId":     chainId,
		}, 2*time.Second)

		logger.Debug("Sent exit node ping results to cloud for selection: pingResults=%+v", pingResults)
	})

	n.client.RegisterHandler("newt/tcp/add", func(msg websocket.WSMessage) {
		logger.Debug(fmtReceivedMsg, msg)

		if n.wgData.TunnelIP == "" || n.pm == nil {
			logger.Info(msgNoTunnelOrProxy)
			return
		}

		targetData, err := parseTargetData(msg.Data)
		if err != nil {
			logger.Info(fmtErrParsingTargetData, err)
			return
		}

		if len(targetData.Targets) > 0 {
			n.updateTargets(n.pm, "add", n.wgData.TunnelIP, "tcp", targetData)
		}
	})

	n.client.RegisterHandler("newt/udp/add", func(msg websocket.WSMessage) {
		logger.Info(fmtReceivedMsg, msg)

		if n.wgData.TunnelIP == "" || n.pm == nil {
			logger.Info(msgNoTunnelOrProxy)
			return
		}

		targetData, err := parseTargetData(msg.Data)
		if err != nil {
			logger.Info(fmtErrParsingTargetData, err)
			return
		}

		if len(targetData.Targets) > 0 {
			n.updateTargets(n.pm, "add", n.wgData.TunnelIP, "udp", targetData)
		}
	})

	n.client.RegisterHandler("newt/udp/remove", func(msg websocket.WSMessage) {
		logger.Info(fmtReceivedMsg, msg)

		if n.wgData.TunnelIP == "" || n.pm == nil {
			logger.Info(msgNoTunnelOrProxy)
			return
		}

		targetData, err := parseTargetData(msg.Data)
		if err != nil {
			logger.Info(fmtErrParsingTargetData, err)
			return
		}

		if len(targetData.Targets) > 0 {
			n.updateTargets(n.pm, "remove", n.wgData.TunnelIP, "udp", targetData)
		}
	})

	n.client.RegisterHandler("newt/tcp/remove", func(msg websocket.WSMessage) {
		logger.Info(fmtReceivedMsg, msg)

		if n.wgData.TunnelIP == "" || n.pm == nil {
			logger.Info(msgNoTunnelOrProxy)
			return
		}

		targetData, err := parseTargetData(msg.Data)
		if err != nil {
			logger.Info(fmtErrParsingTargetData, err)
			return
		}

		if len(targetData.Targets) > 0 {
			n.updateTargets(n.pm, "remove", n.wgData.TunnelIP, "tcp", targetData)
		}
	})

	n.client.RegisterHandler("newt/wg/subnets/add", func(msg websocket.WSMessage) {
		logger.Debug("Received subnet add message")

		var data struct {
			Subnets []string `json:"subnets"`
		}
		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Error("Error marshaling subnet add data: %v", err)
			return
		}
		if err := json.Unmarshal(jsonData, &data); err != nil {
			logger.Error("Error unmarshaling subnet add data: %v", err)
			return
		}
		if len(data.Subnets) == 0 || n.dev == nil {
			return
		}

		for _, subnet := range data.Subnets {
			subnetCfg := fmt.Sprintf("public_key=%s\nallowed_ip=%s", util.FixKey(n.wgData.PublicKey), subnet)
			if err := n.dev.IpcSet(subnetCfg); err != nil {
				logger.Warn("Failed to add AllowedIP %s to main tunnel: %v", subnet, err)
			}
		}
		if n.config.UseNativeMainInterface {
			if err := network.AddRoutes(data.Subnets, n.config.NativeMainInterfaceName); err != nil {
				logger.Warn("Failed to add routes for subnets: %v", err)
			}
		}
		n.activeRemoteSubnets = append(n.activeRemoteSubnets, data.Subnets...)
		logger.Info("Added %d remote exit node subnets", len(data.Subnets))
	})

	n.client.RegisterHandler("newt/wg/subnets/update", func(msg websocket.WSMessage) {
		logger.Debug("Received subnet update message")

		var data struct {
			Subnets []string `json:"subnets"`
		}
		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Error("Error marshaling subnet update data: %v", err)
			return
		}
		if err := json.Unmarshal(jsonData, &data); err != nil {
			logger.Error("Error unmarshaling subnet update data: %v", err)
			return
		}
		if n.dev == nil {
			return
		}

		if n.config.UseNativeMainInterface && len(n.activeRemoteSubnets) > 0 {
			toRemove := make([]string, 0)
			newSet := make(map[string]bool, len(data.Subnets))
			for _, s := range data.Subnets {
				newSet[s] = true
			}
			for _, s := range n.activeRemoteSubnets {
				if !newSet[s] {
					toRemove = append(toRemove, s)
				}
			}
			if len(toRemove) > 0 {
				if err := network.RemoveRoutes(toRemove); err != nil {
					logger.Warn("Failed to remove old subnet routes: %v", err)
				}
			}
		}

		if n.wgData.PublicKey != "" {
			lines := fmt.Sprintf("public_key=%s\nreplace_allowed_ips=true\nallowed_ip=%s/32",
				util.FixKey(n.wgData.PublicKey), n.wgData.ServerIP)
			for _, s := range data.Subnets {
				lines += "\nallowed_ip=" + s
			}
			if err := n.dev.IpcSet(lines); err != nil {
				logger.Warn("Failed to update WireGuard AllowedIPs: %v", err)
			}
		}

		if n.config.UseNativeMainInterface && len(data.Subnets) > 0 {
			existing := make(map[string]bool, len(n.activeRemoteSubnets))
			for _, s := range n.activeRemoteSubnets {
				existing[s] = true
			}
			toAdd := make([]string, 0)
			for _, s := range data.Subnets {
				if !existing[s] {
					toAdd = append(toAdd, s)
				}
			}
			if len(toAdd) > 0 {
				if err := network.AddRoutes(toAdd, n.config.NativeMainInterfaceName); err != nil {
					logger.Warn("Failed to add new subnet routes: %v", err)
				}
			}
		}

		n.activeRemoteSubnets = append([]string{}, data.Subnets...)
		logger.Info("Updated remote exit node subnets: %d total", len(data.Subnets))
	})

	n.client.RegisterHandler("newt/wg/subnets/remove", func(msg websocket.WSMessage) {
		logger.Debug("Received subnet remove message")

		var data struct {
			Subnets []string `json:"subnets"`
		}
		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Error("Error marshaling subnet remove data: %v", err)
			return
		}
		if err := json.Unmarshal(jsonData, &data); err != nil {
			logger.Error("Error unmarshaling subnet remove data: %v", err)
			return
		}
		if len(data.Subnets) == 0 {
			return
		}

		if n.config.UseNativeMainInterface {
			if err := network.RemoveRoutes(data.Subnets); err != nil {
				logger.Warn("Failed to remove routes for subnets: %v", err)
			}
		}

		toRemove := make(map[string]bool, len(data.Subnets))
		for _, s := range data.Subnets {
			toRemove[s] = true
		}
		remaining := n.activeRemoteSubnets[:0]
		for _, s := range n.activeRemoteSubnets {
			if !toRemove[s] {
				remaining = append(remaining, s)
			}
		}
		n.activeRemoteSubnets = remaining

		if n.dev != nil && n.wgData.PublicKey != "" {
			lines := fmt.Sprintf("public_key=%s\nreplace_allowed_ips=true\nallowed_ip=%s/32",
				util.FixKey(n.wgData.PublicKey), n.wgData.ServerIP)
			for _, s := range remaining {
				lines += "\nallowed_ip=" + s
			}
			if err := n.dev.IpcSet(lines); err != nil {
				logger.Warn("Failed to update WireGuard AllowedIPs after subnet removal: %v", err)
			}
		}
		logger.Info("Removed %d remote exit node subnets", len(data.Subnets))
	})

	n.client.RegisterHandler("newt/sync", func(msg websocket.WSMessage) {
		logger.Info("Received sync message")

		if n.wgData.TunnelIP == "" || n.pm == nil {
			logger.Info(msgNoTunnelOrProxy)
			return
		}

		type SyncData struct {
			Targets            TargetsByType        `json:"targets"`
			HealthCheckTargets []healthcheck.Config `json:"healthCheckTargets"`
		}

		var syncData SyncData
		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Error("Error marshaling sync data: %v", err)
			return
		}

		if err := json.Unmarshal(jsonData, &syncData); err != nil {
			logger.Error("Error unmarshaling sync data: %v", err)
			return
		}

		logger.Debug("Sync data received: TCP targets=%d, UDP targets=%d, health check targets=%d",
			len(syncData.Targets.TCP), len(syncData.Targets.UDP), len(syncData.HealthCheckTargets))

		logger.Info("Sync complete")
	})

	n.client.RegisterHandler("newt/socket/check", func(msg websocket.WSMessage) {
		logger.Debug("Received Docker socket check request")

		if n.config.DockerSocket == "" {
			logger.Debug("Docker socket path is not set")
			if err := n.client.SendMessage("newt/socket/status", map[string]interface{}{
				"available":  false,
				"socketPath": n.config.DockerSocket,
			}); err != nil {
				logger.Error("Failed to send Docker socket check response: %v", err)
			}
			return
		}

		isAvailable := docker.CheckSocket(n.config.DockerSocket)

		if err := n.client.SendMessage("newt/socket/status", map[string]interface{}{
			"available":  isAvailable,
			"socketPath": n.config.DockerSocket,
		}); err != nil {
			logger.Error("Failed to send Docker socket check response: %v", err)
		} else {
			logger.Debug("Docker socket check response sent: available=%t", isAvailable)
		}
	})

	n.client.RegisterHandler("newt/socket/fetch", func(msg websocket.WSMessage) {
		logger.Debug("Received Docker container fetch request")

		if n.config.DockerSocket == "" {
			logger.Debug("Docker socket path is not set")
			return
		}

		containers, err := docker.ListContainers(n.config.DockerSocket, n.config.DockerEnforceNetworkValidation)
		if err != nil {
			logger.Error("Failed to list Docker containers: %v", err)
			return
		}

		if err := n.client.SendMessage("newt/socket/containers", map[string]interface{}{
			"containers": containers,
		}); err != nil {
			logger.Error("Failed to send Docker container list: %v", err)
		} else {
			logger.Debug("Docker container list sent, count: %d", len(containers))
		}
	})

	n.client.RegisterHandler("newt/healthcheck/add", func(msg websocket.WSMessage) {
		logger.Debug("Received health check add request: %+v", msg)

		type HealthCheckConfig struct {
			Targets []healthcheck.Config `json:"targets"`
		}

		var config HealthCheckConfig
		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Error("Error marshaling health check data: %v", err)
			return
		}

		if err := json.Unmarshal(jsonData, &config); err != nil {
			logger.Error("Error unmarshaling health check config: %v", err)
			return
		}

		if err := n.healthMonitor.AddTargets(config.Targets); err != nil {
			logger.Error("Failed to add health check targets: %v", err)
		} else {
			logger.Debug("Added %d health check targets", len(config.Targets))
		}

		logger.Debug("Health check targets added: %+v", config.Targets)
	})

	n.client.RegisterHandler("newt/healthcheck/remove", func(msg websocket.WSMessage) {
		logger.Debug("Received health check remove request: %+v", msg)

		type HealthCheckConfig struct {
			IDs []int `json:"ids"`
		}

		var requestData HealthCheckConfig
		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Error("Error marshaling health check remove data: %v", err)
			return
		}

		if err := json.Unmarshal(jsonData, &requestData); err != nil {
			logger.Error("Error unmarshaling health check remove request: %v", err)
			return
		}

		if err := n.healthMonitor.RemoveTargets(requestData.IDs); err != nil {
			logger.Error("Failed to remove health check targets %v: %v", requestData.IDs, err)
		} else {
			logger.Info("Removed %d health check targets: %v", len(requestData.IDs), requestData.IDs)
		}
	})

	n.client.RegisterHandler("newt/healthcheck/enable", func(msg websocket.WSMessage) {
		logger.Debug("Received health check enable request: %+v", msg)

		var requestData struct {
			ID int `json:"id"`
		}
		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Error("Error marshaling health check enable data: %v", err)
			return
		}

		if err := json.Unmarshal(jsonData, &requestData); err != nil {
			logger.Error("Error unmarshaling health check enable request: %v", err)
			return
		}

		if err := n.healthMonitor.EnableTarget(requestData.ID); err != nil {
			logger.Error("Failed to enable health check target %d: %v", requestData.ID, err)
		} else {
			logger.Info("Enabled health check target: %d", requestData.ID)
		}
	})

	n.client.RegisterHandler("newt/healthcheck/disable", func(msg websocket.WSMessage) {
		logger.Debug("Received health check disable request: %+v", msg)

		var requestData struct {
			ID int `json:"id"`
		}
		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Error("Error marshaling health check disable data: %v", err)
			return
		}

		if err := json.Unmarshal(jsonData, &requestData); err != nil {
			logger.Error("Error unmarshaling health check disable request: %v", err)
			return
		}

		if err := n.healthMonitor.DisableTarget(requestData.ID); err != nil {
			logger.Error("Failed to disable health check target %d: %v", requestData.ID, err)
		} else {
			logger.Info("Disabled health check target: %d", requestData.ID)
		}
	})

	n.client.RegisterHandler("newt/healthcheck/status/request", func(msg websocket.WSMessage) {
		logger.Debug("Received health check status request")

		targets := n.healthMonitor.GetTargets()
		healthStatuses := make(map[int]interface{})
		for id, target := range targets {
			healthStatuses[id] = map[string]interface{}{
				"status":     target.Status.String(),
				"lastCheck":  target.LastCheck.Format(time.RFC3339),
				"checkCount": target.CheckCount,
				"lastError":  target.LastError,
				"config":     target.Config,
			}
		}

		if err := n.client.SendMessage("newt/healthcheck/status", map[string]interface{}{
			"targets": healthStatuses,
		}); err != nil {
			logger.Error("Failed to send health check status response: %v", err)
		}
	})

	n.client.RegisterHandler("newt/blueprint/results", func(msg websocket.WSMessage) {
		logger.Debug("Received blueprint results message")

		var blueprintResult BlueprintResult

		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Info("Error marshaling data: %v", err)
			return
		}
		if err := json.Unmarshal(jsonData, &blueprintResult); err != nil {
			logger.Info("Error unmarshaling config results data: %v", err)
			return
		}

		if blueprintResult.Success {
			logger.Debug("Blueprint applied successfully!")
		} else {
			logger.Warn("Blueprint application failed: %s", blueprintResult.Message)
		}
	})

	n.client.RegisterHandler("newt/pam/connection", func(msg websocket.WSMessage) {
		logger.Debug("Received SSH certificate issued message")

		type SSHCertData struct {
			MessageId          int    `json:"messageId"`
			AgentPort          int    `json:"agentPort"`
			AgentHost          string `json:"agentHost"`
			ExternalAuthDaemon bool   `json:"externalAuthDaemon"`
			AuthDaemonMode     string `json:"authDaemonMode"`
			CACert             string `json:"caCert"`
			Username           string `json:"username"`
			NiceID             string `json:"niceId"`
			Metadata           struct {
				SudoMode     string   `json:"sudoMode"`
				SudoCommands []string `json:"sudoCommands"`
				Homedir      bool     `json:"homedir"`
				Groups       []string `json:"groups"`
			} `json:"metadata"`
		}

		var certData SSHCertData
		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Error("Error marshaling SSH cert data: %v", err)
			return
		}

		logger.Debug("Received SSH cert data: %s", string(jsonData))

		if err := json.Unmarshal(jsonData, &certData); err != nil {
			logger.Error("Error unmarshaling SSH cert data: %v", err)
			return
		}

		authDaemonMode := "site"
		if certData.AuthDaemonMode != "" {
			authDaemonMode = certData.AuthDaemonMode
		} else if certData.ExternalAuthDaemon {
			authDaemonMode = "remote"
		}

		switch authDaemonMode {
		case "site":
			logger.Debug("Calling internal auth daemon ProcessConnection for user %s", certData.Username)

			if n.authDaemonServer != nil {
				n.authDaemonServer.ProcessConnection(authdaemon.ConnectionRequest{
					CaCert:   certData.CACert,
					NiceId:   certData.NiceID,
					Username: certData.Username,
					Metadata: authdaemon.ConnectionMetadata{
						SudoMode:     certData.Metadata.SudoMode,
						SudoCommands: certData.Metadata.SudoCommands,
						Homedir:      certData.Metadata.Homedir,
						Groups:       certData.Metadata.Groups,
					},
				})
				err = n.client.SendMessage("ws/round-trip/complete", map[string]interface{}{
					"messageId": certData.MessageId,
					"complete":  true,
				})
			} else {
				logger.Error("Auth daemon server is not initialized, cannot process connection")
				err = n.client.SendMessage("ws/round-trip/complete", map[string]interface{}{
					"messageId": certData.MessageId,
					"complete":  true,
					"error":     "auth daemon server not initialized (enable by running Newt site connector as root)",
				})
				if err != nil {
					logger.Error("Failed to send SSH cert failure response: %v", err)
				}
				return
			}

			logger.Info("Successfully processed connection via internal auth daemon for user %s", certData.Username)

		case "remote":
			if n.config.AuthDaemonKey == "" {
				logger.Error("Auth daemon key not configured, cannot communicate with daemon")
				if err := n.client.SendMessage("ws/round-trip/complete", map[string]interface{}{
					"messageId": certData.MessageId,
					"complete":  true,
					"error":     "auth daemon key not configured",
				}); err != nil {
					logger.Error("Failed to send SSH cert failure response: %v", err)
				}
				return
			}

			requestBody := map[string]interface{}{
				"caCert":   certData.CACert,
				"niceId":   certData.NiceID,
				"username": certData.Username,
				"metadata": map[string]interface{}{
					"sudoMode":     certData.Metadata.SudoMode,
					"sudoCommands": certData.Metadata.SudoCommands,
					"homedir":      certData.Metadata.Homedir,
					"groups":       certData.Metadata.Groups,
				},
			}

			requestJSON, err := json.Marshal(requestBody)
			if err != nil {
				logger.Error("Failed to marshal auth daemon request: %v", err)
				n.client.SendMessage("ws/round-trip/complete", map[string]interface{}{
					"messageId": certData.MessageId,
					"complete":  true,
					"error":     fmt.Sprintf("failed to marshal request: %v", err),
				})
				return
			}

			httpClient := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
				},
				Timeout: 10 * time.Second,
			}

			url := fmt.Sprintf("https://%s:%d/connection", certData.AgentHost, certData.AgentPort)
			req, err := http.NewRequest("POST", url, bytes.NewBuffer(requestJSON))
			if err != nil {
				logger.Error("Failed to create auth daemon request: %v", err)
				n.client.SendMessage("ws/round-trip/complete", map[string]interface{}{
					"messageId": certData.MessageId,
					"complete":  true,
					"error":     fmt.Sprintf("failed to create request: %v", err),
				})
				return
			}

			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+n.config.AuthDaemonKey)

			logger.Debug("Sending SSH cert to auth daemon at %s", url)

			resp, err := httpClient.Do(req)
			if err != nil {
				logger.Error("Failed to connect to auth daemon: %v", err)
				n.client.SendMessage("ws/round-trip/complete", map[string]interface{}{
					"messageId": certData.MessageId,
					"complete":  true,
					"error":     fmt.Sprintf("failed to connect to auth daemon: %v", err),
				})
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				logger.Error("Auth daemon returned non-OK status: %d", resp.StatusCode)
				n.client.SendMessage("ws/round-trip/complete", map[string]interface{}{
					"messageId": certData.MessageId,
					"complete":  true,
					"error":     fmt.Sprintf("auth daemon returned status %d", resp.StatusCode),
				})
				return
			}

			logger.Info("Successfully registered SSH certificate with external auth daemon for user %s", certData.Username)

		case "native":
			logger.Debug("Processing SSH cert for native SSH server for user %s", certData.Username)
			if n.authDaemonServer != nil && n.sshCredStore != nil {
				n.authDaemonServer.ProcessConnection(authdaemon.ConnectionRequest{
					CaCert:   "",
					NiceId:   "",
					Username: certData.Username,
					Metadata: authdaemon.ConnectionMetadata{
						SudoMode:     certData.Metadata.SudoMode,
						SudoCommands: certData.Metadata.SudoCommands,
						Homedir:      certData.Metadata.Homedir,
						Groups:       certData.Metadata.Groups,
					},
				})

				if err := n.sshCredStore.SetCAKey(certData.CACert); err != nil {
					logger.Error("nativessh: failed to set CA key: %v", err)
				}
				n.sshCredStore.AddPrincipals(certData.Username, certData.NiceID)
				logger.Info("nativessh: updated credentials for user %s (niceId=%s)", certData.Username, certData.NiceID)
			} else {
				logger.Error("Auth daemon server or SSH credential store not initialized, cannot process connection")
				err = n.client.SendMessage("ws/round-trip/complete", map[string]interface{}{
					"messageId": certData.MessageId,
					"complete":  true,
					"error":     "auth daemon server or SSH credential store not initialized",
				})
				if err != nil {
					logger.Error("Failed to send SSH cert failure response: %v", err)
				}
				return
			}

		default:
			logger.Error("Unknown auth daemon mode: %s", certData.AuthDaemonMode)
			n.client.SendMessage("ws/round-trip/complete", map[string]interface{}{
				"messageId": certData.MessageId,
				"complete":  true,
				"error":     fmt.Sprintf("unknown auth daemon mode: %s", certData.AuthDaemonMode),
			})
			return
		}

		if err = n.client.SendMessage("ws/round-trip/complete", map[string]interface{}{
			"messageId": certData.MessageId,
			"complete":  true,
		}); err != nil {
			logger.Error("Failed to send SSH cert success response: %v", err)
		}
	})

	n.client.RegisterHandler("newt/browsergateway/add", func(msg websocket.WSMessage) {
		logger.Debug("Received browser gateway add message")

		type BrowserGatewayAddData struct {
			Targets []BrowserGatewayTarget `json:"targets"`
		}

		var addData BrowserGatewayAddData
		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Error("Error marshaling browser gateway add data: %v", err)
			return
		}
		if err := json.Unmarshal(jsonData, &addData); err != nil {
			logger.Error("Error unmarshaling browser gateway add data: %v", err)
			return
		}

		if len(addData.Targets) == 0 {
			return
		}

		if n.browserGateway == nil && (n.tnet != nil || n.config.UseNativeMainInterface) {
			n.browserGateway = browsergateway.New(browsergateway.Config{SSHCredentials: n.sshCredStore})
			var ln net.Listener
			var bgErr error
			if n.config.UseNativeMainInterface {
				ln, bgErr = net.Listen("tcp", fmt.Sprintf("%s:%d", n.wgData.TunnelIP, browsergateway.ListenPort))
			} else {
				ln, bgErr = n.tnet.ListenTCP(&net.TCPAddr{Port: browsergateway.ListenPort})
			}
			if bgErr != nil {
				logger.Error("Failed to start browser gateway listener: %v", bgErr)
				n.browserGateway = nil
			} else {
				n.browserGatewayStop = func() { _ = ln.Close() }
				go func() {
					logger.Debug("Browser gateway started on port %d", browsergateway.ListenPort)
					if startErr := n.browserGateway.Start(ln); startErr != nil {
						logger.Error("Browser gateway stopped with error: %v", startErr)
					}
				}()
			}
		}

		if n.browserGateway == nil {
			logger.Warn("Browser gateway not available, cannot add targets")
			return
		}

		for _, t := range addData.Targets {
			n.browserGateway.AddTarget(browsergateway.Target{
				ID:              t.ID,
				Type:            t.Type,
				Destination:     t.Destination,
				DestinationPort: t.DestinationPort,
				AuthToken:       t.AuthToken,
			})
			logger.Debug("Added browser gateway target %d", t.ID)
		}
	})

	n.client.RegisterHandler("newt/browsergateway/remove", func(msg websocket.WSMessage) {
		logger.Debug("Received browser gateway remove message")

		type BrowserGatewayRemoveData struct {
			IDs []int `json:"ids"`
		}

		var removeData BrowserGatewayRemoveData
		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Error("Error marshaling browser gateway remove data: %v", err)
			return
		}
		if err := json.Unmarshal(jsonData, &removeData); err != nil {
			logger.Error("Error unmarshaling browser gateway remove data: %v", err)
			return
		}

		if n.browserGateway == nil {
			logger.Warn("Browser gateway not available, cannot remove targets")
			return
		}

		for _, id := range removeData.IDs {
			n.browserGateway.RemoveTarget(id)
			logger.Debug("Removed browser gateway target %d", id)
		}
	})

	n.client.OnConnect(func() error {
		n.publicKey = n.privateKey.PublicKey()
		logger.Debug("Public key: %s", n.publicKey)
		logger.Info("Websocket connected")

		if !n.connected {
			if n.stopFunc != nil {
				n.stopFunc()
			}
			pingChainId := generateChainId()
			n.pendingPingChainId = pingChainId
			n.stopFunc = n.client.SendMessageInterval("newt/ping/request", map[string]interface{}{
				"noCloud": n.config.NoCloud,
				"chainId": pingChainId,
			}, 3*time.Second)
			logger.Debug("Requesting exit nodes from server")

			if n.client.GetServerVersion() != "" {
				n.clientsOnConnect()
			} else {
				logger.Warn("CLIENTS WILL NOT WORK ON THIS VERSION OF NEWT WITH THIS VERSION OF PANGOLIN, PLEASE UPDATE THE SERVER TO 1.13 OR HIGHER OR DOWNGRADE NEWT")
			}

			sendBlueprint(n.client, n.config.BlueprintFile)
			if n.client.WasJustProvisioned() {
				logger.Info("Provisioning detected – sending provisioning blueprint")
				sendBlueprint(n.client, n.config.ProvisioningBlueprintFile)
			}
		} else {
			targets := n.healthMonitor.GetTargets()
			if len(targets) > 0 {
				healthStatuses := make(map[int]interface{})
				for id, target := range targets {
					healthStatuses[id] = map[string]interface{}{
						"status":     target.Status.String(),
						"lastCheck":  target.LastCheck.Format(time.RFC3339),
						"checkCount": target.CheckCount,
						"lastError":  target.LastError,
						"config":     target.Config,
					}
				}
				logger.Debug("Reconnected: resending health check status for %d targets", len(healthStatuses))
				if err := n.client.SendMessage("newt/healthcheck/status", map[string]interface{}{
					"targets": healthStatuses,
				}); err != nil {
					logger.Error("Failed to resend health check status on reconnect: %v", err)
				}
			}
		}

		bcChainId := generateChainId()
		n.pendingRegisterChainId = bcChainId
		if err := n.client.SendMessage(topicWGRegister, map[string]interface{}{
			"publicKey":           n.publicKey.String(),
			"newtVersion":         n.config.Version,
			"backwardsCompatible": true,
			"chainId":             bcChainId,
		}); err != nil {
			logger.Error("Failed to send registration message: %v", err)
			return err
		}

		return nil
	})

	// SIGHUP: reload config file and apply credential changes in place
	sighupChan := make(chan os.Signal, 1)
	signal.Notify(sighupChan, syscall.SIGHUP)
	go func() {
		defer signal.Stop(sighupChan)
		for {
			select {
			case <-sighupChan:
				logger.Info("SIGHUP received, reloading config...")
				cfgPath := n.client.GetConfigFilePath()
				data, err := os.ReadFile(cfgPath)
				if err != nil {
					logger.Error("Failed to read config file on SIGHUP: %v", err)
					continue
				}
				var newCfg websocket.Config
				if err := json.Unmarshal(data, &newCfg); err != nil {
					logger.Error("Failed to parse config file on SIGHUP: %v", err)
					continue
				}
				oldCfg := n.client.GetConfig()
				if newCfg.Endpoint != oldCfg.Endpoint || newCfg.ID != oldCfg.ID || newCfg.Secret != oldCfg.Secret {
					logger.Info("Config credentials changed (endpoint/id/secret), restarting...")
					n.closeWgTunnel()
					n.closeClients()
					if n.healthMonitor != nil {
						n.healthMonitor.Stop()
					}
					n.client.Close()
					if n.config.OnRestart != nil {
						if err := n.config.OnRestart(); err != nil {
							logger.Error("Failed to restart: %v", err)
							os.Exit(1)
						}
					}
				}
				if newCfg.Blocked != n.connectionBlocked.Load() {
					n.connectionBlocked.Store(newCfg.Blocked)
					if newCfg.Blocked {
						logger.Debug("Config reload: connection blocking enabled")
					} else {
						logger.Debug("Config reload: connection blocking disabled")
					}
					if p := n.currentPM.Load(); p != nil {
						p.SetBlocked(newCfg.Blocked)
					}
					n.setClientsBlocked(newCfg.Blocked)
				} else {
					logger.Debug("Config reload: no relevant changes detected")
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}
