package newt

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"time"

	"github.com/fosrl/newt/browsergateway"
	newtDevice "github.com/fosrl/newt/device"
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

func (n *Newt) handleConnect(ctx context.Context, msg websocket.WSMessage) {
	n.lifecycleMu.Lock()
	defer n.lifecycleMu.Unlock()
	if n.stopping.Load() || ctx.Err() != nil {
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	connectionReady := false
	defer func() {
		if !connectionReady {
			cancel()
		}
	}()
	if n.shutdownCtx != nil {
		stop := context.AfterFunc(n.shutdownCtx, cancel)
		defer stop()
	}
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

	n.closeWgTunnelLocked()
	if n.stopFunc != nil {
		n.stopFunc()
		n.stopFunc = nil
	}

	defer func() {
		if !connectionReady {
			retry := ctx.Err() == nil
			n.closeWgTunnelLocked()
			if retry {
				n.requestKernelReconnect()
			}
		}
	}()

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

	if n.config.UseKernelMainInterface {
		if err := n.openKernelMain(ctx, resolvedEndpoint); err != nil {
			logger.Error("Failed to create kernel main tunnel: %v", err)
			regResult = "failure"
			return
		}
		logger.Info("Main tunnel uses Linux kernel WireGuard on %s", n.config.NativeMainInterfaceName)
	} else {
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
				return
			}
		}

		n.dev = device.NewDevice(n.tun, conn.NewDefaultBind(), device.NewLogger(
			util.MapToWireGuardLogLevel(n.loggerLevel),
			"gerbil-wireguard: ",
		))
	}

	if ctx.Err() != nil {
		regResult = "failure"
		return
	}
	n.setDownstreamTNetstack(n.tnet)

	relayPort := n.wgData.RelayPort
	if relayPort == 0 {
		relayPort = 21820
	}

	n.clientsHandleNewtConnection(n.wgData.PublicKey, resolvedEndpoint, relayPort)

	if n.dev != nil {
		wgConfig := fmt.Sprintf(`private_key=%s
public_key=%s
allowed_ip=%s/32
endpoint=%s
persistent_keepalive_interval=5`, util.FixKey(n.privateKey.String()), util.FixKey(n.wgData.PublicKey), n.wgData.ServerIP, resolvedEndpoint)

		if err = n.dev.IpcSet(wgConfig); err != nil {
			logger.Error("Failed to configure WireGuard device: %v", err)
			regResult = "failure"
			return
		}

		if err = n.dev.Up(); err != nil {
			logger.Error("Failed to bring up WireGuard device: %v", err)
			regResult = "failure"
			return
		}
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
			fileUAPI.Close()
			logger.Warn("Main tunnel UAPI listen error: %v", uapiListenErr)
		} else {
			n.mainUAPI = uapiListener
			dev := n.dev
			go func() {
				for {
					c, aErr := uapiListener.Accept()
					if aErr != nil {
						return
					}
					go dev.IpcHandle(c)
				}
			}()
			logger.Debug("Main tunnel UAPI listener started on %s", n.config.NativeMainInterfaceName)
		}
	}

	if !n.config.UseKernelMainInterface && len(n.wgData.RemoteExitNodeSubnets) > 0 {
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
	pingCtx, pingCancel := context.WithCancel(ctx)
	n.mainPingCancel = func() {
		pingCancel()
		cancel()
	}
	if n.config.UseKernelMainInterface {
		interfaceName := n.config.NativeMainInterfaceName
		pinger = func(dst string, timeout time.Duration) (time.Duration, error) {
			return pingKernel(pingCtx, interfaceName, dst, timeout)
		}
	} else if n.config.UseNativeMainInterface {
		pinger = func(dst string, timeout time.Duration) (time.Duration, error) {
			return pingNativeContext(pingCtx, dst, timeout)
		}
	} else {
		tnet := n.tnet
		pinger = func(dst string, timeout time.Duration) (time.Duration, error) {
			return pingContext(pingCtx, tnet, dst, timeout)
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
	if ctx.Err() != nil {
		regResult = "failure"
		return
	}

	n.pingWithRetryStopChan, _ = n.pingWithRetry(pinger, n.wgData.ServerIP, n.config.PingTimeout)
	if ctx.Err() != nil {
		regResult = "failure"
		return
	}

	if !n.connected {
		logger.Debug("Starting ping check")
		n.pingStopChan = n.startPingCheck(pinger, n.wgData.ServerIP, n.wgData.PublicKey)
	}

	if n.config.UsesHostMainInterface() {
		n.pm = proxy.NewProxyManagerNative(n.wgData.TunnelIP)
	} else {
		n.pm = proxy.NewProxyManager(n.tnet)
	}
	n.pm.SetAsyncBytes(n.config.MetricsAsyncBytes)
	n.pm.SetUDPIdleTimeout(n.config.UDPProxyIdleTimeout)
	n.pm.SetTunnelID(n.wgData.PublicKey)
	n.pm.SetBlocked(n.connectionBlocked.Load())
	n.currentPM.Store(n.pm)

	if len(n.wgData.Targets.TCP) > 0 {
		n.updateTargets(n.pm, "add", n.wgData.TunnelIP, "tcp", TargetData{Targets: n.wgData.Targets.TCP})
	}
	if len(n.wgData.Targets.UDP) > 0 {
		n.updateTargets(n.pm, "add", n.wgData.TunnelIP, "udp", TargetData{Targets: n.wgData.Targets.UDP})
	}

	if !n.config.UsesHostMainInterface() {
		n.clientsStartDirectRelay(n.wgData.TunnelIP)
	}

	if err := n.healthMonitor.AddTargets(n.wgData.HealthCheckTargets); err != nil {
		logger.Error("Failed to bulk add health check targets: %v", err)
	} else {
		logger.Debug("Successfully added %d health check targets", len(n.wgData.HealthCheckTargets))
	}

	if err = n.pm.Start(); err != nil {
		logger.Error("Failed to start proxy manager: %v", err)
		regResult = "failure"
		return
	}

	if len(n.wgData.BrowserGatewayTargets) > 0 {
		// The netstack is fresh on (re)connect, so any previously running
		// gateway listener is bound to a now-defunct interface - tear it down.
		if n.browserGatewayStop != nil {
			n.browserGatewayStop()
			n.browserGatewayStop = nil
			n.browserGateway = nil
		}

		if err := n.startBrowserGateway(); err != nil {
			logger.Error("Failed to start browser gateway listener: %v", err)
		} else {
			n.browserGateway.SetTargets(toBrowserGatewayTargets(n.wgData.BrowserGatewayTargets))
		}
	}
	n.connected = true
	connectionReady = true
}

// startBrowserGateway creates the browser gateway and its listener if one
// isn't already running. Callers that need to rebind to a fresh netstack
// (e.g. on reconnect) must stop and clear any existing gateway first.
func (n *Newt) startBrowserGateway() error {
	if n.browserGateway != nil {
		return nil
	}
	if n.tnet == nil && !n.config.UsesHostMainInterface() {
		return fmt.Errorf("netstack not ready")
	}

	gateway := browsergateway.New(browsergateway.Config{SSHCredentials: n.sshCredStore})

	var ln net.Listener
	var err error
	if n.config.UsesHostMainInterface() {
		ln, err = net.Listen("tcp", fmt.Sprintf("%s:%d", n.wgData.TunnelIP, browsergateway.ListenPort))
	} else {
		ln, err = n.tnet.ListenTCP(&net.TCPAddr{Port: browsergateway.ListenPort})
	}
	if err != nil {
		return err
	}

	n.browserGateway = gateway
	n.browserGatewayStop = func() { _ = ln.Close() }
	go func() {
		logger.Debug("Browser gateway started on port %d", browsergateway.ListenPort)
		if startErr := gateway.Start(ln); startErr != nil {
			logger.Error("Browser gateway stopped with error: %v", startErr)
		}
	}()

	return nil
}

// syncBrowserGatewayTargets reconciles the browser gateway's allowed
// destinations with the desired state received from a sync message.
// It lazily starts the gateway if targets are present and it isn't running
// yet, and clears the allow-list (without tearing down the listener) when
// no targets are desired.
func (n *Newt) syncBrowserGatewayTargets(targets []BrowserGatewayTarget) {
	bgTargets := toBrowserGatewayTargets(targets)

	if len(bgTargets) == 0 {
		if n.browserGateway != nil {
			n.browserGateway.SetTargets(nil)
		}
		return
	}

	if err := n.startBrowserGateway(); err != nil {
		logger.Error("Failed to start browser gateway: %v", err)
		return
	}

	n.browserGateway.SetTargets(bgTargets)
}

func toBrowserGatewayTargets(targets []BrowserGatewayTarget) []browsergateway.Target {
	bgTargets := make([]browsergateway.Target, 0, len(targets))
	for _, t := range targets {
		bgTargets = append(bgTargets, browsergateway.Target{
			ID:              t.ID,
			Type:            t.Type,
			Destination:     t.Destination,
			DestinationPort: t.DestinationPort,
			AuthToken:       t.AuthToken,
		})
	}
	return bgTargets
}
