package newt

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/fosrl/newt/authdaemon"
	"github.com/fosrl/newt/browsergateway"
	wgclients "github.com/fosrl/newt/clients"
	"github.com/fosrl/newt/docker"
	"github.com/fosrl/newt/healthcheck"
	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/nativessh"
	"github.com/fosrl/newt/proxy"
	"github.com/fosrl/newt/util"
	"github.com/fosrl/newt/websocket"
	"golang.zx2c4.com/wireguard/device"
	wtun "golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Newt holds all runtime state for a newt tunnel instance.
type Newt struct {
	config      Config
	client      *websocket.Client
	privateKey  wgtypes.Key
	publicKey   wgtypes.Key
	loggerLevel logger.LogLevel
	tlsOpt      websocket.ClientOption

	// WireGuard tunnel state
	tun  wtun.Device
	tnet *netstack.Net
	dev  *device.Device

	// Proxy / networking
	pm                  *proxy.ProxyManager
	currentPM           atomic.Pointer[proxy.ProxyManager]
	connectionBlocked   atomic.Bool
	activeRemoteSubnets []string

	// Ping state
	pingStopChan          chan struct{}
	pingWithRetryStopChan chan struct{}

	// Connection / messaging state
	connected              bool
	stopFunc               func()
	pendingRegisterChainId string
	pendingPingChainId     string

	// Browser gateway
	browserGateway     *browsergateway.Gateway
	browserGatewayStop func()

	// Health monitoring
	healthMonitor *healthcheck.Monitor

	// Downstream WireGuard client management
	wgService    *wgclients.WireGuardService
	ready        bool
	sshCredStore *nativessh.CredentialStore

	// Auth daemon (Linux only)
	authDaemonServer *authdaemon.Server

	// Docker monitoring
	dockerEventMonitor *docker.EventMonitor

	// Current tunnel data
	wgData WgData
}

// Init creates and initialises a Newt instance. It sets up the websocket
// client, generates WireGuard keys, and starts the auth daemon if enabled.
// Callers should invoke Start after any additional setup (telemetry, etc.).
func Init(ctx context.Context, cfg Config) (*Newt, error) {
	n := &Newt{config: cfg}

	n.loggerLevel = util.ParseLogLevel(cfg.LogLevel)

	if !cfg.DisableSSH {
		if err := n.startAuthDaemon(ctx); err != nil {
			logger.Warn("Did not start on site auth daemon: %v", err)
		}
	}

	logger.GetLogger().SetLevel(n.loggerLevel)

	if cfg.TLSPrivateKey != "" {
		logger.Warn("Using deprecated PKCS12 format for mTLS. Consider migrating to separate certificate files using --tls-client-cert-file, --tls-client-key, and --tls-client-ca")
	}

	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("generate private key: %w", err)
	}
	n.privateKey = privateKey

	if cfg.TLSClientCert != "" && cfg.TLSClientKey != "" {
		n.tlsOpt = websocket.WithTLSConfig(websocket.TLSConfig{
			ClientCertFile: cfg.TLSClientCert,
			ClientKeyFile:  cfg.TLSClientKey,
			CAFiles:        cfg.TLSClientCAs,
		})
		logger.Debug("Using separate certificate files for mTLS")
		logger.Debug("Client cert: %s", cfg.TLSClientCert)
		logger.Debug("Client key: %s", cfg.TLSClientKey)
		logger.Debug("CA files: %v", cfg.TLSClientCAs)
	} else if cfg.TLSPrivateKey != "" {
		n.tlsOpt = websocket.WithTLSConfig(websocket.TLSConfig{
			PKCS12File: cfg.TLSPrivateKey,
		})
		logger.Debug("Using PKCS12 file for mTLS: %s", cfg.TLSPrivateKey)
	}

	client, err := websocket.NewClient(
		"newt",
		cfg.ID,
		cfg.Secret,
		cfg.Endpoint,
		30*time.Second,
		n.tlsOpt,
		websocket.WithConfigFile(cfg.ConfigFile),
	)
	if err != nil {
		return nil, fmt.Errorf("create websocket client: %w", err)
	}
	n.client = client

	if cfg.ProvisioningKey != "" && client.GetConfig().ProvisioningKey == "" {
		client.GetConfig().ProvisioningKey = cfg.ProvisioningKey
	}
	if cfg.NewtName != "" && client.GetConfig().Name == "" {
		client.GetConfig().Name = cfg.NewtName
	}

	// Update config from resolved client values (provisioning / config file).
	n.config.Endpoint = client.GetConfig().Endpoint
	n.config.ID = client.GetConfig().ID
	n.config.Secret = client.GetConfig().Secret

	if !cfg.DisableSSH {
		n.sshCredStore = nativessh.NewCredentialStore()
	}

	return n, nil
}

// GetConfig returns the (potentially resolved) configuration.
func (n *Newt) GetConfig() Config {
	return n.config
}

// GetTLSClientOpt returns the websocket TLS option, so callers can reuse the
// same TLS configuration for other HTTP clients (e.g. self-update).
func (n *Newt) GetTLSClientOpt() websocket.ClientOption {
	return n.tlsOpt
}

// Start sets up all WebSocket handlers, connects to the server, and blocks
// until ctx is cancelled.
func (n *Newt) Start(ctx context.Context) {
	if !n.config.DisableClients {
		n.setupClients()
	}

	n.connectionBlocked.Store(n.client.GetConfig().Blocked)
	if n.connectionBlocked.Load() {
		logger.Info("Connection blocking is enabled (from config)")
		n.setClientsBlocked(true)
	}

	n.healthMonitor = healthcheck.NewMonitor(func(targets map[int]*healthcheck.Target) {
		logger.Debug("Health check status update for %d targets", len(targets))

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

		logger.Debug("Health check status: %+v", healthStatuses)

		if err := n.client.SendMessage("newt/healthcheck/status", map[string]interface{}{
			"targets": healthStatuses,
		}); err != nil {
			logger.Error("Failed to send health check status update: %v", err)
		}
	}, n.config.EnforceHealthcheckCert)

	n.registerHandlers(ctx)

	if err := n.client.Connect(); err != nil {
		logger.Fatal("Failed to connect to server: %v", err)
	}
	defer n.client.Close()

	if n.config.DockerSocket != "" {
		logger.Debug("Initializing Docker event monitoring")
		var err error
		n.dockerEventMonitor, err = docker.NewEventMonitor(
			n.config.DockerSocket,
			n.config.DockerEnforceNetworkValidation,
			func(containers []docker.Container) {
				logger.Debug("Docker event detected, sending updated container list (%d containers)", len(containers))
				if err := n.client.SendMessage("newt/socket/containers", map[string]interface{}{
					"containers": containers,
				}); err != nil {
					logger.Error("Failed to send updated container list after Docker event: %v", err)
				} else {
					logger.Debug("Updated container list sent successfully")
				}
			})
		if err != nil {
			logger.Error("Failed to create Docker event monitor: %v", err)
		} else {
			if err := n.dockerEventMonitor.Start(); err != nil {
				logger.Error("Failed to start Docker event monitoring: %v", err)
			} else {
				logger.Debug("Docker event monitoring started successfully")
			}
		}
	}

	if n.config.BlueprintFile != "" {
		go watchBlueprintFile(ctx, n.config.BlueprintFile, func() error {
			return sendBlueprint(n.client, n.config.BlueprintFile)
		})
	}

	<-ctx.Done()

	n.closeClients()

	if n.dockerEventMonitor != nil {
		n.dockerEventMonitor.Stop()
	}

	if n.healthMonitor != nil {
		n.healthMonitor.Stop()
	}

	if n.dev != nil {
		n.dev.Close()
	}

	if n.pm != nil {
		n.pm.Stop()
	}

	n.client.SendMessage("newt/disconnecting", map[string]any{})

	if n.client != nil {
		n.client.Close()
	}
	logger.Info("Exiting...")
}

// Close performs an emergency shutdown: closes the tunnel, clients, health
// monitor, and websocket connection. Typically used before re-exec.
func (n *Newt) Close() {
	n.closeWgTunnel()
	n.closeClients()
	if n.healthMonitor != nil {
		n.healthMonitor.Stop()
	}
	if n.client != nil {
		n.client.Close()
	}
}

func generateChainId() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
