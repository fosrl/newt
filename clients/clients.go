package clients

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fosrl/newt/bind"
	newtDevice "github.com/fosrl/newt/device"
	"github.com/fosrl/newt/holepunch"
	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/netstack2"
	"github.com/fosrl/newt/network"
	"github.com/fosrl/newt/util"
	"github.com/fosrl/newt/websocket"
	"github.com/fosrl/newt/wgtester"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/fosrl/newt/internal/telemetry"
)

type WgConfig struct {
	IpAddress string   `json:"ipAddress"`
	Peers     []Peer   `json:"peers"`
	Targets   []Target `json:"targets"`
}

type Target struct {
	SourcePrefix string      `json:"sourcePrefix"`
	DestPrefix   string      `json:"destPrefix"`
	RewriteTo    string      `json:"rewriteTo,omitempty"`
	DisableIcmp  bool        `json:"disableIcmp,omitempty"`
	PortRange    []PortRange `json:"portRange,omitempty"`
}

type PortRange struct {
	Min      uint16 `json:"min"`
	Max      uint16 `json:"max"`
	Protocol string `json:"protocol"` // "tcp" or "udp"
}

type Peer struct {
	PublicKey  string   `json:"publicKey"`
	AllowedIPs []string `json:"allowedIps"`
	Endpoint   string   `json:"endpoint"`
}

type PeerBandwidth struct {
	PublicKey string  `json:"publicKey"`
	BytesIn   float64 `json:"bytesIn"`
	BytesOut  float64 `json:"bytesOut"`
}

type PeerReading struct {
	BytesReceived    int64
	BytesTransmitted int64
	LastChecked      time.Time
}

type WireGuardService struct {
	interfaceName string
	mtu           int
	client        *websocket.Client
	config        WgConfig
	key           wgtypes.Key
	newtId        string
	lastReadings  map[string]PeerReading
	mu            sync.Mutex
	Port          uint16
	host          string
	serverPubKey  string
	token         string
	stopGetConfig func()
	// Netstack fields
	tun    tun.Device
	tnet   *netstack2.Net
	device *device.Device
	dns    []netip.Addr
	// Callback for when netstack is ready
	onNetstackReady func(*netstack2.Net)
	// Callback for when netstack is closed
	onNetstackClose func()
	othertnet       *netstack.Net
	// Proxy manager for tunnel
	TunnelIP string
	// Shared bind and holepunch manager
	sharedBind         *bind.SharedBind
	holePunchManager   *holepunch.Manager
	useNativeInterface bool
	// Direct UDP relay from main tunnel to clients' WireGuard
	directRelayStop    chan struct{}
	directRelayWg      sync.WaitGroup
	netstackListener   net.PacketConn
	netstackListenerMu sync.Mutex
	wgTesterServer     *wgtester.Server
}

func NewWireGuardService(interfaceName string, port uint16, mtu int, host string, newtId string, wsClient *websocket.Client, dns string, useNativeInterface bool) (*WireGuardService, error) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	if port == 0 {
		// Find an available port
		portRandom, err := util.FindAvailableUDPPort(49152, 65535)
		if err != nil {
			return nil, fmt.Errorf("error finding available port: %v", err)
		}
		port = uint16(portRandom)
	}

	// Create shared UDP socket for both holepunch and WireGuard
	localAddr := &net.UDPAddr{
		Port: int(port),
		IP:   net.IPv4zero,
	}

	udpConn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP socket: %v", err)
	}

	sharedBind, err := bind.New(udpConn)
	if err != nil {
		udpConn.Close()
		return nil, fmt.Errorf("failed to create shared bind: %v", err)
	}

	// Add a reference for the hole punch manager (creator already has one reference for WireGuard)
	sharedBind.AddRef()

	logger.Debug("Created shared UDP socket on port %d (refcount: %d)", port, sharedBind.GetRefCount())

	// Parse DNS addresses
	dnsAddrs := []netip.Addr{netip.MustParseAddr(dns)}

	service := &WireGuardService{
		interfaceName:      interfaceName,
		mtu:                mtu,
		client:             wsClient,
		key:                key,
		newtId:             newtId,
		host:               host,
		lastReadings:       make(map[string]PeerReading),
		Port:               port,
		dns:                dnsAddrs,
		sharedBind:         sharedBind,
		useNativeInterface: useNativeInterface,
	}

	// Create the holepunch manager with ResolveDomain function
	// We'll need to pass a domain resolver function
	service.holePunchManager = holepunch.NewManager(sharedBind, newtId, "newt", key.PublicKey().String())

	// Register websocket handlers
	wsClient.RegisterHandler("newt/wg/receive-config", service.handleConfig)
	wsClient.RegisterHandler("newt/wg/peer/add", service.handleAddPeer)
	wsClient.RegisterHandler("newt/wg/peer/remove", service.handleRemovePeer)
	wsClient.RegisterHandler("newt/wg/peer/update", service.handleUpdatePeer)
	wsClient.RegisterHandler("newt/wg/targets/add", service.handleAddTarget)
	wsClient.RegisterHandler("newt/wg/targets/remove", service.handleRemoveTarget)
	wsClient.RegisterHandler("newt/wg/targets/update", service.handleUpdateTarget)
	wsClient.RegisterHandler("newt/wg/sync", service.handleSyncConfig)

	return service, nil
}

// ReportRTT allows reporting native RTTs to telemetry, rate-limited externally.
func (s *WireGuardService) ReportRTT(seconds float64) {
	if s.serverPubKey == "" {
		return
	}
	telemetry.ObserveTunnelLatency(context.Background(), s.serverPubKey, "wireguard", seconds)
}

func (s *WireGuardService) SetOthertnet(tnet *netstack.Net) {
	s.othertnet = tnet
}

func (s *WireGuardService) Close() {
	if s.stopGetConfig != nil {
		s.stopGetConfig()
		s.stopGetConfig = nil
	}

	// Stop the direct UDP relay first
	s.StopDirectUDPRelay()

	// Stop hole punch manager
	if s.holePunchManager != nil {
		s.holePunchManager.Stop()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Close WireGuard device first - this will call sharedBind.Close() which releases WireGuard's reference
	if s.device != nil {
		s.device.Close()
		s.device = nil
	}

	// Clear references but don't manually close since device.Close() already did it
	if s.tnet != nil {
		s.tnet = nil
	}
	if s.tun != nil {
		s.tun = nil // Don't call tun.Close() here since device.Close() already closed it
	}

	// Release the hole punch reference to the shared bind
	if s.sharedBind != nil {
		// Release hole punch reference (WireGuard already released its reference via device.Close())
		logger.Debug("Releasing shared bind (refcount before release: %d)", s.sharedBind.GetRefCount())
		s.sharedBind.Release()
		s.sharedBind = nil
		logger.Info("Released shared UDP bind")
	}

	if s.wgTesterServer != nil {
		s.wgTesterServer.Stop()
		s.wgTesterServer = nil
	}
}

func (s *WireGuardService) SetToken(token string) {
	s.token = token
	if s.holePunchManager != nil {
		s.holePunchManager.SetToken(token)
	}
}

// GetNetstackNet returns the netstack network interface for use by other components
func (s *WireGuardService) GetNetstackNet() *netstack2.Net {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tnet
}

// IsReady returns true if the WireGuard service is ready to use
func (s *WireGuardService) IsReady() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.device != nil && s.tnet != nil
}

// GetPublicKey returns the public key of this WireGuard service
func (s *WireGuardService) GetPublicKey() wgtypes.Key {
	return s.key.PublicKey()
}

// SetOnNetstackReady sets a callback function to be called when the netstack interface is ready
func (s *WireGuardService) SetOnNetstackReady(callback func(*netstack2.Net)) {
	s.onNetstackReady = callback
}

func (s *WireGuardService) SetOnNetstackClose(callback func()) {
	s.onNetstackClose = callback
}

// StartHolepunch starts hole punching to a specific endpoint
func (s *WireGuardService) StartHolepunch(publicKey string, endpoint string, relayPort uint16) {
	if s.holePunchManager == nil {
		logger.Warn("Hole punch manager not initialized")
		return
	}

	if relayPort == 0 {
	    relayPort = 21820
	}

	// Convert websocket.ExitNode to holepunch.ExitNode
	hpExitNodes := []holepunch.ExitNode{
		{
			Endpoint:  endpoint,
			RelayPort: relayPort,
			PublicKey: publicKey,
		},
	}

	// Start hole punching using the manager
	if err := s.holePunchManager.StartMultipleExitNodes(hpExitNodes); err != nil {
		logger.Warn("Failed to start hole punch: %v", err)
	}

	logger.Debug("Starting hole punch to %s with public key: %s", endpoint, publicKey)
}

// StartDirectUDPRelay starts a direct UDP relay from the main tunnel netstack to the clients' WireGuard.
// This bypasses the proxy by listening on the main tunnel's netstack and forwarding packets
// directly to the SharedBind that feeds the clients' WireGuard device.
// Responses are automatically routed back through the netstack by the SharedBind.
// tunnelIP is the IP address to listen on within the main tunnel's netstack.
func (s *WireGuardService) StartDirectUDPRelay(tunnelIP string) error {
	if s.othertnet == nil {
		return fmt.Errorf("main tunnel netstack (othertnet) not set")
	}
	if s.sharedBind == nil {
		return fmt.Errorf("shared bind not initialized")
	}

	// Stop any existing relay
	s.StopDirectUDPRelay()

	s.directRelayStop = make(chan struct{})

	// Parse the tunnel IP
	ip := net.ParseIP(tunnelIP)
	if ip == nil {
		return fmt.Errorf("invalid tunnel IP: %s", tunnelIP)
	}

	// Listen on the main tunnel netstack for UDP packets destined for the clients' WireGuard port
	listenAddr := &net.UDPAddr{
		IP:   ip,
		Port: int(s.Port),
	}

	// Use othertnet (main tunnel's netstack) to listen
	listener, err := s.othertnet.ListenUDP(listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on main tunnel netstack: %v", err)
	}

	// Store the listener reference so we can close it later
	s.netstackListenerMu.Lock()
	s.netstackListener = listener
	s.netstackListenerMu.Unlock()

	// Set the netstack connection on the SharedBind so responses go back through the tunnel
	s.sharedBind.SetNetstackConn(listener)

	logger.Debug("Started direct UDP relay on %s:%d (bidirectional via SharedBind)", tunnelIP, s.Port)

	// Start the relay goroutine to read from netstack and inject into SharedBind
	s.directRelayWg.Add(1)
	go s.runDirectUDPRelay(listener)

	return nil
}

// runDirectUDPRelay handles receiving UDP packets from the main tunnel netstack
// and injecting them into the SharedBind for processing by WireGuard.
// Responses are handled automatically by SharedBind.Send() which routes them
// back through the netstack connection.
func (s *WireGuardService) runDirectUDPRelay(listener net.PacketConn) {
	defer s.directRelayWg.Done()
	// Note: Don't close listener here - it's also used by SharedBind for sending responses
	// It will be closed when the relay is stopped

	logger.Debug("Direct UDP relay started (bidirectional through SharedBind)")

	buf := make([]byte, 65535) // Max UDP packet size

	for {
		select {
		case <-s.directRelayStop:
			logger.Info("Stopping direct UDP relay")
			return
		default:
		}

		// Set a read deadline so we can check for stop signal periodically
		listener.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

		n, remoteAddr, err := listener.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // Just a timeout, check for stop and try again
			}
			if s.directRelayStop != nil {
				select {
				case <-s.directRelayStop:
					return // Stopped
				default:
				}
			}
			logger.Debug("Direct UDP relay read error: %v", err)
			continue
		}

		// Get the source address
		var srcAddrPort netip.AddrPort
		if udpAddr, ok := remoteAddr.(*net.UDPAddr); ok {
			srcAddrPort = udpAddr.AddrPort()
			// Unmap IPv4-in-IPv6 addresses to ensure consistency with parsed endpoints
			if srcAddrPort.Addr().Is4In6() {
				srcAddrPort = netip.AddrPortFrom(srcAddrPort.Addr().Unmap(), srcAddrPort.Port())
			}
		} else {
			logger.Debug("Unexpected address type in relay: %T", remoteAddr)
			continue
		}

		// Inject the packet directly into the SharedBind (also tracks this endpoint as netstack-sourced)
		if err := s.sharedBind.InjectPacket(buf[:n], srcAddrPort); err != nil {
			logger.Debug("Failed to inject packet into SharedBind: %v", err)
			continue
		}

		// logger.Debug("Relayed %d bytes from %s into WireGuard", n, srcAddrPort.String())
	}
}

// StopDirectUDPRelay stops the direct UDP relay and closes the netstack listener
func (s *WireGuardService) StopDirectUDPRelay() {
	if s.directRelayStop != nil {
		close(s.directRelayStop)
		s.directRelayWg.Wait()
		s.directRelayStop = nil
	}

	// Clear the netstack connection from SharedBind so responses don't try to use it
	if s.sharedBind != nil {
		s.sharedBind.ClearNetstackConn()
	}

	// Close the netstack listener
	s.netstackListenerMu.Lock()
	if s.netstackListener != nil {
		s.netstackListener.Close()
		s.netstackListener = nil
	}
	s.netstackListenerMu.Unlock()
}

func (s *WireGuardService) LoadRemoteConfig() error {
	if s.stopGetConfig != nil {
		s.stopGetConfig()
		s.stopGetConfig = nil
	}
	s.stopGetConfig = s.client.SendMessageInterval("newt/wg/get-config", map[string]interface{}{
		"publicKey": s.key.PublicKey().String(),
		"port":      s.Port,
	}, 2*time.Second)

	logger.Debug("Requesting WireGuard configuration from remote server")
	go s.periodicBandwidthCheck()

	return nil
}

func (s *WireGuardService) handleConfig(msg websocket.WSMessage) {
	var config WgConfig

	logger.Debug("Received message: %v", msg)
	logger.Debug("Received WireGuard clients configuration from remote server")

	jsonData, err := json.Marshal(msg.Data)
	if err != nil {
		logger.Info("Error marshaling data: %v", err)
		return
	}

	if err := json.Unmarshal(jsonData, &config); err != nil {
		logger.Info("Error unmarshaling target data: %v", err)
		return
	}
	s.config = config

	if s.stopGetConfig != nil {
		s.stopGetConfig()
		s.stopGetConfig = nil
	}

	// Ensure the WireGuard interface and peers are configured
	if err := s.ensureWireguardInterface(config); err != nil {
		logger.Error("Failed to ensure WireGuard interface: %v", err)
		logger.Error("Clients functionality will be disabled until the interface can be created")
		return
	}

	if err := s.ensureWireguardPeers(config.Peers); err != nil {
		logger.Error("Failed to ensure WireGuard peers: %v", err)
	}

	if err := s.ensureTargets(config.Targets); err != nil {
		logger.Error("Failed to ensure WireGuard targets: %v", err)
	}

	logger.Info("Client connectivity setup. Ready to accept connections from clients!")
}

// SyncConfig represents the configuration sent from server for syncing
type SyncConfig struct {
	Targets []Target `json:"targets"`
	Peers   []Peer   `json:"peers"`
}

func (s *WireGuardService) handleSyncConfig(msg websocket.WSMessage) {
	var syncConfig SyncConfig

	logger.Debug("Received sync message: %v", msg)
	logger.Info("Received sync configuration from remote server")

	jsonData, err := json.Marshal(msg.Data)
	if err != nil {
		logger.Error("Error marshaling sync data: %v", err)
		return
	}

	if err := json.Unmarshal(jsonData, &syncConfig); err != nil {
		logger.Error("Error unmarshaling sync data: %v", err)
		return
	}

	// Sync peers
	if err := s.syncPeers(syncConfig.Peers); err != nil {
		logger.Error("Failed to sync peers: %v", err)
	}

	// Sync targets
	if err := s.syncTargets(syncConfig.Targets); err != nil {
		logger.Error("Failed to sync targets: %v", err)
	}
}

// syncPeers synchronizes the current peers with the desired state
// It removes peers not in the desired list and adds missing ones
func (s *WireGuardService) syncPeers(desiredPeers []Peer) error {
	if s.device == nil {
		return fmt.Errorf("WireGuard device is not initialized")
	}

	// Get current peers from the device
	currentConfig, err := s.device.IpcGet()
	if err != nil {
		return fmt.Errorf("failed to get current device config: %v", err)
	}

	// Parse current peer public keys
	lines := strings.Split(currentConfig, "\n")
	currentPeerKeys := make(map[string]bool)
	for _, line := range lines {
		if strings.HasPrefix(line, "public_key=") {
			pubKey := strings.TrimPrefix(line, "public_key=")
			currentPeerKeys[pubKey] = true
		}
	}

	// Build a map of desired peers by their public key (normalized)
	desiredPeerMap := make(map[string]Peer)
	for _, peer := range desiredPeers {
		// Normalize the public key for comparison
		pubKey, err := wgtypes.ParseKey(peer.PublicKey)
		if err != nil {
			logger.Warn("Invalid public key in desired peers: %s", peer.PublicKey)
			continue
		}
		normalizedKey := util.FixKey(pubKey.String())
		desiredPeerMap[normalizedKey] = peer
	}

	// Remove peers that are not in the desired list
	for currentKey := range currentPeerKeys {
		if _, exists := desiredPeerMap[currentKey]; !exists {
			// Parse the key back to get the original format for removal
			removeConfig := fmt.Sprintf("public_key=%s\nremove=true", currentKey)
			if err := s.device.IpcSet(removeConfig); err != nil {
				logger.Warn("Failed to remove peer %s during sync: %v", currentKey, err)
			} else {
				logger.Info("Removed peer %s during sync", currentKey)
			}
		}
	}

	// Add peers that are missing
	for normalizedKey, peer := range desiredPeerMap {
		if _, exists := currentPeerKeys[normalizedKey]; !exists {
			if err := s.addPeerToDevice(peer); err != nil {
				logger.Warn("Failed to add peer %s during sync: %v", peer.PublicKey, err)
			} else {
				logger.Info("Added peer %s during sync", peer.PublicKey)
			}
		}
	}

	return nil
}

// syncTargets synchronizes the current targets with the desired state
// It removes targets not in the desired list and adds missing ones
func (s *WireGuardService) syncTargets(desiredTargets []Target) error {
	if s.tnet == nil {
		// Native interface mode - proxy features not available, skip silently
		logger.Debug("Skipping target sync - using native interface (no proxy support)")
		return nil
	}

	// Get current rules from the proxy handler
	currentRules := s.tnet.GetProxySubnetRules()

	// Build a map of current rules by source+dest prefix
	type ruleKey struct {
		sourcePrefix string
		destPrefix   string
	}
	currentRuleMap := make(map[ruleKey]bool)
	for _, rule := range currentRules {
		key := ruleKey{
			sourcePrefix: rule.SourcePrefix.String(),
			destPrefix:   rule.DestPrefix.String(),
		}
		currentRuleMap[key] = true
	}

	// Build a map of desired targets
	desiredTargetMap := make(map[ruleKey]Target)
	for _, target := range desiredTargets {
		key := ruleKey{
			sourcePrefix: target.SourcePrefix,
			destPrefix:   target.DestPrefix,
		}
		desiredTargetMap[key] = target
	}

	// Remove targets that are not in the desired list
	for _, rule := range currentRules {
		key := ruleKey{
			sourcePrefix: rule.SourcePrefix.String(),
			destPrefix:   rule.DestPrefix.String(),
		}
		if _, exists := desiredTargetMap[key]; !exists {
			s.tnet.RemoveProxySubnetRule(rule.SourcePrefix, rule.DestPrefix)
			logger.Info("Removed target %s -> %s during sync", rule.SourcePrefix.String(), rule.DestPrefix.String())
		}
	}

	// Add targets that are missing
	for key, target := range desiredTargetMap {
		if _, exists := currentRuleMap[key]; !exists {
			sourcePrefix, err := netip.ParsePrefix(target.SourcePrefix)
			if err != nil {
				logger.Warn("Invalid source prefix %s during sync: %v", target.SourcePrefix, err)
				continue
			}

			destPrefix, err := netip.ParsePrefix(target.DestPrefix)
			if err != nil {
				logger.Warn("Invalid dest prefix %s during sync: %v", target.DestPrefix, err)
				continue
			}

			var portRanges []netstack2.PortRange
			for _, pr := range target.PortRange {
				portRanges = append(portRanges, netstack2.PortRange{
					Min:      pr.Min,
					Max:      pr.Max,
					Protocol: pr.Protocol,
				})
			}

			s.tnet.AddProxySubnetRule(sourcePrefix, destPrefix, target.RewriteTo, portRanges, target.DisableIcmp)
			logger.Info("Added target %s -> %s during sync", target.SourcePrefix, target.DestPrefix)
		}
	}

	return nil
}

func (s *WireGuardService) ensureWireguardInterface(wgconfig WgConfig) error {
	s.mu.Lock()

	// split off the cidr from the IP address
	parts := strings.Split(wgconfig.IpAddress, "/")
	if len(parts) != 2 {
		s.mu.Unlock()
		return fmt.Errorf("invalid IP address format: %s", wgconfig.IpAddress)
	}
	// Parse the IP address and CIDR mask
	tunnelIP := netip.MustParseAddr(parts[0])

	var err error

	if s.useNativeInterface {
		// Create native TUN device
		var interfaceName = s.interfaceName
		if runtime.GOOS == "darwin" {
			interfaceName, err = network.FindUnusedUTUN()
			if err != nil {
				s.mu.Unlock()
				return fmt.Errorf("failed to find unused utun: %v", err)
			}
		}

		s.tun, err = tun.CreateTUN(interfaceName, s.mtu)
		if err != nil {
			s.mu.Unlock()
			return fmt.Errorf("failed to create native TUN device: %v", err)
		}

		// Get the real interface name (may differ on some platforms)
		if realName, err := s.tun.Name(); err == nil {
			interfaceName = realName
		}

		s.TunnelIP = tunnelIP.String()
		// s.tnet is nil for native interface - proxy features not available
		s.tnet = nil

		// Create WireGuard device using the shared bind
		s.device = device.NewDevice(s.tun, s.sharedBind, device.NewLogger(
			device.LogLevelSilent,
			"client-wireguard: ",
		))

		fileUAPI, err := func() (*os.File, error) {
			return newtDevice.UapiOpen(interfaceName)
		}()
		if err != nil {
			logger.Error("UAPI listen error: %v", err)
		}

		uapiListener, err := newtDevice.UapiListen(interfaceName, fileUAPI)
		if err != nil {
			logger.Error("Failed to listen on uapi socket: %v", err)
			os.Exit(1)
		}

		go func() {
			for {
				conn, err := uapiListener.Accept()
				if err != nil {

					return
				}
				go s.device.IpcHandle(conn)
			}
		}()
		logger.Info("UAPI listener started")

		// Configure WireGuard with private key
		config := fmt.Sprintf("private_key=%s", util.FixKey(s.key.String()))

		err = s.device.IpcSet(config)
		if err != nil {
			s.mu.Unlock()
			return fmt.Errorf("failed to configure WireGuard device: %v", err)
		}

		// Bring up the device
		err = s.device.Up()
		if err != nil {
			s.mu.Unlock()
			return fmt.Errorf("failed to bring up WireGuard device: %v", err)
		}

		// Configure the network interface with IP address
		if err := network.ConfigureInterface(interfaceName, wgconfig.IpAddress, s.mtu); err != nil {
			s.mu.Unlock()
			return fmt.Errorf("failed to configure interface: %v", err)
		}

		s.wgTesterServer = wgtester.NewServer("0.0.0.0", s.Port, s.newtId) // TODO: maybe make this the same ip of the wg server?
		err = s.wgTesterServer.Start()
		if err != nil {
			logger.Error("Failed to start WireGuard tester server: %v", err)
		}

		logger.Info("WireGuard native device created and configured on %s", interfaceName)

		s.mu.Unlock()
		return nil
	}

	// Create TUN device and network stack using netstack
	s.tun, s.tnet, err = netstack2.CreateNetTUNWithOptions(
		[]netip.Addr{tunnelIP},
		s.dns,
		s.mtu,
		netstack2.NetTunOptions{
			EnableTCPProxy:  true,
			EnableUDPProxy:  true,
			EnableICMPProxy: true,
		},
	)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("failed to create TUN device: %v", err)
	}

	s.TunnelIP = tunnelIP.String()

	// Create WireGuard device using the shared bind
	s.device = device.NewDevice(s.tun, s.sharedBind, device.NewLogger(
		device.LogLevelSilent, // Use silent logging by default - could be made configurable
		"wireguard: ",
	))

	// Configure WireGuard with private key
	config := fmt.Sprintf("private_key=%s", util.FixKey(s.key.String()))

	err = s.device.IpcSet(config)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("failed to configure WireGuard device: %v", err)
	}

	// Bring up the device
	err = s.device.Up()
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("failed to bring up WireGuard device: %v", err)
	}

	logger.Debug("WireGuard netstack device created and configured")

	// Release the mutex before calling the callback
	s.mu.Unlock()

	s.wgTesterServer = wgtester.NewServerWithNetstack("0.0.0.0", s.Port, s.newtId, s.tnet) // TODO: maybe make this the same ip of the wg server?
	err = s.wgTesterServer.Start()
	if err != nil {
		logger.Error("Failed to start WireGuard tester server: %v", err)
	}

	// Note: we already unlocked above, so don't use defer unlock
	return nil
}

func (s *WireGuardService) ensureWireguardPeers(peers []Peer) error {
	// For netstack, we need to manage peers differently
	// We'll configure peers directly on the device using IPC

	// Check if device is initialized
	if s.device == nil {
		return fmt.Errorf("WireGuard device is not initialized")
	}

	// First, clear all existing peers by getting current config and removing them
	currentConfig, err := s.device.IpcGet()
	if err != nil {
		return fmt.Errorf("failed to get current device config: %v", err)
	}

	// Parse current peers and remove them
	lines := strings.Split(currentConfig, "\n")
	var currentPeerKeys []string
	for _, line := range lines {
		if strings.HasPrefix(line, "public_key=") {
			pubKey := strings.TrimPrefix(line, "public_key=")
			currentPeerKeys = append(currentPeerKeys, pubKey)
		}
	}

	// Remove existing peers
	for _, pubKey := range currentPeerKeys {
		removeConfig := fmt.Sprintf("public_key=%s\nremove=true", pubKey)
		if err := s.device.IpcSet(removeConfig); err != nil {
			logger.Warn("Failed to remove peer %s: %v", pubKey, err)
		}
	}

	// Add new peers
	for _, peer := range peers {
		if err := s.addPeerToDevice(peer); err != nil {
			return fmt.Errorf("failed to add peer: %v", err)
		}
	}

	return nil
}

func (s *WireGuardService) ensureTargets(targets []Target) error {
	if s.tnet == nil {
		// Native interface mode - proxy features not available, skip silently
		logger.Debug("Skipping target configuration - using native interface (no proxy support)")
		return nil
	}

	for _, target := range targets {
		sourcePrefix, err := netip.ParsePrefix(target.SourcePrefix)
		if err != nil {
			return fmt.Errorf("invalid CIDR %s: %v", target.SourcePrefix, err)
		}

		destPrefix, err := netip.ParsePrefix(target.DestPrefix)
		if err != nil {
			return fmt.Errorf("invalid CIDR %s: %v", target.DestPrefix, err)
		}

		var portRanges []netstack2.PortRange
		for _, pr := range target.PortRange {
			portRanges = append(portRanges, netstack2.PortRange{
				Min:      pr.Min,
				Max:      pr.Max,
				Protocol: pr.Protocol,
			})
		}

		s.tnet.AddProxySubnetRule(sourcePrefix, destPrefix, target.RewriteTo, portRanges, target.DisableIcmp)

		logger.Info("Added target subnet from %s to %s rewrite to %s with port ranges: %v", target.SourcePrefix, target.DestPrefix, target.RewriteTo, target.PortRange)
	}

	return nil
}

func (s *WireGuardService) addPeerToDevice(peer Peer) error {
	// parse the key first
	pubKey, err := wgtypes.ParseKey(peer.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %v", err)
	}

	// Build IPC configuration string for the peer
	config := fmt.Sprintf("public_key=%s", util.FixKey(pubKey.String()))

	// Add allowed IPs
	for _, allowedIP := range peer.AllowedIPs {
		config += fmt.Sprintf("\nallowed_ip=%s", allowedIP)
	}

	// Add endpoint if specified
	if peer.Endpoint != "" {
		config += fmt.Sprintf("\nendpoint=%s", peer.Endpoint)
	}

	// Add persistent keepalive
	config += "\npersistent_keepalive_interval=25"

	// Apply the configuration
	if err := s.device.IpcSet(config); err != nil {
		return fmt.Errorf("failed to configure peer: %v", err)
	}

	logger.Info("Peer %s added successfully", peer.PublicKey)
	return nil
}

func (s *WireGuardService) handleAddPeer(msg websocket.WSMessage) {
	logger.Debug("Received message: %v", msg.Data)
	var peer Peer

	jsonData, err := json.Marshal(msg.Data)
	if err != nil {
		logger.Info("Error marshaling data: %v", err)
		return
	}

	if err := json.Unmarshal(jsonData, &peer); err != nil {
		logger.Info("Error unmarshaling target data: %v", err)
		return
	}

	if s.device == nil {
		logger.Info("WireGuard device is not initialized")
		return
	}

	s.holePunchManager.TriggerHolePunch()

	err = s.addPeerToDevice(peer)
	if err != nil {
		logger.Info("Error adding peer: %v", err)
		return
	}
}

func (s *WireGuardService) handleRemovePeer(msg websocket.WSMessage) {
	logger.Debug("Received message: %v", msg.Data)
	// parse the publicKey from the message which is json { "publicKey": "asdfasdfl;akjsdf" }
	type RemoveRequest struct {
		PublicKey string `json:"publicKey"`
	}

	jsonData, err := json.Marshal(msg.Data)
	if err != nil {
		logger.Info("Error marshaling data: %v", err)
		return
	}

	var request RemoveRequest
	if err := json.Unmarshal(jsonData, &request); err != nil {
		logger.Info("Error unmarshaling data: %v", err)
		return
	}

	if s.device == nil {
		logger.Info("WireGuard device is not initialized")
		return
	}

	if err := s.removePeer(request.PublicKey); err != nil {
		logger.Info("Error removing peer: %v", err)
		return
	}
}

func (s *WireGuardService) removePeer(publicKey string) error {

	// Parse the public key
	pubKey, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %v", err)
	}

	// Build IPC configuration string to remove the peer
	config := fmt.Sprintf("public_key=%s\nremove=true", util.FixKey(pubKey.String()))

	if err := s.device.IpcSet(config); err != nil {
		return fmt.Errorf("failed to remove peer: %v", err)
	}

	logger.Info("Peer %s removed successfully", publicKey)
	return nil
}

func (s *WireGuardService) handleUpdatePeer(msg websocket.WSMessage) {
	logger.Debug("Received message: %v", msg.Data)
	// Define a struct to match the incoming message structure with optional fields
	type UpdatePeerRequest struct {
		PublicKey  string   `json:"publicKey"`
		AllowedIPs []string `json:"allowedIps,omitempty"`
		Endpoint   string   `json:"endpoint,omitempty"`
	}

	jsonData, err := json.Marshal(msg.Data)
	if err != nil {
		logger.Info("Error marshaling data: %v", err)
		return
	}

	var request UpdatePeerRequest
	if err := json.Unmarshal(jsonData, &request); err != nil {
		logger.Info("Error unmarshaling peer data: %v", err)
		return
	}

	s.holePunchManager.TriggerHolePunch()

	// Parse the public key
	pubKey, err := wgtypes.ParseKey(request.PublicKey)
	if err != nil {
		logger.Info("Failed to parse public key: %v", err)
		return
	}

	if s.device == nil {
		logger.Info("WireGuard device is not initialized")
		return
	}

	// Build IPC configuration string to update the peer
	config := fmt.Sprintf("public_key=%s\nupdate_only=true", util.FixKey(pubKey.String()))

	// Handle AllowedIPs update
	if len(request.AllowedIPs) > 0 {
		config += "\nreplace_allowed_ips=true"
		for _, allowedIP := range request.AllowedIPs {
			config += fmt.Sprintf("\nallowed_ip=%s", allowedIP)
		}
		logger.Info("Updating AllowedIPs for peer %s", request.PublicKey)
	}

	// Handle Endpoint field special case
	endpointSpecified := false
	for key := range msg.Data.(map[string]interface{}) {
		if key == "endpoint" {
			endpointSpecified = true
			break
		}
	}

	if endpointSpecified {
		if request.Endpoint != "" {
			config += fmt.Sprintf("\nendpoint=%s", request.Endpoint)
			logger.Info("Updating Endpoint for peer %s to %s", request.PublicKey, request.Endpoint)
		} else {
			config += "\nendpoint=0.0.0.0:0" // Remove endpoint
			logger.Info("Removing Endpoint for peer %s", request.PublicKey)
		}
	}

	// Always set persistent keepalive
	config += "\npersistent_keepalive_interval=25"

	// Apply the configuration update
	if err := s.device.IpcSet(config); err != nil {
		logger.Info("Error updating peer configuration: %v", err)
		return
	}

	logger.Info("Peer %s updated successfully", request.PublicKey)
}

func (s *WireGuardService) periodicBandwidthCheck() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if err := s.reportPeerBandwidth(); err != nil {
			logger.Info("Failed to report peer bandwidth: %v", err)
		}
	}
}

func (s *WireGuardService) calculatePeerBandwidth() ([]PeerBandwidth, error) {
	if s.device == nil {
		return []PeerBandwidth{}, nil
	}

	// Get device statistics using IPC
	stats, err := s.device.IpcGet()
	if err != nil {
		return nil, fmt.Errorf("failed to get device statistics: %v", err)
	}

	peerBandwidths := []PeerBandwidth{}
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	// Parse the IPC response to extract peer statistics
	lines := strings.Split(stats, "\n")
	var currentPubKey string
	var rxBytes, txBytes int64

	for _, line := range lines {
		if strings.HasPrefix(line, "public_key=") {
			// Process previous peer if we have one
			if currentPubKey != "" {
				bandwidth := s.processPeerBandwidth(currentPubKey, rxBytes, txBytes, now)
				if bandwidth != nil {
					peerBandwidths = append(peerBandwidths, *bandwidth)
				}
			}
			// Start new peer
			currentPubKey = strings.TrimPrefix(line, "public_key=")
			rxBytes = 0
			txBytes = 0
		} else if strings.HasPrefix(line, "rx_bytes=") {
			rxBytes, _ = strconv.ParseInt(strings.TrimPrefix(line, "rx_bytes="), 10, 64)
		} else if strings.HasPrefix(line, "tx_bytes=") {
			txBytes, _ = strconv.ParseInt(strings.TrimPrefix(line, "tx_bytes="), 10, 64)
		}
	}

	// Process the last peer
	if currentPubKey != "" {
		bandwidth := s.processPeerBandwidth(currentPubKey, rxBytes, txBytes, now)
		if bandwidth != nil {
			peerBandwidths = append(peerBandwidths, *bandwidth)
		}
	}

	// Clean up old peers
	devicePeers := make(map[string]bool)
	lines = strings.Split(stats, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "public_key=") {
			pubKey := strings.TrimPrefix(line, "public_key=")
			devicePeers[pubKey] = true
		}
	}

	for publicKey := range s.lastReadings {
		if !devicePeers[publicKey] {
			delete(s.lastReadings, publicKey)
		}
	}

	// parse the public keys and have them as base64 in the opposite order to fixKey
	for i := range peerBandwidths {
		peerBandwidths[i].PublicKey = util.UnfixKey(peerBandwidths[i].PublicKey) // its in the long form but we need base64
	}

	return peerBandwidths, nil
}

func (s *WireGuardService) processPeerBandwidth(publicKey string, rxBytes, txBytes int64, now time.Time) *PeerBandwidth {
	currentReading := PeerReading{
		BytesReceived:    rxBytes,
		BytesTransmitted: txBytes,
		LastChecked:      now,
	}

	var bytesInDiff, bytesOutDiff float64
	lastReading, exists := s.lastReadings[publicKey]

	if exists {
		timeDiff := currentReading.LastChecked.Sub(lastReading.LastChecked).Seconds()
		if timeDiff > 0 {
			// Calculate bytes transferred since last reading
			bytesInDiff = float64(currentReading.BytesReceived - lastReading.BytesReceived)
			bytesOutDiff = float64(currentReading.BytesTransmitted - lastReading.BytesTransmitted)

			// Handle counter wraparound (if the counter resets or overflows)
			if bytesInDiff < 0 {
				bytesInDiff = float64(currentReading.BytesReceived)
			}
			if bytesOutDiff < 0 {
				bytesOutDiff = float64(currentReading.BytesTransmitted)
			}

			// Convert to MB
			bytesInMB := bytesInDiff / (1024 * 1024)
			bytesOutMB := bytesOutDiff / (1024 * 1024)

			// Update the last reading
			s.lastReadings[publicKey] = currentReading

			return &PeerBandwidth{
				PublicKey: publicKey,
				BytesIn:   bytesInMB,
				BytesOut:  bytesOutMB,
			}
		}
	}

	// For first reading or if readings are too close together, report 0
	s.lastReadings[publicKey] = currentReading
	return &PeerBandwidth{
		PublicKey: publicKey,
		BytesIn:   0,
		BytesOut:  0,
	}
}

func (s *WireGuardService) reportPeerBandwidth() error {
	bandwidths, err := s.calculatePeerBandwidth()
	if err != nil {
		return fmt.Errorf("failed to calculate peer bandwidth: %v", err)
	}

	err = s.client.SendMessageNoLog("newt/receive-bandwidth", map[string]interface{}{
		"bandwidthData": bandwidths,
	})
	if err != nil {
		return fmt.Errorf("failed to send bandwidth data: %v", err)
	}

	return nil
}

// filterReadOnlyFields removes read-only fields from WireGuard IPC configuration
func (s *WireGuardService) handleAddTarget(msg websocket.WSMessage) {
	logger.Debug("Received message: %v", msg.Data)

	jsonData, err := json.Marshal(msg.Data)
	if err != nil {
		logger.Info("Error marshaling data: %v", err)
		return
	}

	if s.tnet == nil {
		// Native interface mode - proxy features not available, skip silently
		logger.Debug("Skipping add target - using native interface (no proxy support)")
		return
	}

	// Try to unmarshal as array first
	var targets []Target
	if err := json.Unmarshal(jsonData, &targets); err != nil {
		logger.Warn("Error unmarshaling target data: %v", err)
		return
	}

	// Process all targets
	for _, target := range targets {
		sourcePrefix, err := netip.ParsePrefix(target.SourcePrefix)
		if err != nil {
			logger.Info("Invalid CIDR %s: %v", target.SourcePrefix, err)
			continue
		}

		destPrefix, err := netip.ParsePrefix(target.DestPrefix)
		if err != nil {
			logger.Info("Invalid CIDR %s: %v", target.DestPrefix, err)
			continue
		}

		var portRanges []netstack2.PortRange
		for _, pr := range target.PortRange {
			portRanges = append(portRanges, netstack2.PortRange{
				Min: pr.Min,
				Max: pr.Max,
				Protocol:    pr.Protocol,
			})
		}

		s.tnet.AddProxySubnetRule(sourcePrefix, destPrefix, target.RewriteTo, portRanges, target.DisableIcmp)

		logger.Info("Added target subnet from %s to %s rewrite to %s with port ranges: %v", target.SourcePrefix, target.DestPrefix, target.RewriteTo, target.PortRange)
	}
}

// filterReadOnlyFields removes read-only fields from WireGuard IPC configuration
func (s *WireGuardService) handleRemoveTarget(msg websocket.WSMessage) {
	logger.Debug("Received message: %v", msg.Data)

	jsonData, err := json.Marshal(msg.Data)
	if err != nil {
		logger.Info("Error marshaling data: %v", err)
		return
	}

	if s.tnet == nil {
		// Native interface mode - proxy features not available, skip silently
		logger.Debug("Skipping remove target - using native interface (no proxy support)")
		return
	}

	// Try to unmarshal as array first
	var targets []Target
	if err := json.Unmarshal(jsonData, &targets); err != nil {
		logger.Warn("Error unmarshaling target data: %v", err)
		return
	}

	// Process all targets
	for _, target := range targets {
		sourcePrefix, err := netip.ParsePrefix(target.SourcePrefix)
		if err != nil {
			logger.Info("Invalid CIDR %s: %v", target.SourcePrefix, err)
			continue
		}

		destPrefix, err := netip.ParsePrefix(target.DestPrefix)
		if err != nil {
			logger.Info("Invalid CIDR %s: %v", target.DestPrefix, err)
			continue
		}

		s.tnet.RemoveProxySubnetRule(sourcePrefix, destPrefix)

		logger.Info("Removed target subnet %s with destination %s", target.SourcePrefix, target.DestPrefix)
	}
}

func (s *WireGuardService) handleUpdateTarget(msg websocket.WSMessage) {
	logger.Debug("Received message: %v", msg.Data)

	// you are going to get a oldTarget and a newTarget in the message
	type UpdateTargetRequest struct {
		OldTargets []Target `json:"oldTargets"`
		NewTargets []Target `json:"newTargets"`
	}

	jsonData, err := json.Marshal(msg.Data)
	if err != nil {
		logger.Info("Error marshaling data: %v", err)
		return
	}

	if s.tnet == nil {
		// Native interface mode - proxy features not available, skip silently
		logger.Debug("Skipping update target - using native interface (no proxy support)")
		return
	}

	// Try to unmarshal as array first
	var requests UpdateTargetRequest
	if err := json.Unmarshal(jsonData, &requests); err != nil {
		logger.Warn("Error unmarshaling target data: %v", err)
		return
	}

	// Process all update requests
	for _, target := range requests.OldTargets {
		sourcePrefix, err := netip.ParsePrefix(target.SourcePrefix)
		if err != nil {
			logger.Info("Invalid CIDR %s: %v", target.SourcePrefix, err)
			continue
		}

		destPrefix, err := netip.ParsePrefix(target.DestPrefix)
		if err != nil {
			logger.Info("Invalid CIDR %s: %v", target.DestPrefix, err)
			continue
		}

		s.tnet.RemoveProxySubnetRule(sourcePrefix, destPrefix)
		logger.Info("Removed target subnet %s with destination %s", target.SourcePrefix, target.DestPrefix)
	}

	for _, target := range requests.NewTargets {
		// Now add the new target
		sourcePrefix, err := netip.ParsePrefix(target.SourcePrefix)
		if err != nil {
			logger.Info("Invalid CIDR %s: %v", target.SourcePrefix, err)
			continue
		}

		destPrefix, err := netip.ParsePrefix(target.DestPrefix)
		if err != nil {
			logger.Info("Invalid CIDR %s: %v", target.DestPrefix, err)
			continue
		}

		var portRanges []netstack2.PortRange
		for _, pr := range target.PortRange {
			portRanges = append(portRanges, netstack2.PortRange{
				Min:         pr.Min,
				Max:         pr.Max,
				Protocol:    pr.Protocol,
			})
		}

		s.tnet.AddProxySubnetRule(sourcePrefix, destPrefix, target.RewriteTo, portRanges, target.DisableIcmp)
		logger.Info("Added target subnet from %s to %s rewrite to %s with port ranges: %v", target.SourcePrefix, target.DestPrefix, target.RewriteTo, target.PortRange)
	}
}

// filterReadOnlyFields removes read-only fields from WireGuard IPC configuration
func (s *WireGuardService) filterReadOnlyFields(config string) string {
	lines := strings.Split(config, "\n")
	var filteredLines []string

	// List of read-only fields that should not be included in IpcSet
	readOnlyFields := map[string]bool{
		"last_handshake_time_sec":  true,
		"last_handshake_time_nsec": true,
		"rx_bytes":                 true,
		"tx_bytes":                 true,
		"protocol_version":         true,
	}

	for _, line := range lines {
		if line == "" {
			continue
		}

		// Check if this line contains a read-only field
		isReadOnly := false
		for field := range readOnlyFields {
			if strings.HasPrefix(line, field+"=") {
				isReadOnly = true
				break
			}
		}

		// Only include non-read-only lines
		if !isReadOnly {
			filteredLines = append(filteredLines, line)
		}
	}

	return strings.Join(filteredLines, "\n")
}
