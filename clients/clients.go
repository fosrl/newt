package clients

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fosrl/newt/bind"
	"github.com/fosrl/newt/holepunch"
	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/netstack2"
	"github.com/fosrl/newt/util"
	"github.com/fosrl/newt/websocket"
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
	PortRange    []PortRange `json:"portRange,omitempty"`
}

type PortRange struct {
	Min uint16 `json:"min"`
	Max uint16 `json:"max"`
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
	keyFilePath   string
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
	sharedBind       *bind.SharedBind
	holePunchManager *holepunch.Manager
}

func NewWireGuardService(interfaceName string, mtu int, generateAndSaveKeyTo string, host string, newtId string, wsClient *websocket.Client, dns string) (*WireGuardService, error) {
	var key wgtypes.Key
	var err error

	key, err = wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	// Load or generate private key
	if generateAndSaveKeyTo != "" {
		if _, err := os.Stat(generateAndSaveKeyTo); os.IsNotExist(err) {
			// File doesn't exist, save the generated key
			err = os.WriteFile(generateAndSaveKeyTo, []byte(key.String()), 0600)
			if err != nil {
				return nil, fmt.Errorf("failed to save private key: %v", err)
			}
		} else {
			// File exists, read the existing key
			keyData, err := os.ReadFile(generateAndSaveKeyTo)
			if err != nil {
				return nil, fmt.Errorf("failed to read private key: %v", err)
			}
			key, err = wgtypes.ParseKey(strings.TrimSpace(string(keyData)))
			if err != nil {
				return nil, fmt.Errorf("failed to parse private key: %v", err)
			}
		}
	}

	// Find an available port
	port, err := util.FindAvailableUDPPort(49152, 65535)

	if err != nil {
		return nil, fmt.Errorf("error finding available port: %v", err)
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

	logger.Info("Created shared UDP socket on port %d (refcount: %d)", port, sharedBind.GetRefCount())

	// Parse DNS addresses
	dnsAddrs := []netip.Addr{netip.MustParseAddr(dns)}

	service := &WireGuardService{
		interfaceName: interfaceName,
		mtu:           mtu,
		client:        wsClient,
		key:           key,
		keyFilePath:   generateAndSaveKeyTo,
		newtId:        newtId,
		host:          host,
		lastReadings:  make(map[string]PeerReading),
		Port:          port,
		dns:           dnsAddrs,
		sharedBind:    sharedBind,
	}

	// Create the holepunch manager with ResolveDomain function
	// We'll need to pass a domain resolver function
	service.holePunchManager = holepunch.NewManager(sharedBind, newtId, "newt")

	// Register websocket handlers
	wsClient.RegisterHandler("newt/wg/receive-config", service.handleConfig)
	wsClient.RegisterHandler("newt/wg/peer/add", service.handleAddPeer)
	wsClient.RegisterHandler("newt/wg/peer/remove", service.handleRemovePeer)
	wsClient.RegisterHandler("newt/wg/peer/update", service.handleUpdatePeer)
	wsClient.RegisterHandler("newt/wg/targets/add", service.handleAddTarget)
	wsClient.RegisterHandler("newt/wg/targets/remove", service.handleRemoveTarget)
	wsClient.RegisterHandler("newt/wg/targets/update", service.handleUpdateTarget)

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

func (s *WireGuardService) Close(rm bool) {
	if s.stopGetConfig != nil {
		s.stopGetConfig()
		s.stopGetConfig = nil
	}

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
func (s *WireGuardService) StartHolepunch(publicKey string, endpoint string) {
	if s.holePunchManager == nil {
		logger.Warn("Hole punch manager not initialized")
		return
	}

	logger.Info("Starting hole punch to %s with public key: %s", endpoint, publicKey)
	if err := s.holePunchManager.StartSingleEndpoint(endpoint, publicKey); err != nil {
		logger.Warn("Failed to start hole punch: %v", err)
	}
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

	logger.Info("Requesting WireGuard configuration from remote server")
	go s.periodicBandwidthCheck()

	return nil
}

func (s *WireGuardService) handleConfig(msg websocket.WSMessage) {
	var config WgConfig

	logger.Debug("Received message: %v", msg)
	logger.Info("Received WireGuard clients configuration from remote server")

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
	}

	if err := s.ensureWireguardPeers(config.Peers); err != nil {
		logger.Error("Failed to ensure WireGuard peers: %v", err)
	}

	if err := s.ensureTargets(config.Targets); err != nil {
		logger.Error("Failed to ensure WireGuard targets: %v", err)
	}
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

	// Stop any ongoing hole punch operations
	if s.holePunchManager != nil {
		s.holePunchManager.Stop()
	}

	// Parse the IP address from the config
	// tunnelIP := netip.MustParseAddr(wgconfig.IpAddress)

	// Create TUN device and network stack using netstack
	var err error
	s.tun, s.tnet, err = netstack2.CreateNetTUNWithOptions(
		[]netip.Addr{tunnelIP},
		s.dns,
		s.mtu,
		netstack2.NetTunOptions{
			EnableTCPProxy: true,
			EnableUDPProxy: true,
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

	// logger.Info("Private key is %s", fixKey(s.key.String()))

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

	logger.Info("WireGuard netstack device created and configured")

	// Store callback and tnet reference before releasing mutex
	callback := s.onNetstackReady
	tnet := s.tnet

	// Release the mutex before calling the callback
	s.mu.Unlock()

	// Call the callback if it's set to notify that netstack is ready
	if callback != nil {
		callback(tnet)
	}

	// Note: we already unlocked above, so don't use defer unlock
	return nil
}

func (s *WireGuardService) ensureWireguardPeers(peers []Peer) error {
	// For netstack, we need to manage peers differently
	// We'll configure peers directly on the device using IPC

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
		return fmt.Errorf("netstack not initialized")
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

		var rewriteTo netip.Prefix
		if target.RewriteTo != "" {
			rewriteTo, err = netip.ParsePrefix(target.RewriteTo)
			if err != nil {
				logger.Info("Invalid CIDR %s: %v", target.RewriteTo, err)
				continue
			}
		}

		var portRanges []netstack2.PortRange
		for _, pr := range target.PortRange {
			portRanges = append(portRanges, netstack2.PortRange{
				Min: pr.Min,
				Max: pr.Max,
			})
		}

		s.tnet.AddProxySubnetRule(sourcePrefix, destPrefix, rewriteTo, portRanges)

		logger.Info("Added target subnet from %s to %s with port ranges: %v", target.SourcePrefix, target.DestPrefix, target.PortRange)
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
		pubKeyBytes, err := base64.StdEncoding.DecodeString(peerBandwidths[i].PublicKey)
		if err != nil {
			logger.Info("Failed to decode public key %s: %v", peerBandwidths[i].PublicKey, err)
			continue
		}
		// Convert to hex
		peerBandwidths[i].PublicKey = hex.EncodeToString(pubKeyBytes)
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

	err = s.client.SendMessage("newt/receive-bandwidth", map[string]interface{}{
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
		logger.Info("Netstack not initialized")
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

		var rewriteTo netip.Prefix
		if target.RewriteTo != "" {
			rewriteTo, err = netip.ParsePrefix(target.RewriteTo)
			if err != nil {
				logger.Info("Invalid CIDR %s: %v", target.RewriteTo, err)
				continue
			}
		}

		var portRanges []netstack2.PortRange
		for _, pr := range target.PortRange {
			portRanges = append(portRanges, netstack2.PortRange{
				Min: pr.Min,
				Max: pr.Max,
			})
		}

		s.tnet.AddProxySubnetRule(sourcePrefix, destPrefix, rewriteTo, portRanges)

		logger.Info("Added target subnet from %s to %s with port ranges: %v", target.SourcePrefix, target.DestPrefix, target.PortRange)
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
		logger.Info("Netstack not initialized")
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
		logger.Info("Netstack not initialized")
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

		var rewriteTo netip.Prefix
		if target.RewriteTo != "" {
			rewriteTo, err = netip.ParsePrefix(target.RewriteTo)
			if err != nil {
				logger.Info("Invalid CIDR %s: %v", target.RewriteTo, err)
				continue
			}
		}

		var portRanges []netstack2.PortRange
		for _, pr := range target.PortRange {
			portRanges = append(portRanges, netstack2.PortRange{
				Min: pr.Min,
				Max: pr.Max,
			})
		}

		s.tnet.AddProxySubnetRule(sourcePrefix, destPrefix, rewriteTo, portRanges)
		logger.Info("Added target subnet from %s to %s with port ranges: %v", target.SourcePrefix, target.DestPrefix, target.PortRange)
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
