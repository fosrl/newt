package wgnetstack

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	mathrand "math/rand/v2"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/network"
	"github.com/fosrl/newt/proxy"
	"github.com/fosrl/newt/websocket"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/fosrl/newt/internal/telemetry"
)

type WgConfig struct {
	IpAddress string        `json:"ipAddress"`
	Peers     []Peer        `json:"peers"`
	Targets   TargetsByType `json:"targets"`
}

type TargetsByType struct {
	UDP []string `json:"udp"`
	TCP []string `json:"tcp"`
}

type TargetData struct {
	Targets []string `json:"targets"`
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
	interfaceName     string
	mtu               int
	client            *websocket.Client
	config            WgConfig
	key               wgtypes.Key
	keyFilePath       string
	newtId            string
	lastReadings      map[string]PeerReading
	mu                sync.Mutex
	Port              uint16
	stopHolepunch     chan struct{}
	host              string
	serverPubKey      string
	holePunchEndpoint string
	token             string
	stopGetConfig     func()
	// Netstack fields
	tun    tun.Device
	tnet   *netstack.Net
	device *device.Device
	dns    []netip.Addr
	// Callback for when netstack is ready
	onNetstackReady func(*netstack.Net)
	// Callback for when netstack is closed
	onNetstackClose func()
	othertnet       *netstack.Net
	// Proxy manager for tunnel
	proxyManager *proxy.ProxyManager
	TunnelIP     string
}

// GetProxyManager returns the proxy manager for this WireGuardService
func (s *WireGuardService) GetProxyManager() *proxy.ProxyManager {
	return s.proxyManager
}

// AddProxyTarget adds a target to the proxy manager
func (s *WireGuardService) AddProxyTarget(proto, listenIP string, port int, targetAddr string) error {
	if s.proxyManager == nil {
		return fmt.Errorf("proxy manager not initialized")
	}
	return s.proxyManager.AddTarget(proto, listenIP, port, targetAddr)
}

// RemoveProxyTarget removes a target from the proxy manager
func (s *WireGuardService) RemoveProxyTarget(proto, listenIP string, port int) error {
	if s.proxyManager == nil {
		return fmt.Errorf("proxy manager not initialized")
	}
	return s.proxyManager.RemoveTarget(proto, listenIP, port)
}

// Add this type definition
type fixedPortBind struct {
	port uint16
	conn.Bind
}

func (b *fixedPortBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	// Ignore the requested port and use our fixed port
	return b.Bind.Open(b.port)
}

func NewFixedPortBind(port uint16) conn.Bind {
	return &fixedPortBind{
		port: port,
		Bind: conn.NewDefaultBind(),
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
	port, err := FindAvailableUDPPort(49152, 65535)
	if err != nil {
		return nil, fmt.Errorf("error finding available port: %v", err)
	}

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
		stopHolepunch: make(chan struct{}),
		Port:          port,
		dns:           dnsAddrs,
		proxyManager:  proxy.NewProxyManagerWithoutTNet(),
	}

	// Register websocket handlers
	wsClient.RegisterHandler("newt/wg/receive-config", service.handleConfig)
	wsClient.RegisterHandler("newt/wg/peer/add", service.handleAddPeer)
	wsClient.RegisterHandler("newt/wg/peer/remove", service.handleRemovePeer)
	wsClient.RegisterHandler("newt/wg/peer/update", service.handleUpdatePeer)
	wsClient.RegisterHandler("newt/wg/tcp/add", service.addTcpTarget)
	wsClient.RegisterHandler("newt/wg/udp/add", service.addUdpTarget)
	wsClient.RegisterHandler("newt/wg/udp/remove", service.removeUdpTarget)
	wsClient.RegisterHandler("newt/wg/tcp/remove", service.removeTcpTarget)

	return service, nil
}

// ReportRTT allows reporting native RTTs to telemetry, rate-limited externally.
func (s *WireGuardService) ReportRTT(seconds float64) {
	if s.serverPubKey == "" { return }
	telemetry.ObserveTunnelLatency(context.Background(), s.serverPubKey, "wireguard", seconds)
}

func (s *WireGuardService) addTcpTarget(msg websocket.WSMessage) {
	logger.Debug("Received: %+v", msg)

	// if there is no wgData or pm, we can't add targets
	if s.TunnelIP == "" || s.proxyManager == nil {
		logger.Info("No tunnel IP or proxy manager available")
	return
}

	targetData, err := parseTargetData(msg.Data)
	if err != nil {
		logger.Info("Error parsing target data: %v", err)
		return
	}

	if len(targetData.Targets) > 0 {
		s.updateTargets(s.proxyManager, "add", s.TunnelIP, "tcp", targetData)
	}
}

func (s *WireGuardService) addUdpTarget(msg websocket.WSMessage) {
	logger.Info("Received: %+v", msg)

	// if there is no wgData or pm, we can't add targets
	if s.TunnelIP == "" || s.proxyManager == nil {
		logger.Info("No tunnel IP or proxy manager available")
		return
	}

	targetData, err := parseTargetData(msg.Data)
	if err != nil {
		logger.Info("Error parsing target data: %v", err)
		return
	}

	if len(targetData.Targets) > 0 {
		s.updateTargets(s.proxyManager, "add", s.TunnelIP, "udp", targetData)
	}
}

func (s *WireGuardService) removeUdpTarget(msg websocket.WSMessage) {
	logger.Info("Received: %+v", msg)

	// if there is no wgData or pm, we can't add targets
	if s.TunnelIP == "" || s.proxyManager == nil {
		logger.Info("No tunnel IP or proxy manager available")
		return
	}

	targetData, err := parseTargetData(msg.Data)
	if err != nil {
		logger.Info("Error parsing target data: %v", err)
		return
	}

	if len(targetData.Targets) > 0 {
		s.updateTargets(s.proxyManager, "remove", s.TunnelIP, "udp", targetData)
	}
}

func (s *WireGuardService) removeTcpTarget(msg websocket.WSMessage) {
	logger.Info("Received: %+v", msg)

	// if there is no wgData or pm, we can't add targets
	if s.TunnelIP == "" || s.proxyManager == nil {
		logger.Info("No tunnel IP or proxy manager available")
		return
	}

	targetData, err := parseTargetData(msg.Data)
	if err != nil {
		logger.Info("Error parsing target data: %v", err)
		return
	}

	if len(targetData.Targets) > 0 {
		s.updateTargets(s.proxyManager, "remove", s.TunnelIP, "tcp", targetData)
	}
}

func (s *WireGuardService) SetOthertnet(tnet *netstack.Net) {
	s.othertnet = tnet
}

func (s *WireGuardService) Close(rm bool) {
	if s.stopGetConfig != nil {
		s.stopGetConfig()
		s.stopGetConfig = nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Close WireGuard device first - this will automatically close the TUN device
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
}

func (s *WireGuardService) StartHolepunch(serverPubKey string, endpoint string) {
	// if the device is already created dont start a new holepunch
	if s.device != nil {
		return
	}

	s.serverPubKey = serverPubKey
	s.holePunchEndpoint = endpoint

	logger.Debug("Starting UDP hole punch to %s", s.holePunchEndpoint)

	// Create a new stop channel for this holepunch session
	s.stopHolepunch = make(chan struct{})

	// start the UDP holepunch
	go s.keepSendingUDPHolePunch(s.holePunchEndpoint)
}

func (s *WireGuardService) SetToken(token string) {
	s.token = token
}

// GetNetstackNet returns the netstack network interface for use by other components
func (s *WireGuardService) GetNetstackNet() *netstack.Net {
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
func (s *WireGuardService) SetOnNetstackReady(callback func(*netstack.Net)) {
	s.onNetstackReady = callback
}

func (s *WireGuardService) SetOnNetstackClose(callback func()) {
	s.onNetstackClose = callback
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

	// add the targets if there are any
	if len(config.Targets.TCP) > 0 {
		s.updateTargets(s.proxyManager, "add", s.TunnelIP, "tcp", TargetData{Targets: config.Targets.TCP})
	}

	if len(config.Targets.UDP) > 0 {
		s.updateTargets(s.proxyManager, "add", s.TunnelIP, "udp", TargetData{Targets: config.Targets.UDP})
	}

	// Create ProxyManager for this tunnel
	s.proxyManager.Start()
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

	// stop the holepunch its a channel
	if s.stopHolepunch != nil {
		close(s.stopHolepunch)
		s.stopHolepunch = nil
	}

	// Parse the IP address from the config
	// tunnelIP := netip.MustParseAddr(wgconfig.IpAddress)

	// Create TUN device and network stack using netstack
	var err error
	s.tun, s.tnet, err = netstack.CreateNetTUN(
		[]netip.Addr{tunnelIP},
		s.dns,
		s.mtu)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("failed to create TUN device: %v", err)
	}

	s.proxyManager.SetTNet(s.tnet)
	s.TunnelIP = tunnelIP.String()

	// Create WireGuard device
	s.device = device.NewDevice(s.tun, NewFixedPortBind(s.Port), device.NewLogger(
		device.LogLevelSilent, // Use silent logging by default - could be made configurable
		"wireguard: ",
	))

	// logger.Info("Private key is %s", fixKey(s.key.String()))

	// Configure WireGuard with private key
	config := fmt.Sprintf("private_key=%s", fixKey(s.key.String()))

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

func (s *WireGuardService) addPeerToDevice(peer Peer) error {
	// parse the key first
	pubKey, err := wgtypes.ParseKey(peer.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %v", err)
	}

	// Build IPC configuration string for the peer
	config := fmt.Sprintf("public_key=%s", fixKey(pubKey.String()))

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
	config := fmt.Sprintf("public_key=%s\nremove=true", fixKey(pubKey.String()))

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
	config := fmt.Sprintf("public_key=%s\nupdate_only=true", fixKey(pubKey.String()))

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

func (s *WireGuardService) sendUDPHolePunch(serverAddr string) error {

	if s.serverPubKey == "" || s.token == "" {
		logger.Debug("Server public key or token not set, skipping UDP hole punch")
		return nil
	}

	// Parse server address
	serverSplit := strings.Split(serverAddr, ":")
	if len(serverSplit) < 2 {
		return fmt.Errorf("invalid server address format, expected hostname:port")
	}

	serverHostname := serverSplit[0]
	serverPort, err := strconv.ParseUint(serverSplit[1], 10, 16)
	if err != nil {
		return fmt.Errorf("failed to parse server port: %v", err)
	}

	// Resolve server hostname to IP
	serverIPAddr := network.HostToAddr(serverHostname)
	if serverIPAddr == nil {
		return fmt.Errorf("failed to resolve server hostname")
	}

	// Create local UDP address using the same port as WireGuard
	localAddr := &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: int(s.Port),
	}

	// Create remote server address
	remoteAddr := &net.UDPAddr{
		IP:   serverIPAddr.IP,
		Port: int(serverPort),
	}

	// Create UDP connection bound to the same port as WireGuard
	conn, err := net.DialUDP("udp", localAddr, remoteAddr)
	if err != nil {
		return fmt.Errorf("failed to create netstack UDP connection: %v", err)
	}
	defer conn.Close()

	// Create JSON payload
	payload := struct {
		NewtID string `json:"newtId"`
		Token  string `json:"token"`
	}{
		NewtID: s.newtId,
		Token:  s.token,
	}

	// Convert payload to JSON
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %v", err)
	}

	// Encrypt the payload using the server's WireGuard public key
	encryptedPayload, err := s.encryptPayload(payloadBytes)
	if err != nil {
		return fmt.Errorf("failed to encrypt payload: %v", err)
	}

	// Convert encrypted payload to JSON
	jsonData, err := json.Marshal(encryptedPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal encrypted payload: %v", err)
	}

	// Send the encrypted packet using the netstack UDP connection
	_, err = conn.Write(jsonData)
	if err != nil {
		return fmt.Errorf("failed to send UDP packet: %v", err)
	}

	logger.Debug("Sent UDP hole punch to %s via netstack", remoteAddr.String())

	return nil
}

func (s *WireGuardService) encryptPayload(payload []byte) (interface{}, error) {
	// Generate an ephemeral keypair for this message
	ephemeralPrivateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral private key: %v", err)
	}
	ephemeralPublicKey := ephemeralPrivateKey.PublicKey()

	// Parse the server's public key
	serverPubKey, err := wgtypes.ParseKey(s.serverPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse server public key: %v", err)
	}

	// Use X25519 for key exchange (replacing deprecated ScalarMult)
	var ephPrivKeyFixed [32]byte
	copy(ephPrivKeyFixed[:], ephemeralPrivateKey[:])

	// Perform X25519 key exchange
	sharedSecret, err := curve25519.X25519(ephPrivKeyFixed[:], serverPubKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to perform X25519 key exchange: %v", err)
	}

	// Create an AEAD cipher using the shared secret
	aead, err := chacha20poly1305.New(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD cipher: %v", err)
	}

	// Generate a random nonce
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	// Encrypt the payload
	ciphertext := aead.Seal(nil, nonce, payload, nil)

	// Prepare the final encrypted message
	encryptedMsg := struct {
		EphemeralPublicKey string `json:"ephemeralPublicKey"`
		Nonce              []byte `json:"nonce"`
		Ciphertext         []byte `json:"ciphertext"`
	}{
		EphemeralPublicKey: ephemeralPublicKey.String(),
		Nonce:              nonce,
		Ciphertext:         ciphertext,
	}

	return encryptedMsg, nil
}

func (s *WireGuardService) keepSendingUDPHolePunch(host string) {
	logger.Info("Starting UDP hole punch routine to %s:21820", host)

	// send initial hole punch
	if err := s.sendUDPHolePunch(host + ":21820"); err != nil {
		logger.Debug("Failed to send initial UDP hole punch: %v", err)
	}

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	timeout := time.NewTimer(15 * time.Second)
	defer timeout.Stop()

	for {
		select {
		case <-s.stopHolepunch:
			logger.Info("Stopping UDP holepunch")
			return
		case <-timeout.C:
			logger.Info("UDP holepunch routine timed out after 15 seconds")
			return
		case <-ticker.C:
			if err := s.sendUDPHolePunch(host + ":21820"); err != nil {
				logger.Debug("Failed to send UDP hole punch: %v", err)
			}
		}
	}
}

func (s *WireGuardService) updateTargets(pm *proxy.ProxyManager, action string, tunnelIP string, proto string, targetData TargetData) error {
	var replace = false
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

			// Only remove the specific target if it exists
			err := pm.RemoveTarget(proto, tunnelIP, port)
			if err != nil {
				// Ignore "target not found" errors as this is expected for new targets
				if !strings.Contains(err.Error(), "target not found") {
					logger.Error("Failed to remove existing target: %v", err)
				}
			} else {
				replace = true // We successfully removed an existing target
			}

			// Add the new target
			pm.AddTarget(proto, tunnelIP, port, processedTarget)

		} else if action == "remove" {
			logger.Info("Removing target with port %d", port)

			err := pm.RemoveTarget(proto, tunnelIP, port)
			if err != nil {
				logger.Error("Failed to remove target: %v", err)
				return err
			}
		}
	}

	if replace {
		// If we replaced any targets, we need to hot swap the netstack
		if err := s.ReplaceNetstack(); err != nil {
			logger.Error("Failed to replace netstack after updating targets: %v", err)
			return err
		}
		logger.Info("Netstack replaced successfully after updating targets")
	} else {
		logger.Info("No targets updated, no netstack replacement needed")
	}

	return nil
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

// Add this method to WireGuardService
func (s *WireGuardService) ReplaceNetstack() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.device == nil || s.tun == nil {
		return fmt.Errorf("WireGuard device not initialized")
	}

	// Parse the current tunnel IP from the existing config
	parts := strings.Split(s.config.IpAddress, "/")
	if len(parts) != 2 {
		return fmt.Errorf("invalid IP address format: %s", s.config.IpAddress)
	}
	tunnelIP := netip.MustParseAddr(parts[0])

	// Stop the proxy manager temporarily
	s.proxyManager.Stop()

	// Create new TUN device and netstack with new DNS
	newTun, newTnet, err := netstack.CreateNetTUN(
		[]netip.Addr{tunnelIP},
		s.dns,
		s.mtu)
	if err != nil {
		// Restart proxy manager with old tnet on failure
		s.proxyManager.Start()
		return fmt.Errorf("failed to create new TUN device: %v", err)
	}

	// Get current device config before closing
	currentConfig, err := s.device.IpcGet()
	if err != nil {
		newTun.Close()
		s.proxyManager.Start()
		return fmt.Errorf("failed to get current device config: %v", err)
	}

	// Filter out read-only fields from the config
	filteredConfig := s.filterReadOnlyFields(currentConfig)

	// if onNetstackClose callback is set, call it
	if s.onNetstackClose != nil {
		s.onNetstackClose()
	}

	// Close old device (this closes the old TUN device)
	s.device.Close()

	// Update references
	s.tun = newTun
	s.tnet = newTnet

	// Create new WireGuard device with same port
	s.device = device.NewDevice(s.tun, NewFixedPortBind(s.Port), device.NewLogger(
		device.LogLevelSilent,
		"wireguard: ",
	))

	// Restore the configuration (without read-only fields)
	err = s.device.IpcSet(filteredConfig)
	if err != nil {
		return fmt.Errorf("failed to restore WireGuard configuration: %v", err)
	}

	// Bring up the device
	err = s.device.Up()
	if err != nil {
		return fmt.Errorf("failed to bring up new WireGuard device: %v", err)
	}

	// Update proxy manager with new tnet and restart
	s.proxyManager.SetTNet(s.tnet)
	s.proxyManager.Start()

	s.proxyManager.PrintTargets()

	// Call the netstack ready callback if set
	if s.onNetstackReady != nil {
		go s.onNetstackReady(s.tnet)
	}

	return nil
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
