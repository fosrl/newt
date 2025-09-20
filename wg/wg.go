//go:build linux

package wg

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/network"
	"github.com/fosrl/newt/websocket"
	"github.com/vishvananda/netlink"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/exp/rand"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type WgConfig struct {
	IpAddress string `json:"ipAddress"`
	Peers     []Peer `json:"peers"`
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
	wgClient          *wgctrl.Client
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
	interfaceCreated  bool
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
	rand.Seed(uint64(time.Now().UnixNano()))
	for i := len(portRange) - 1; i > 0; i-- {
		j := rand.Intn(i + 1)
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

		// Check if port+1 is also available
		addr2 := &net.UDPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: int(port + 1),
		}
		conn2, err2 := net.ListenUDP("udp", addr2)
		if err2 != nil {
			// The next port is not available, so close the first connection and try again
			conn1.Close()
			continue
		}

		// Both ports are available, close connections and return the first port
		conn1.Close()
		conn2.Close()
		return port, nil
	}

	return 0, fmt.Errorf("no available consecutive UDP ports found in range %d-%d", minPort, maxPort)
}

func NewWireGuardService(interfaceName string, mtu int, generateAndSaveKeyTo string, host string, newtId string, wsClient *websocket.Client) (*WireGuardService, error) {
	wgClient, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create WireGuard client: %v", err)
	}

	var key wgtypes.Key
	// if generateAndSaveKeyTo is provided, generate a private key and save it to the file. if the file already exists, load the key from the file
	key, err = wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	// Load or generate private key
	if generateAndSaveKeyTo != "" {
		if _, err := os.Stat(generateAndSaveKeyTo); os.IsNotExist(err) {
			keyData, err := os.ReadFile(generateAndSaveKeyTo)
			if err != nil {
				return nil, fmt.Errorf("failed to read private key: %v", err)
			}
			key, err = wgtypes.ParseKey(strings.TrimSpace(string(keyData)))
			if err != nil {
				return nil, fmt.Errorf("failed to parse private key: %v", err)
			}
		} else {
			err = os.WriteFile(generateAndSaveKeyTo, []byte(key.String()), 0600)
			if err != nil {
				return nil, fmt.Errorf("failed to save private key: %v", err)
			}
		}
	}

	service := &WireGuardService{
		interfaceName: interfaceName,
		mtu:           mtu,
		client:        wsClient,
		wgClient:      wgClient,
		key:           key,
		keyFilePath:   generateAndSaveKeyTo,
		newtId:        newtId,
		host:          host,
		lastReadings:  make(map[string]PeerReading),
		stopHolepunch: make(chan struct{}),
	}

	// Get the existing wireguard port (keep this part)
	device, err := service.wgClient.Device(service.interfaceName)
	if err == nil {
		service.Port = uint16(device.ListenPort)
		if service.Port != 0 {
			logger.Info("WireGuard interface %s already exists with port %d\n", service.interfaceName, service.Port)
		} else {
			service.Port, err = FindAvailableUDPPort(49152, 65535)
			if err != nil {
				fmt.Printf("Error finding available port: %v\n", err)
				return nil, err
			}
		}
	} else {
		service.Port, err = FindAvailableUDPPort(49152, 65535)
		if err != nil {
			fmt.Printf("Error finding available port: %v\n", err)
			return nil, err
		}
	}

	// Register websocket handlers
	wsClient.RegisterHandler("newt/wg/receive-config", service.handleConfig)
	wsClient.RegisterHandler("newt/wg/peer/add", service.handleAddPeer)
	wsClient.RegisterHandler("newt/wg/peer/remove", service.handleRemovePeer)
	wsClient.RegisterHandler("newt/wg/peer/update", service.handleUpdatePeer)

	return service, nil
}

func (s *WireGuardService) Close(rm bool) {
	if s.stopGetConfig != nil {
		s.stopGetConfig()
		s.stopGetConfig = nil
	}

	s.wgClient.Close()
	// Remove the WireGuard interface
	if rm {
		if err := s.removeInterface(); err != nil {
			logger.Error("Failed to remove WireGuard interface: %v", err)
		}

		// Remove the private key file
		// if s.keyFilePath != "" {
		// 	if err := os.Remove(s.keyFilePath); err != nil {
		// 		logger.Error("Failed to remove private key file: %v", err)
		// 	}
		// }
	}
}

func (s *WireGuardService) StartHolepunch(serverPubKey string, endpoint string) {
	// if the device is already created dont start a new holepunch
	if s.interfaceCreated {
		return
	}

	s.serverPubKey = serverPubKey
	s.holePunchEndpoint = endpoint

	logger.Debug("Starting UDP hole punch to %s", s.holePunchEndpoint)

	s.stopHolepunch = make(chan struct{})

	// start the UDP holepunch
	go s.keepSendingUDPHolePunch(s.holePunchEndpoint)
}

func (s *WireGuardService) SetToken(token string) {
	s.token = token
}

func (s *WireGuardService) LoadRemoteConfig() error {
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
}

func (s *WireGuardService) ensureWireguardInterface(wgconfig WgConfig) error {
	// Check if the WireGuard interface exists
	_, err := netlink.LinkByName(s.interfaceName)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			// Interface doesn't exist, so create it
			err = s.createWireGuardInterface()
			if err != nil {
				logger.Fatal("Failed to create WireGuard interface: %v", err)
			}
			s.interfaceCreated = true
			logger.Info("Created WireGuard interface %s\n", s.interfaceName)
		} else {
			logger.Fatal("Error checking for WireGuard interface: %v", err)
		}
	} else {
		logger.Info("WireGuard interface %s already exists\n", s.interfaceName)

		// get the exising wireguard port
		device, err := s.wgClient.Device(s.interfaceName)
		if err != nil {
			return fmt.Errorf("failed to get device: %v", err)
		}

		// get the existing port
		s.Port = uint16(device.ListenPort)
		logger.Info("WireGuard interface %s already exists with port %d\n", s.interfaceName, s.Port)

		s.interfaceCreated = true
		return nil
	}

	// stop the holepunch its a channel
	if s.stopHolepunch != nil {
		close(s.stopHolepunch)
		s.stopHolepunch = nil
	}

	logger.Info("Assigning IP address %s to interface %s\n", wgconfig.IpAddress, s.interfaceName)
	// Assign IP address to the interface
	err = s.assignIPAddress(wgconfig.IpAddress)
	if err != nil {
		logger.Fatal("Failed to assign IP address: %v", err)
	}

	// Check if the interface already exists
	_, err = s.wgClient.Device(s.interfaceName)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("interface %s does not exist", s.interfaceName)
		}
		return fmt.Errorf("failed to get device: %v", err)
	}

	// Parse the private key
	key, err := wgtypes.ParseKey(s.key.String())
	if err != nil {
		return fmt.Errorf("failed to parse private key: %v", err)
	}

	config := wgtypes.Config{
		PrivateKey: &key,
		ListenPort: new(int),
	}

	// Use the service's fixed port instead of the config port
	*config.ListenPort = int(s.Port)

	// Create and configure the WireGuard interface
	err = s.wgClient.ConfigureDevice(s.interfaceName, config)
	if err != nil {
		return fmt.Errorf("failed to configure WireGuard device: %v", err)
	}

	// bring up the interface
	link, err := netlink.LinkByName(s.interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get interface: %v", err)
	}

	if err := netlink.LinkSetMTU(link, s.mtu); err != nil {
		return fmt.Errorf("failed to set MTU: %v", err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to bring up interface: %v", err)
	}

	// if err := s.ensureMSSClamping(); err != nil {
	// 	logger.Warn("Failed to ensure MSS clamping: %v", err)
	// }

	logger.Info("WireGuard interface %s created and configured", s.interfaceName)

	return nil
}

func (s *WireGuardService) createWireGuardInterface() error {
	wgLink := &netlink.GenericLink{
		LinkAttrs: netlink.LinkAttrs{Name: s.interfaceName},
		LinkType:  "wireguard",
	}
	return netlink.LinkAdd(wgLink)
}

func (s *WireGuardService) assignIPAddress(ipAddress string) error {
	link, err := netlink.LinkByName(s.interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get interface: %v", err)
	}

	addr, err := netlink.ParseAddr(ipAddress)
	if err != nil {
		return fmt.Errorf("failed to parse IP address: %v", err)
	}

	return netlink.AddrAdd(link, addr)
}

func (s *WireGuardService) ensureWireguardPeers(peers []Peer) error {
	// get the current peers
	device, err := s.wgClient.Device(s.interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get device: %v", err)
	}

	// get the peer public keys
	var currentPeers []string
	for _, peer := range device.Peers {
		currentPeers = append(currentPeers, peer.PublicKey.String())
	}

	// remove any peers that are not in the config
	for _, peer := range currentPeers {
		found := false
		for _, configPeer := range peers {
			if peer == configPeer.PublicKey {
				found = true
				break
			}
		}
		if !found {
			err := s.removePeer(peer)
			if err != nil {
				return fmt.Errorf("failed to remove peer: %v", err)
			}
		}
	}

	// add any peers that are in the config but not in the current peers
	for _, configPeer := range peers {
		found := false
		for _, peer := range currentPeers {
			if configPeer.PublicKey == peer {
				found = true
				break
			}
		}
		if !found {
			err := s.addPeer(configPeer)
			if err != nil {
				return fmt.Errorf("failed to add peer: %v", err)
			}
		}
	}

	return nil
}

func (s *WireGuardService) handleAddPeer(msg websocket.WSMessage) {
	logger.Debug("Received message: %v", msg.Data)
	var peer Peer

	jsonData, err := json.Marshal(msg.Data)
	if err != nil {
		logger.Info("Error marshaling data: %v", err)
	}

	if err := json.Unmarshal(jsonData, &peer); err != nil {
		logger.Info("Error unmarshaling target data: %v", err)
	}

	err = s.addPeer(peer)
	if err != nil {
		logger.Info("Error adding peer: %v", err)
		return
	}
}

func (s *WireGuardService) addPeer(peer Peer) error {
	pubKey, err := wgtypes.ParseKey(peer.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %v", err)
	}

	// parse allowed IPs into array of net.IPNet
	var allowedIPs []net.IPNet
	for _, ipStr := range peer.AllowedIPs {
		_, ipNet, err := net.ParseCIDR(ipStr)
		if err != nil {
			return fmt.Errorf("failed to parse allowed IP: %v", err)
		}
		allowedIPs = append(allowedIPs, *ipNet)
	}
	// add keep alive using *time.Duration	 of 1 second
	keepalive := time.Second

	var peerConfig wgtypes.PeerConfig
	if peer.Endpoint != "" {
		// This logic correctly handles IPv4, IPv6, and hostnames.
		formattedEndpoint := peer.Endpoint
		host, _, err := net.SplitHostPort(formattedEndpoint)
		if err == nil {
			// It's a host:port string, check if the host is a literal IPv6
			ip := net.ParseIP(host)
			if ip != nil && ip.To4() == nil { // It is a literal IPv6
				// Already correctly formatted by SplitHostPort logic, do nothing
			}
		} else {
			// Not a standard host:port string, could be IPv6 without brackets.
			// Let's try to parse it as such.
			lastColon := strings.LastIndex(formattedEndpoint, ":")
			if lastColon != -1 {
				host := formattedEndpoint[:lastColon]
				port := formattedEndpoint[lastColon+1:]
				ip := net.ParseIP(host)
				if ip != nil && ip.To4() == nil { // It is a literal IPv6
					formattedEndpoint = fmt.Sprintf("[%s]:%s", host, port)
				}
			}
		}

		endpoint, err := net.ResolveUDPAddr("udp", formattedEndpoint)
		if err != nil {
			return fmt.Errorf("failed to resolve endpoint address '%s': %w", formattedEndpoint, err)
		}

		peerConfig = wgtypes.PeerConfig{
			PublicKey:                   pubKey,
			AllowedIPs:                  allowedIPs,
			PersistentKeepaliveInterval: &keepalive,
			Endpoint:                    endpoint,
		}
	} else {
		peerConfig = wgtypes.PeerConfig{
			PublicKey:                   pubKey,
			AllowedIPs:                  allowedIPs,
			PersistentKeepaliveInterval: &keepalive,
		}
		logger.Info("Added peer with no endpoint!")
	}

	config := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerConfig},
		ReplacePeers: false,
	}

	if err := s.wgClient.ConfigureDevice(s.interfaceName, config); err != nil {
		return fmt.Errorf("failed to add peer: %v", err)
	}

	logger.Info("Peer %s added successfully", peer.PublicKey)

	return nil
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
	}

	var request RemoveRequest
	if err := json.Unmarshal(jsonData, &request); err != nil {
		logger.Info("Error unmarshaling data: %v", err)
		return
	}

	if err := s.removePeer(request.PublicKey); err != nil {
		logger.Info("Error removing peer: %v", err)
		return
	}
}

func (s *WireGuardService) removePeer(publicKey string) error {
	pubKey, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %v", err)
	}

	peerConfig := wgtypes.PeerConfig{
		PublicKey: pubKey,
		Remove:    true,
	}

	config := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerConfig},
	}

	if err := s.wgClient.ConfigureDevice(s.interfaceName, config); err != nil {
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
    // First, get the current peer configuration to preserve any unmodified fields
    device, err := s.wgClient.Device(s.interfaceName)
    if err != nil {
        logger.Info("Error getting WireGuard device: %v", err)
        return
    }
    pubKey, err := wgtypes.ParseKey(request.PublicKey)
    if err != nil {
        logger.Info("Error parsing public key: %v", err)
        return
    }
    // Find the existing peer configuration
    var currentPeer *wgtypes.Peer
    for i := range device.Peers {
        if device.Peers[i].PublicKey == pubKey {
            currentPeer = &device.Peers[i]
            break
        }
    }
    if currentPeer == nil {
        logger.Info("Peer %s not found, cannot update", request.PublicKey)
        return
    }
    // Create the update peer config
    peerConfig := wgtypes.PeerConfig{
        PublicKey:  pubKey,
        UpdateOnly: true,
    }
    // Keep the default persistent keepalive
    keepalive := 25 * time.Second
    peerConfig.PersistentKeepaliveInterval = &keepalive

    // Handle Endpoint field special case
    endpointSpecified := false
    if rawData, ok := msg.Data.(map[string]interface{}); ok {
        _, endpointSpecified = rawData["endpoint"]
    }

    // Only update AllowedIPs if provided in the request
    if len(request.AllowedIPs) > 0 {
        var allowedIPs []net.IPNet
        for _, ipStr := range request.AllowedIPs {
            _, ipNet, err := net.ParseCIDR(ipStr)
            if err != nil {
                logger.Info("Error parsing allowed IP %s: %v", ipStr, err)
                return
            }
            allowedIPs = append(allowedIPs, *ipNet)
        }
        peerConfig.AllowedIPs = allowedIPs
        peerConfig.ReplaceAllowedIPs = true
        logger.Info("Updating AllowedIPs for peer %s", request.PublicKey)
    }

    if endpointSpecified {
        if request.Endpoint != "" {
            // Update to new endpoint using the robust formatting logic
            formattedEndpoint := request.Endpoint
            host, port, err := net.SplitHostPort(request.Endpoint)
            if err == nil {
                ip := net.ParseIP(host)
                if ip != nil && ip.To4() == nil {
                    formattedEndpoint = fmt.Sprintf("[%s]:%s", host, port)
                }
            }
            endpoint, err := net.ResolveUDPAddr("udp", formattedEndpoint)
            if err != nil {
                logger.Info("Error resolving endpoint address %s: %v", formattedEndpoint, err)
                return
            }
            peerConfig.Endpoint = endpoint
            logger.Info("Updating Endpoint for peer %s to %s", request.PublicKey, formattedEndpoint)
        } else {
            // Set a valid "any" IP address instead of a nil one.
            logger.Info("Removing Endpoint for peer %s", request.PublicKey)
            peerConfig.Endpoint = &net.UDPAddr{IP: net.IPv4zero, Port: 0}
        }
    }

    // Apply the configuration update
    config := wgtypes.Config{
        Peers: []wgtypes.PeerConfig{peerConfig},
    }
    if err := s.wgClient.ConfigureDevice(s.interfaceName, config); err != nil {
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
	device, err := s.wgClient.Device(s.interfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get device: %v", err)
	}

	peerBandwidths := []PeerBandwidth{}
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, peer := range device.Peers {
		publicKey := peer.PublicKey.String()
		currentReading := PeerReading{
			BytesReceived:    peer.ReceiveBytes,
			BytesTransmitted: peer.TransmitBytes,
			LastChecked:      now,
		}

		lastReading, exists := s.lastReadings[publicKey]

		if exists {
			timeDiff := currentReading.LastChecked.Sub(lastReading.LastChecked).Seconds()
			if timeDiff > 0 {
				bytesInDiff := float64(currentReading.BytesReceived - lastReading.BytesReceived)
				bytesOutDiff := float64(currentReading.BytesTransmitted - lastReading.BytesTransmitted)

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

				peerBandwidths = append(peerBandwidths, PeerBandwidth{
					PublicKey: publicKey,
					BytesIn:   bytesInMB,
					BytesOut:  bytesOutMB,
				})
			}
		}
		s.lastReadings[publicKey] = currentReading
	}

	activePeers := make(map[string]struct{})
	for _, peer := range device.Peers {
		activePeers[peer.PublicKey.String()] = struct{}{}
	}
	for publicKey := range s.lastReadings {
		if _, found := activePeers[publicKey]; !found {
			delete(s.lastReadings, publicKey)
		}
	}

	return peerBandwidths, nil
}

func (s *WireGuardService) reportPeerBandwidth() error {
	bandwidths, err := s.calculatePeerBandwidth()
	if err != nil {
		return fmt.Errorf("failed to calculate peer bandwidth: %v", err)
	}

	if len(bandwidths) == 0 {
		return nil
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

	serverHostname, serverPortStr, err := net.SplitHostPort(serverAddr)
	if err != nil {
		return fmt.Errorf("failed to parse server address '%s': %v", serverAddr, err)
	}

	serverPort, err := strconv.ParseUint(serverPortStr, 10, 16)
	if err != nil {
		return fmt.Errorf("failed to parse server port from '%s': %v", serverPortStr, err)
	}

	var serverIPAddr net.IP
	ip := net.ParseIP(serverHostname)

	if ip != nil {
		serverIPAddr = ip
	} else {
		serverIPAddr = network.HostToAddr(serverHostname)
		if serverIPAddr == nil {
			return fmt.Errorf("failed to resolve server hostname: %s", serverHostname)
		}
	}

	clientIP := network.GetClientIP(serverIPAddr)

	// Create server and client configs
	server := &network.Server{
		Hostname: serverHostname,
		Addr:     serverIPAddr,
		Port:     uint16(serverPort),
	}

	client := &network.PeerNet{
		IP:     clientIP,
		Port:   s.Port,
		NewtID: s.newtId,
	}

	conn := network.SetupConn(client)
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

	// Send the encrypted packet using the raw connection
	err = network.SendDataPacket(encryptedPayload, conn, server, client)
	if err != nil {
		return fmt.Errorf("failed to send UDP packet: %v", err)
	}

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
	// send initial hole punch
	if err := s.sendUDPHolePunch(host + ":21820"); err != nil {
		logger.Error("Failed to send initial UDP hole punch: %v", err)
	}

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopHolepunch:
			logger.Info("Stopping UDP holepunch")
			return
		case <-ticker.C:
			if err := s.sendUDPHolePunch(host + ":21820"); err != nil {
				logger.Error("Failed to send UDP hole punch: %v", err)
			}
		}
	}
}

func (s *WireGuardService) removeInterface() error {
	// Remove the WireGuard interface
	link, err := netlink.LinkByName(s.interfaceName)
	if err != nil {
		// If the link is not found, we can consider it as successfully removed
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			logger.Info("WireGuard interface %s already removed", s.interfaceName)
			return nil
		}
		return fmt.Errorf("failed to get interface: %v", err)
	}

	err = netlink.LinkDel(link)
	if err != nil {
		return fmt.Errorf("failed to delete interface: %v", err)
	}

	logger.Info("WireGuard interface %s removed successfully", s.interfaceName)

	return nil
}
