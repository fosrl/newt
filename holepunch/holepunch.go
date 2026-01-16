package holepunch

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/fosrl/newt/bind"
	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/util"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	mrand "golang.org/x/exp/rand"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// ExitNode represents a WireGuard exit node for hole punching
type ExitNode struct {
	Endpoint  string `json:"endpoint"`
	RelayPort uint16 `json:"relayPort"`
	PublicKey string `json:"publicKey"`
	SiteIds   []int  `json:"siteIds,omitempty"`
}

// Manager handles UDP hole punching operations
type Manager struct {
	mu         sync.Mutex
	running    bool
	stopChan   chan struct{}
	sharedBind *bind.SharedBind
	ID         string
	token      string
	publicKey  string
	clientType string
	exitNodes  map[string]ExitNode // key is endpoint
	updateChan chan struct{}       // signals the goroutine to refresh exit nodes

	sendHolepunchInterval    time.Duration
	sendHolepunchIntervalMin time.Duration
	sendHolepunchIntervalMax time.Duration
	defaultIntervalMin       time.Duration
	defaultIntervalMax       time.Duration
}

const defaultSendHolepunchIntervalMax = 60 * time.Second
const defaultSendHolepunchIntervalMin = 1 * time.Second

// NewManager creates a new hole punch manager
func NewManager(sharedBind *bind.SharedBind, ID string, clientType string, publicKey string) *Manager {
	return &Manager{
		sharedBind:               sharedBind,
		ID:                       ID,
		clientType:               clientType,
		publicKey:                publicKey,
		exitNodes:                make(map[string]ExitNode),
		sendHolepunchInterval:    defaultSendHolepunchIntervalMin,
		sendHolepunchIntervalMin: defaultSendHolepunchIntervalMin,
		sendHolepunchIntervalMax: defaultSendHolepunchIntervalMax,
		defaultIntervalMin:       defaultSendHolepunchIntervalMin,
		defaultIntervalMax:       defaultSendHolepunchIntervalMax,
	}
}

// SetToken updates the authentication token used for hole punching
func (m *Manager) SetToken(token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.token = token
}

// IsRunning returns whether hole punching is currently active
func (m *Manager) IsRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}

// Stop stops any ongoing hole punch operations
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return
	}

	if m.stopChan != nil {
		close(m.stopChan)
		m.stopChan = nil
	}

	if m.updateChan != nil {
		close(m.updateChan)
		m.updateChan = nil
	}

	m.running = false
	logger.Info("Hole punch manager stopped")
}

// AddExitNode adds a new exit node to the rotation if it doesn't already exist
func (m *Manager) AddExitNode(exitNode ExitNode) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.exitNodes[exitNode.Endpoint]; exists {
		logger.Debug("Exit node %s already exists in rotation", exitNode.Endpoint)
		return false
	}

	m.exitNodes[exitNode.Endpoint] = exitNode
	logger.Info("Added exit node %s to hole punch rotation", exitNode.Endpoint)

	// Signal the goroutine to refresh if running
	if m.running && m.updateChan != nil {
		select {
		case m.updateChan <- struct{}{}:
		default:
			// Channel full or closed, skip
		}
	}

	return true
}

// RemoveExitNode removes an exit node from the rotation
func (m *Manager) RemoveExitNode(endpoint string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.exitNodes[endpoint]; !exists {
		logger.Debug("Exit node %s not found in rotation", endpoint)
		return false
	}

	delete(m.exitNodes, endpoint)
	logger.Info("Removed exit node %s from hole punch rotation", endpoint)

	// Signal the goroutine to refresh if running
	if m.running && m.updateChan != nil {
		select {
		case m.updateChan <- struct{}{}:
		default:
			// Channel full or closed, skip
		}
	}

	return true
}

/*
RemoveExitNodesByPeer removes the peer ID from the SiteIds list in each exit node.
If the SiteIds list becomes empty after removal, the exit node is removed entirely.
Returns the number of exit nodes removed.
*/
func (m *Manager) RemoveExitNodesByPeer(peerID int) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	removed := 0
	for endpoint, node := range m.exitNodes {
		// Remove peerID from SiteIds if present
		newSiteIds := make([]int, 0, len(node.SiteIds))
		for _, id := range node.SiteIds {
			if id != peerID {
				newSiteIds = append(newSiteIds, id)
			}
		}
		if len(newSiteIds) != len(node.SiteIds) {
			node.SiteIds = newSiteIds
			if len(node.SiteIds) == 0 {
				delete(m.exitNodes, endpoint)
				logger.Info("Removed exit node %s as no more site IDs remain after removing peer %d", endpoint, peerID)
				removed++
			} else {
				m.exitNodes[endpoint] = node
				logger.Info("Removed peer %d from exit node %s site IDs", peerID, endpoint)
			}
		}
	}

	if removed > 0 {
		// Signal the goroutine to refresh if running
		if m.running && m.updateChan != nil {
			select {
			case m.updateChan <- struct{}{}:
			default:
				// Channel full or closed, skip
			}
		}
	}

	return removed
}

// GetExitNodes returns a copy of the current exit nodes
func (m *Manager) GetExitNodes() []ExitNode {
	m.mu.Lock()
	defer m.mu.Unlock()

	nodes := make([]ExitNode, 0, len(m.exitNodes))
	for _, node := range m.exitNodes {
		nodes = append(nodes, node)
	}
	return nodes
}

// SetServerHolepunchInterval sets custom min and max intervals for hole punching.
// This is useful for low power mode where longer intervals are desired.
func (m *Manager) SetServerHolepunchInterval(min, max time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.sendHolepunchIntervalMin = min
	m.sendHolepunchIntervalMax = max
	m.sendHolepunchInterval = min

	logger.Info("Set hole punch intervals: min=%v, max=%v", min, max)

	// Signal the goroutine to apply the new interval if running
	if m.running && m.updateChan != nil {
		select {
		case m.updateChan <- struct{}{}:
		default:
			// Channel full or closed, skip
		}
	}
}

// GetInterval returns the current min and max intervals
func (m *Manager) GetServerHolepunchInterval() (min, max time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sendHolepunchIntervalMin, m.sendHolepunchIntervalMax
}

// ResetServerHolepunchInterval resets the hole punch interval back to the default values.
// This restores normal operation after low power mode or other custom settings.
func (m *Manager) ResetServerHolepunchInterval() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.sendHolepunchIntervalMin = m.defaultIntervalMin
	m.sendHolepunchIntervalMax = m.defaultIntervalMax
	m.sendHolepunchInterval = m.defaultIntervalMin

	logger.Info("Reset hole punch intervals to defaults: min=%v, max=%v", m.defaultIntervalMin, m.defaultIntervalMax)

	// Signal the goroutine to apply the new interval if running
	if m.running && m.updateChan != nil {
		select {
		case m.updateChan <- struct{}{}:
		default:
			// Channel full or closed, skip
		}
	}
}

// TriggerHolePunch sends an immediate hole punch packet to all configured exit nodes
// This is useful for triggering hole punching on demand without waiting for the interval
func (m *Manager) TriggerHolePunch() error {
	m.mu.Lock()

	if len(m.exitNodes) == 0 {
		m.mu.Unlock()
		return fmt.Errorf("no exit nodes configured")
	}

	// Get a copy of exit nodes to work with
	currentExitNodes := make([]ExitNode, 0, len(m.exitNodes))
	for _, node := range m.exitNodes {
		currentExitNodes = append(currentExitNodes, node)
	}
	m.mu.Unlock()

	logger.Info("Triggering on-demand hole punch to %d exit nodes", len(currentExitNodes))

	// Send hole punch to all exit nodes
	successCount := 0
	for _, exitNode := range currentExitNodes {
		host, err := util.ResolveDomain(exitNode.Endpoint)
		if err != nil {
			logger.Warn("Failed to resolve endpoint %s: %v", exitNode.Endpoint, err)
			continue
		}

		serverAddr := net.JoinHostPort(host, strconv.Itoa(int(exitNode.RelayPort)))
		remoteAddr, err := net.ResolveUDPAddr("udp", serverAddr)
		if err != nil {
			logger.Error("Failed to resolve UDP address %s: %v", serverAddr, err)
			continue
		}

		if err := m.sendHolePunch(remoteAddr, exitNode.PublicKey); err != nil {
			logger.Warn("Failed to send on-demand hole punch to %s: %v", exitNode.Endpoint, err)
			continue
		}

		logger.Debug("Sent on-demand hole punch to %s", exitNode.Endpoint)
		successCount++
	}

	if successCount == 0 {
		return fmt.Errorf("failed to send hole punch to any exit node")
	}

	logger.Info("Successfully sent on-demand hole punch to %d/%d exit nodes", successCount, len(currentExitNodes))
	return nil
}

// StartMultipleExitNodes starts hole punching to multiple exit nodes
func (m *Manager) StartMultipleExitNodes(exitNodes []ExitNode) error {
	m.mu.Lock()

	if m.running {
		m.mu.Unlock()
		logger.Debug("UDP hole punch already running, skipping new request")
		return fmt.Errorf("hole punch already running")
	}

	// Populate exit nodes map
	m.exitNodes = make(map[string]ExitNode)
	for _, node := range exitNodes {
		m.exitNodes[node.Endpoint] = node
	}

	m.running = true
	m.stopChan = make(chan struct{})
	m.updateChan = make(chan struct{}, 1)
	m.mu.Unlock()

	logger.Debug("Starting UDP hole punch to %d exit nodes with shared bind", len(exitNodes))

	go m.runMultipleExitNodes()

	return nil
}

// Start starts hole punching with the current set of exit nodes
func (m *Manager) Start() error {
	m.mu.Lock()

	if m.running {
		m.mu.Unlock()
		logger.Debug("UDP hole punch already running")
		return fmt.Errorf("hole punch already running")
	}

	m.running = true
	m.stopChan = make(chan struct{})
	m.updateChan = make(chan struct{}, 1)
	nodeCount := len(m.exitNodes)
	m.mu.Unlock()

	if nodeCount == 0 {
		logger.Info("Starting UDP hole punch manager (waiting for exit nodes to be added)")
	} else {
		logger.Info("Starting UDP hole punch with %d exit nodes", nodeCount)
	}

	go m.runMultipleExitNodes()

	return nil
}

// runMultipleExitNodes performs hole punching to multiple exit nodes
func (m *Manager) runMultipleExitNodes() {
	defer func() {
		m.mu.Lock()
		m.running = false
		m.mu.Unlock()
		logger.Info("UDP hole punch goroutine ended for all exit nodes")
	}()

	// Resolve all endpoints upfront
	type resolvedExitNode struct {
		remoteAddr   *net.UDPAddr
		publicKey    string
		endpointName string
	}

	resolveNodes := func() []resolvedExitNode {
		m.mu.Lock()
		currentExitNodes := make([]ExitNode, 0, len(m.exitNodes))
		for _, node := range m.exitNodes {
			currentExitNodes = append(currentExitNodes, node)
		}
		m.mu.Unlock()

		var resolvedNodes []resolvedExitNode
		for _, exitNode := range currentExitNodes {
			host, err := util.ResolveDomain(exitNode.Endpoint)
			if err != nil {
				logger.Warn("Failed to resolve endpoint %s: %v", exitNode.Endpoint, err)
				continue
			}

			serverAddr := net.JoinHostPort(host, strconv.Itoa(int(exitNode.RelayPort)))
			remoteAddr, err := net.ResolveUDPAddr("udp", serverAddr)
			if err != nil {
				logger.Error("Failed to resolve UDP address %s: %v", serverAddr, err)
				continue
			}

			resolvedNodes = append(resolvedNodes, resolvedExitNode{
				remoteAddr:   remoteAddr,
				publicKey:    exitNode.PublicKey,
				endpointName: exitNode.Endpoint,
			})
			logger.Debug("Resolved exit node: %s -> %s", exitNode.Endpoint, remoteAddr.String())
		}
		return resolvedNodes
	}

	resolvedNodes := resolveNodes()

	if len(resolvedNodes) == 0 {
		logger.Info("No exit nodes available yet, waiting for nodes to be added")
	} else {
		// Send initial hole punch to all exit nodes
		for _, node := range resolvedNodes {
			if err := m.sendHolePunch(node.remoteAddr, node.publicKey); err != nil {
				logger.Warn("Failed to send initial hole punch to %s: %v", node.endpointName, err)
			}
		}
	}

	// Start with minimum interval
	m.mu.Lock()
	m.sendHolepunchInterval = m.sendHolepunchIntervalMin
	m.mu.Unlock()

	ticker := time.NewTicker(m.sendHolepunchInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopChan:
			logger.Debug("Hole punch stopped by signal")
			return
		case <-m.updateChan:
			// Re-resolve exit nodes when update is signaled
			logger.Info("Refreshing exit nodes for hole punching")
			resolvedNodes = resolveNodes()
			if len(resolvedNodes) == 0 {
				logger.Warn("No exit nodes available after refresh")
			} else {
				logger.Info("Updated resolved nodes count: %d", len(resolvedNodes))
			}
			// Reset interval to minimum on update
			m.mu.Lock()
			m.sendHolepunchInterval = m.sendHolepunchIntervalMin
			m.mu.Unlock()
			ticker.Reset(m.sendHolepunchInterval)
			// Send immediate hole punch to newly resolved nodes
			for _, node := range resolvedNodes {
				if err := m.sendHolePunch(node.remoteAddr, node.publicKey); err != nil {
					logger.Debug("Failed to send hole punch to %s: %v", node.endpointName, err)
				}
			}
		case <-ticker.C:
			// Send hole punch to all exit nodes (if any are available)
			if len(resolvedNodes) > 0 {
				for _, node := range resolvedNodes {
					if err := m.sendHolePunch(node.remoteAddr, node.publicKey); err != nil {
						logger.Debug("Failed to send hole punch to %s: %v", node.endpointName, err)
					}
				}
				// Exponential backoff: double the interval up to max
				m.mu.Lock()
				newInterval := m.sendHolepunchInterval * 2
				if newInterval > m.sendHolepunchIntervalMax {
					newInterval = m.sendHolepunchIntervalMax
				}
				if newInterval != m.sendHolepunchInterval {
					m.sendHolepunchInterval = newInterval
					ticker.Reset(m.sendHolepunchInterval)
					logger.Debug("Increased hole punch interval to %v", m.sendHolepunchInterval)
				}
				m.mu.Unlock()
			}
		}
	}
}

// sendHolePunch sends an encrypted hole punch packet using the shared bind
func (m *Manager) sendHolePunch(remoteAddr *net.UDPAddr, serverPubKey string) error {
	m.mu.Lock()
	token := m.token
	ID := m.ID
	m.mu.Unlock()

	if serverPubKey == "" || token == "" {
		return fmt.Errorf("server public key or OLM token is empty")
	}

	var payload interface{}
	if m.clientType == "newt" {
		payload = struct {
			ID        string `json:"newtId"`
			Token     string `json:"token"`
			PublicKey string `json:"publicKey"`
		}{
			ID:        ID,
			Token:     token,
			PublicKey: m.publicKey,
		}
	} else {
		payload = struct {
			ID        string `json:"olmId"`
			Token     string `json:"token"`
			PublicKey string `json:"publicKey"`
		}{
			ID:        ID,
			Token:     token,
			PublicKey: m.publicKey,
		}
	}

	// Convert payload to JSON
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Encrypt the payload using the server's WireGuard public key
	encryptedPayload, err := encryptPayload(payloadBytes, serverPubKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt payload: %w", err)
	}

	jsonData, err := json.Marshal(encryptedPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal encrypted payload: %w", err)
	}

	_, err = m.sharedBind.WriteToUDP(jsonData, remoteAddr)
	if err != nil {
		return fmt.Errorf("failed to write to UDP: %w", err)
	}

	logger.Debug("Sent UDP hole punch to %s: %s", remoteAddr.String(), string(jsonData))

	return nil
}

// encryptPayload encrypts the payload using ChaCha20-Poly1305 AEAD with X25519 key exchange
func encryptPayload(payload []byte, serverPublicKey string) (interface{}, error) {
	// Generate an ephemeral keypair for this message
	ephemeralPrivateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral private key: %v", err)
	}
	ephemeralPublicKey := ephemeralPrivateKey.PublicKey()

	// Parse the server's public key
	serverPubKey, err := wgtypes.ParseKey(serverPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse server public key: %v", err)
	}

	// Use X25519 for key exchange
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
	if _, err := mrand.Read(nonce); err != nil {
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
