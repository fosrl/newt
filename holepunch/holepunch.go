package holepunch

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/fosrl/newt/bind"
	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/util"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/exp/rand"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// ExitNode represents a WireGuard exit node for hole punching
type ExitNode struct {
	Endpoint  string `json:"endpoint"`
	PublicKey string `json:"publicKey"`
}

// Manager handles UDP hole punching operations
type Manager struct {
	mu         sync.Mutex
	running    bool
	stopChan   chan struct{}
	sharedBind *bind.SharedBind
	ID         string
	token      string
	clientType string
}

// NewManager creates a new hole punch manager
func NewManager(sharedBind *bind.SharedBind, ID string, clientType string) *Manager {
	return &Manager{
		sharedBind: sharedBind,
		ID:         ID,
		clientType: clientType,
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

	m.running = false
	logger.Info("Hole punch manager stopped")
}

// StartMultipleExitNodes starts hole punching to multiple exit nodes
func (m *Manager) StartMultipleExitNodes(exitNodes []ExitNode) error {
	m.mu.Lock()

	if m.running {
		m.mu.Unlock()
		logger.Debug("UDP hole punch already running, skipping new request")
		return fmt.Errorf("hole punch already running")
	}

	if len(exitNodes) == 0 {
		m.mu.Unlock()
		logger.Warn("No exit nodes provided for hole punching")
		return fmt.Errorf("no exit nodes provided")
	}

	m.running = true
	m.stopChan = make(chan struct{})
	m.mu.Unlock()

	logger.Info("Starting UDP hole punch to %d exit nodes with shared bind", len(exitNodes))

	go m.runMultipleExitNodes(exitNodes)

	return nil
}

// StartSingleEndpoint starts hole punching to a single endpoint (legacy mode)
func (m *Manager) StartSingleEndpoint(endpoint, serverPubKey string) error {
	m.mu.Lock()

	if m.running {
		m.mu.Unlock()
		logger.Debug("UDP hole punch already running, skipping new request")
		return fmt.Errorf("hole punch already running")
	}

	m.running = true
	m.stopChan = make(chan struct{})
	m.mu.Unlock()

	logger.Info("Starting UDP hole punch to %s with shared bind", endpoint)

	go m.runSingleEndpoint(endpoint, serverPubKey)

	return nil
}

// runMultipleExitNodes performs hole punching to multiple exit nodes
func (m *Manager) runMultipleExitNodes(exitNodes []ExitNode) {
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

	var resolvedNodes []resolvedExitNode
	for _, exitNode := range exitNodes {
		host, err := util.ResolveDomain(exitNode.Endpoint)
		if err != nil {
			logger.Warn("Failed to resolve endpoint %s: %v", exitNode.Endpoint, err)
			continue
		}

		serverAddr := net.JoinHostPort(host, "21820")
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
		logger.Info("Resolved exit node: %s -> %s", exitNode.Endpoint, remoteAddr.String())
	}

	if len(resolvedNodes) == 0 {
		logger.Error("No exit nodes could be resolved")
		return
	}

	// Send initial hole punch to all exit nodes
	for _, node := range resolvedNodes {
		if err := m.sendHolePunch(node.remoteAddr, node.publicKey); err != nil {
			logger.Warn("Failed to send initial hole punch to %s: %v", node.endpointName, err)
		}
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()

	for {
		select {
		case <-m.stopChan:
			logger.Debug("Hole punch stopped by signal")
			return
		case <-timeout.C:
			logger.Debug("Hole punch timeout reached")
			return
		case <-ticker.C:
			// Send hole punch to all exit nodes
			for _, node := range resolvedNodes {
				if err := m.sendHolePunch(node.remoteAddr, node.publicKey); err != nil {
					logger.Debug("Failed to send hole punch to %s: %v", node.endpointName, err)
				}
			}
		}
	}
}

// runSingleEndpoint performs hole punching to a single endpoint
func (m *Manager) runSingleEndpoint(endpoint, serverPubKey string) {
	defer func() {
		m.mu.Lock()
		m.running = false
		m.mu.Unlock()
		logger.Info("UDP hole punch goroutine ended for %s", endpoint)
	}()

	host, err := util.ResolveDomain(endpoint)
	if err != nil {
		logger.Error("Failed to resolve domain %s: %v", endpoint, err)
		return
	}

	serverAddr := net.JoinHostPort(host, "21820")

	remoteAddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		logger.Error("Failed to resolve UDP address %s: %v", serverAddr, err)
		return
	}

	// Execute once immediately before starting the loop
	if err := m.sendHolePunch(remoteAddr, serverPubKey); err != nil {
		logger.Warn("Failed to send initial hole punch: %v", err)
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()

	for {
		select {
		case <-m.stopChan:
			logger.Debug("Hole punch stopped by signal")
			return
		case <-timeout.C:
			logger.Debug("Hole punch timeout reached")
			return
		case <-ticker.C:
			if err := m.sendHolePunch(remoteAddr, serverPubKey); err != nil {
				logger.Debug("Failed to send hole punch: %v", err)
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
			ID    string `json:"newtId"`
			Token string `json:"token"`
		}{
			ID:    ID,
			Token: token,
		}
	} else {
		payload = struct {
			ID    string `json:"olmId"`
			Token string `json:"token"`
		}{
			ID:    ID,
			Token: token,
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
