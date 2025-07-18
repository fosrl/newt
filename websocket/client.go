package websocket

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"software.sslmate.com/src/go-pkcs12"

	"github.com/fosrl/newt/logger"
	"github.com/gorilla/websocket"
)

type Client struct {
	conn              *websocket.Conn
	config            *Config
	baseURL           string
	handlers          map[string]MessageHandler
	done              chan struct{}
	handlersMux       sync.RWMutex
	reconnectInterval time.Duration
	isConnected       bool
	reconnectMux      sync.RWMutex
	pingInterval      time.Duration
	pingTimeout       time.Duration
	onConnect         func() error
	onTokenUpdate     func(token string)
	writeMux          sync.Mutex
	clientType        string // Type of client (e.g., "newt", "olm")
}

type ClientOption func(*Client)

type MessageHandler func(message WSMessage)

// WithBaseURL sets the base URL for the client
func WithBaseURL(url string) ClientOption {
	return func(c *Client) {
		c.baseURL = url
	}
}

func WithTLSConfig(tlsClientCertPath string) ClientOption {
	return func(c *Client) {
		c.config.TlsClientCert = tlsClientCertPath
	}
}

func (c *Client) OnConnect(callback func() error) {
	c.onConnect = callback
}

func (c *Client) OnTokenUpdate(callback func(token string)) {
	c.onTokenUpdate = callback
}

// NewClient creates a new websocket client
func NewClient(clientType string, ID, secret string, endpoint string, pingInterval time.Duration, pingTimeout time.Duration, opts ...ClientOption) (*Client, error) {
	config := &Config{
		ID:       ID,
		Secret:   secret,
		Endpoint: endpoint,
	}

	client := &Client{
		config:            config,
		baseURL:           endpoint, // default value
		handlers:          make(map[string]MessageHandler),
		done:              make(chan struct{}),
		reconnectInterval: 3 * time.Second,
		isConnected:       false,
		pingInterval:      pingInterval,
		pingTimeout:       pingTimeout,
		clientType:        clientType,
	}

	// Apply options before loading config
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(client)
	}

	// Load existing config if available
	if err := client.loadConfig(); err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	return client, nil
}

// Connect establishes the WebSocket connection
func (c *Client) Connect() error {
	go c.connectWithRetry()
	return nil
}

// Close closes the WebSocket connection gracefully
func (c *Client) Close() error {
	// Signal shutdown to all goroutines first
	select {
	case <-c.done:
		// Already closed
		return nil
	default:
		close(c.done)
	}

	// Set connection status to false
	c.setConnected(false)

	// Close the WebSocket connection gracefully
	if c.conn != nil {
		// Send close message
		c.writeMux.Lock()
		c.conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		c.writeMux.Unlock()

		// Close the connection
		return c.conn.Close()
	}

	return nil
}

// SendMessage sends a message through the WebSocket connection
func (c *Client) SendMessage(messageType string, data interface{}) error {
	if c.conn == nil {
		return fmt.Errorf("not connected")
	}

	msg := WSMessage{
		Type: messageType,
		Data: data,
	}

	logger.Debug("Sending message: %s, data: %+v", messageType, data)

	c.writeMux.Lock()
	defer c.writeMux.Unlock()
	return c.conn.WriteJSON(msg)
}

func (c *Client) SendMessageInterval(messageType string, data interface{}, interval time.Duration) (stop func()) {
	stopChan := make(chan struct{})
	go func() {
		err := c.SendMessage(messageType, data) // Send immediately
		if err != nil {
			logger.Error("Failed to send initial message: %v", err)
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				err = c.SendMessage(messageType, data)
				if err != nil {
					logger.Error("Failed to send message: %v", err)
				}
			case <-stopChan:
				return
			}
		}
	}()
	return func() {
		close(stopChan)
	}
}

// RegisterHandler registers a handler for a specific message type
func (c *Client) RegisterHandler(messageType string, handler MessageHandler) {
	c.handlersMux.Lock()
	defer c.handlersMux.Unlock()
	c.handlers[messageType] = handler
}

func (c *Client) getToken() (string, error) {
	// Parse the base URL to ensure we have the correct hostname
	baseURL, err := url.Parse(c.baseURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse base URL: %w", err)
	}

	// Ensure we have the base URL without trailing slashes
	baseEndpoint := strings.TrimRight(baseURL.String(), "/")

	var tlsConfig *tls.Config = nil
	if c.config.TlsClientCert != "" {
		tlsConfig, err = loadClientCertificate(c.config.TlsClientCert)
		if err != nil {
			return "", fmt.Errorf("failed to load certificate %s: %w", c.config.TlsClientCert, err)
		}
	}

	var tokenData map[string]interface{}

	// Get a new token
	if c.clientType == "newt" {
		tokenData = map[string]interface{}{
			"newtId": c.config.ID,
			"secret": c.config.Secret,
		}
	} else if c.clientType == "olm" {
		tokenData = map[string]interface{}{
			"olmId":  c.config.ID,
			"secret": c.config.Secret,
		}
	}
	jsonData, err := json.Marshal(tokenData)

	if err != nil {
		return "", fmt.Errorf("failed to marshal token request data: %w", err)
	}

	// Create a new request
	req, err := http.NewRequest(
		"POST",
		baseEndpoint+"/api/v1/auth/"+c.clientType+"/get-token",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", "x-csrf-protection")

	// Make the request
	client := &http.Client{}
	if tlsConfig != nil {
		client.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to request new token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Error("Failed to get token with status code: %d", resp.StatusCode)
		return "", fmt.Errorf("failed to get token with status code: %d", resp.StatusCode)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		logger.Error("Failed to decode token response.")
		return "", fmt.Errorf("failed to decode token response: %w", err)
	}

	if !tokenResp.Success {
		return "", fmt.Errorf("failed to get token: %s", tokenResp.Message)
	}

	if tokenResp.Data.Token == "" {
		return "", fmt.Errorf("received empty token from server")
	}

	logger.Debug("Received token: %s", tokenResp.Data.Token)

	return tokenResp.Data.Token, nil
}

func (c *Client) connectWithRetry() {
	for {
		select {
		case <-c.done:
			return
		default:
			err := c.establishConnection()
			if err != nil {
				logger.Error("Failed to connect: %v. Retrying in %v...", err, c.reconnectInterval)
				time.Sleep(c.reconnectInterval)
				continue
			}
			return
		}
	}
}

func (c *Client) establishConnection() error {
	// Get token for authentication
	token, err := c.getToken()
	if err != nil {
		return fmt.Errorf("failed to get token: %w", err)
	}

	if c.onTokenUpdate != nil {
		c.onTokenUpdate(token)
	}

	// Parse the base URL to determine protocol and hostname
	baseURL, err := url.Parse(c.baseURL)
	if err != nil {
		return fmt.Errorf("failed to parse base URL: %w", err)
	}

	// Determine WebSocket protocol based on HTTP protocol
	wsProtocol := "wss"
	if baseURL.Scheme == "http" {
		wsProtocol = "ws"
	}

	// Create WebSocket URL
	wsURL := fmt.Sprintf("%s://%s/api/v1/ws", wsProtocol, baseURL.Host)
	u, err := url.Parse(wsURL)
	if err != nil {
		return fmt.Errorf("failed to parse WebSocket URL: %w", err)
	}

	// Add token to query parameters
	q := u.Query()
	q.Set("token", token)
	q.Set("clientType", c.clientType)
	u.RawQuery = q.Encode()

	// Connect to WebSocket
	dialer := websocket.DefaultDialer
	if c.config.TlsClientCert != "" {
		logger.Info("Adding tls to req")
		tlsConfig, err := loadClientCertificate(c.config.TlsClientCert)
		if err != nil {
			return fmt.Errorf("failed to load certificate %s: %w", c.config.TlsClientCert, err)
		}
		dialer.TLSClientConfig = tlsConfig
	}
	conn, _, err := dialer.Dial(u.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to connect to WebSocket: %w", err)
	}

	c.conn = conn
	c.setConnected(true)

	// Start the ping monitor
	go c.pingMonitor()
	// Start the read pump with disconnect detection
	go c.readPumpWithDisconnectDetection()

	if c.onConnect != nil {
		err := c.saveConfig()
		if err != nil {
			logger.Error("Failed to save config: %v", err)
		}
		if err := c.onConnect(); err != nil {
			logger.Error("OnConnect callback failed: %v", err)
		}
	}

	return nil
}

// pingMonitor sends pings at a short interval and triggers reconnect on failure
func (c *Client) pingMonitor() {
	ticker := time.NewTicker(c.pingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			if c.conn == nil {
				return
			}
			c.writeMux.Lock()
			err := c.conn.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(c.pingTimeout))
			c.writeMux.Unlock()
			if err != nil {
				// Check if we're shutting down before logging error and reconnecting
				select {
				case <-c.done:
					// Expected during shutdown
					return
				default:
					logger.Error("Ping failed: %v", err)
					c.reconnect()
					return
				}
			}
		}
	}
}

// readPumpWithDisconnectDetection reads messages and triggers reconnect on error
func (c *Client) readPumpWithDisconnectDetection() {
	defer func() {
		if c.conn != nil {
			c.conn.Close()
		}
		// Only attempt reconnect if we're not shutting down
		select {
		case <-c.done:
			// Shutting down, don't reconnect
			return
		default:
			c.reconnect()
		}
	}()

	for {
		select {
		case <-c.done:
			return
		default:
			var msg WSMessage
			err := c.conn.ReadJSON(&msg)
			if err != nil {
				// Check if we're shutting down before logging error
				select {
				case <-c.done:
					// Expected during shutdown, don't log as error
					logger.Debug("WebSocket connection closed during shutdown")
					return
				default:
					// Unexpected error during normal operation
					if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure, websocket.CloseNormalClosure) {
						logger.Error("WebSocket read error: %v", err)
					} else {
						logger.Debug("WebSocket connection closed: %v", err)
					}
					return // triggers reconnect via defer
				}
			}

			c.handlersMux.RLock()
			if handler, ok := c.handlers[msg.Type]; ok {
				handler(msg)
			}
			c.handlersMux.RUnlock()
		}
	}
}

func (c *Client) reconnect() {
	c.setConnected(false)
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}

	// Only reconnect if we're not shutting down
	select {
	case <-c.done:
		return
	default:
		go c.connectWithRetry()
	}
}

func (c *Client) setConnected(status bool) {
	c.reconnectMux.Lock()
	defer c.reconnectMux.Unlock()
	c.isConnected = status
}

// LoadClientCertificate Helper method to load client certificates
func loadClientCertificate(p12Path string) (*tls.Config, error) {
	logger.Info("Loading tls-client-cert %s", p12Path)
	// Read the PKCS12 file
	p12Data, err := os.ReadFile(p12Path)
	if err != nil {
		return nil, fmt.Errorf("failed to read PKCS12 file: %w", err)
	}

	// Parse PKCS12 with empty password for non-encrypted files
	privateKey, certificate, caCerts, err := pkcs12.DecodeChain(p12Data, "")
	if err != nil {
		return nil, fmt.Errorf("failed to decode PKCS12: %w", err)
	}

	// Create certificate
	cert := tls.Certificate{
		Certificate: [][]byte{certificate.Raw},
		PrivateKey:  privateKey,
	}

	// Optional: Add CA certificates if present
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("failed to load system cert pool: %w", err)
	}
	if len(caCerts) > 0 {
		for _, caCert := range caCerts {
			rootCAs.AddCert(caCert)
		}
	}

	// Create TLS configuration
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      rootCAs,
	}, nil
}
