package websocket

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"software.sslmate.com/src/go-pkcs12"

	"github.com/fosrl/newt/logger"
	"github.com/gorilla/websocket"

	"context"

	"github.com/fosrl/newt/internal/telemetry"
	"go.opentelemetry.io/otel"
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
	tlsConfig         TLSConfig
	metricsCtxMu      sync.RWMutex
	metricsCtx        context.Context
	configNeedsSave   bool // Flag to track if config needs to be saved
	serverVersion     string
	configVersion     int64        // Latest config version received from server
	configVersionMux  sync.RWMutex
	processingMessage bool           // Flag to track if a message is currently being processed
	processingMux     sync.RWMutex   // Protects processingMessage
	processingWg      sync.WaitGroup // WaitGroup to wait for message processing to complete
}

type ClientOption func(*Client)

type MessageHandler func(message WSMessage)

// TLSConfig holds TLS configuration options
type TLSConfig struct {
	// New separate certificate support
	ClientCertFile string
	ClientKeyFile  string
	CAFiles        []string

	// Existing PKCS12 support (deprecated)
	PKCS12File string
}

// WithBaseURL sets the base URL for the client
func WithBaseURL(url string) ClientOption {
	return func(c *Client) {
		c.baseURL = url
	}
}

// WithTLSConfig sets the TLS configuration for the client
func WithTLSConfig(config TLSConfig) ClientOption {
	return func(c *Client) {
		c.tlsConfig = config
		// For backward compatibility, also set the legacy field
		if config.PKCS12File != "" {
			c.config.TlsClientCert = config.PKCS12File
		}
	}
}

func (c *Client) OnConnect(callback func() error) {
	c.onConnect = callback
}

func (c *Client) OnTokenUpdate(callback func(token string)) {
	c.onTokenUpdate = callback
}

func (c *Client) metricsContext() context.Context {
	c.metricsCtxMu.RLock()
	defer c.metricsCtxMu.RUnlock()
	if c.metricsCtx != nil {
		return c.metricsCtx
	}
	return context.Background()
}

func (c *Client) setMetricsContext(ctx context.Context) {
	c.metricsCtxMu.Lock()
	c.metricsCtx = ctx
	c.metricsCtxMu.Unlock()
}

// MetricsContext exposes the context used for telemetry emission when a connection is active.
func (c *Client) MetricsContext() context.Context {
	return c.metricsContext()
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

func (c *Client) GetConfig() *Config {
	return c.config
}

func (c *Client) GetServerVersion() string {
	return c.serverVersion
}

// GetConfigVersion returns the latest config version received from server
func (c *Client) GetConfigVersion() int64 {
	c.configVersionMux.RLock()
	defer c.configVersionMux.RUnlock()
	return c.configVersion
}

// setConfigVersion updates the config version
func (c *Client) setConfigVersion(version int64) {
	c.configVersionMux.Lock()
	defer c.configVersionMux.Unlock()
	c.configVersion = version
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
	telemetry.SetWSConnectionState(false)

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
	if err := c.conn.WriteJSON(msg); err != nil {
		return err
	}
	telemetry.IncWSMessage(c.metricsContext(), "out", "text")
	return nil
}

// SendMessage sends a message through the WebSocket connection
func (c *Client) SendMessageNoLog(messageType string, data interface{}) error {
	if c.conn == nil {
		return fmt.Errorf("not connected")
	}

	msg := WSMessage{
		Type: messageType,
		Data: data,
	}

	c.writeMux.Lock()
	defer c.writeMux.Unlock()
	if err := c.conn.WriteJSON(msg); err != nil {
		return err
	}
	telemetry.IncWSMessage(c.metricsContext(), "out", "text")
	return nil
}

func (c *Client) SendMessageInterval(messageType string, data interface{}, interval time.Duration) (stop func()) {
	stopChan := make(chan struct{})
	go func() {
		count := 0
		maxAttempts := 10

		err := c.SendMessage(messageType, data) // Send immediately
		if err != nil {
			logger.Error("Failed to send initial message: %v", err)
		}
		count++

		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if count >= maxAttempts {
					logger.Info("SendMessageInterval timed out after %d attempts for message type: %s", maxAttempts, messageType)
					return
				}
				err = c.SendMessage(messageType, data)
				if err != nil {
					logger.Error("Failed to send message: %v", err)
				}
				count++
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

	// Use new TLS configuration method
	if c.tlsConfig.ClientCertFile != "" || c.tlsConfig.ClientKeyFile != "" || len(c.tlsConfig.CAFiles) > 0 || c.tlsConfig.PKCS12File != "" {
		tlsConfig, err = c.setupTLS()
		if err != nil {
			return "", fmt.Errorf("failed to setup TLS configuration: %w", err)
		}
	}

	// Check for environment variable to skip TLS verification
	if os.Getenv("SKIP_TLS_VERIFY") == "true" {
		if tlsConfig == nil {
			tlsConfig = &tls.Config{}
		}
		tlsConfig.InsecureSkipVerify = true
		logger.Debug("TLS certificate verification disabled via SKIP_TLS_VERIFY environment variable")
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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create a new request
	req, err := http.NewRequestWithContext(
		ctx,
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
		telemetry.IncConnAttempt(ctx, "auth", "failure")
		telemetry.IncConnError(ctx, "auth", classifyConnError(err))
		return "", fmt.Errorf("failed to request new token: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	logger.Debug("Token response body: %s", string(body))

	if resp.StatusCode != http.StatusOK {
		logger.Error("Failed to get token with status code: %d", resp.StatusCode)
		telemetry.IncConnAttempt(ctx, "auth", "failure")
		etype := "io_error"
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			etype = "auth_failed"
		}
		telemetry.IncConnError(ctx, "auth", etype)
		// Reconnect reason mapping for auth failures
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			telemetry.IncReconnect(ctx, c.config.ID, "client", telemetry.ReasonAuthError)
		}
		return "", fmt.Errorf("failed to get token with status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		logger.Error("Failed to decode token response.")
		return "", fmt.Errorf("failed to decode token response: %w", err)
	}

	if !tokenResp.Success {
		return "", fmt.Errorf("failed to get token: %s", tokenResp.Message)
	}

	if tokenResp.Data.Token == "" {
		return "", fmt.Errorf("received empty token from server")
	}

	// print server version
	logger.Info("Server version: %s", tokenResp.Data.ServerVersion)

	c.serverVersion = tokenResp.Data.ServerVersion

	logger.Debug("Received token: %s", tokenResp.Data.Token)
	telemetry.IncConnAttempt(ctx, "auth", "success")

	return tokenResp.Data.Token, nil
}

// classifyConnError maps to fixed, low-cardinality error_type values.
// Allowed enum: dial_timeout, tls_handshake, auth_failed, io_error
func classifyConnError(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "tls") || strings.Contains(msg, "certificate"):
		return "tls_handshake"
	case strings.Contains(msg, "timeout") || strings.Contains(msg, "i/o timeout") || strings.Contains(msg, "deadline exceeded"):
		return "dial_timeout"
	case strings.Contains(msg, "unauthorized") || strings.Contains(msg, "forbidden"):
		return "auth_failed"
	default:
		// Group remaining network/socket errors as io_error to avoid label explosion
		return "io_error"
	}
}

func classifyWSDisconnect(err error) (result, reason string) {
	if err == nil {
		return "success", "normal"
	}
	if websocket.IsCloseError(err, websocket.CloseNormalClosure) {
		return "success", "normal"
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return "error", "timeout"
	}
	if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
		return "error", "unexpected_close"
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "eof"):
		return "error", "eof"
	case strings.Contains(msg, "reset"):
		return "error", "connection_reset"
	default:
		return "error", "read_error"
	}
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
	ctx := context.Background()

	// Get token for authentication
	token, err := c.getToken()
	if err != nil {
		telemetry.IncConnAttempt(ctx, "websocket", "failure")
		telemetry.IncConnError(ctx, "websocket", classifyConnError(err))
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

	// Connect to WebSocket (optional span)
	tr := otel.Tracer("newt")
	ctx, span := tr.Start(ctx, "ws.connect")
	defer span.End()

	start := time.Now()
	dialer := websocket.DefaultDialer

	// Use new TLS configuration method
	if c.tlsConfig.ClientCertFile != "" || c.tlsConfig.ClientKeyFile != "" || len(c.tlsConfig.CAFiles) > 0 || c.tlsConfig.PKCS12File != "" {
		logger.Info("Setting up TLS configuration for WebSocket connection")
		tlsConfig, err := c.setupTLS()
		if err != nil {
			return fmt.Errorf("failed to setup TLS configuration: %w", err)
		}
		dialer.TLSClientConfig = tlsConfig
	}

	// Check for environment variable to skip TLS verification for WebSocket connection
	if os.Getenv("SKIP_TLS_VERIFY") == "true" {
		if dialer.TLSClientConfig == nil {
			dialer.TLSClientConfig = &tls.Config{}
		}
		dialer.TLSClientConfig.InsecureSkipVerify = true
		logger.Debug("WebSocket TLS certificate verification disabled via SKIP_TLS_VERIFY environment variable")
	}

	conn, _, err := dialer.DialContext(ctx, u.String(), nil)
	lat := time.Since(start).Seconds()
	if err != nil {
		telemetry.IncConnAttempt(ctx, "websocket", "failure")
		etype := classifyConnError(err)
		telemetry.IncConnError(ctx, "websocket", etype)
		telemetry.ObserveWSConnectLatency(ctx, lat, "failure", etype)
		// Map handshake-related errors to reconnect reasons where appropriate
		if etype == "tls_handshake" {
			telemetry.IncReconnect(ctx, c.config.ID, "client", telemetry.ReasonHandshakeError)
		} else if etype == "dial_timeout" {
			telemetry.IncReconnect(ctx, c.config.ID, "client", telemetry.ReasonTimeout)
		} else {
			telemetry.IncReconnect(ctx, c.config.ID, "client", telemetry.ReasonError)
		}
		telemetry.IncWSReconnect(ctx, etype)
		return fmt.Errorf("failed to connect to WebSocket: %w", err)
	}

	telemetry.IncConnAttempt(ctx, "websocket", "success")
	telemetry.ObserveWSConnectLatency(ctx, lat, "success", "")
	c.conn = conn
	c.setConnected(true)
	telemetry.SetWSConnectionState(true)
	c.setMetricsContext(ctx)
	sessionStart := time.Now()
	// Wire up pong handler for metrics
	c.conn.SetPongHandler(func(appData string) error {
		telemetry.IncWSMessage(c.metricsContext(), "in", "pong")
		return nil
	})

	// Start the ping monitor
	go c.pingMonitor()
	// Start the read pump with disconnect detection
	go c.readPumpWithDisconnectDetection(sessionStart)

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

// setupTLS configures TLS based on the TLS configuration
func (c *Client) setupTLS() (*tls.Config, error) {
	tlsConfig := &tls.Config{}

	// Handle new separate certificate configuration
	if c.tlsConfig.ClientCertFile != "" && c.tlsConfig.ClientKeyFile != "" {
		logger.Info("Loading separate certificate files for mTLS")
		logger.Debug("Client cert: %s", c.tlsConfig.ClientCertFile)
		logger.Debug("Client key: %s", c.tlsConfig.ClientKeyFile)

		// Load client certificate and key
		cert, err := tls.LoadX509KeyPair(c.tlsConfig.ClientCertFile, c.tlsConfig.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate pair: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}

		// Load CA certificates for remote validation if specified
		if len(c.tlsConfig.CAFiles) > 0 {
			logger.Debug("Loading CA certificates: %v", c.tlsConfig.CAFiles)
			caCertPool := x509.NewCertPool()
			for _, caFile := range c.tlsConfig.CAFiles {
				caCert, err := os.ReadFile(caFile)
				if err != nil {
					return nil, fmt.Errorf("failed to read CA file %s: %w", caFile, err)
				}

				// Try to parse as PEM first, then DER
				if !caCertPool.AppendCertsFromPEM(caCert) {
					// If PEM parsing failed, try DER
					cert, err := x509.ParseCertificate(caCert)
					if err != nil {
						return nil, fmt.Errorf("failed to parse CA certificate from %s: %w", caFile, err)
					}
					caCertPool.AddCert(cert)
				}
			}
			tlsConfig.RootCAs = caCertPool
		}

		return tlsConfig, nil
	}

	// Fallback to existing PKCS12 implementation for backward compatibility
	if c.tlsConfig.PKCS12File != "" {
		logger.Info("Loading PKCS12 certificate for mTLS (deprecated)")
		return c.setupPKCS12TLS()
	}

	// Legacy fallback using config.TlsClientCert
	if c.config.TlsClientCert != "" {
		logger.Info("Loading legacy PKCS12 certificate for mTLS (deprecated)")
		return loadClientCertificate(c.config.TlsClientCert)
	}

	return nil, nil
}

// setupPKCS12TLS loads TLS configuration from PKCS12 file
func (c *Client) setupPKCS12TLS() (*tls.Config, error) {
	return loadClientCertificate(c.tlsConfig.PKCS12File)
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

			// Skip ping if a message is currently being processed
			c.processingMux.RLock()
			isProcessing := c.processingMessage
			c.processingMux.RUnlock()
			if isProcessing {
				logger.Debug("Skipping ping, message is being processed")
				continue
			}

			c.configVersionMux.RLock()
			configVersion := c.configVersion
			c.configVersionMux.RUnlock()

			pingMsg := WSMessage{
				Type:          "newt/ping",
				Data:          map[string]interface{}{},
				ConfigVersion: configVersion,
			}

			c.writeMux.Lock()
			err := c.conn.WriteJSON(pingMsg)
			if err == nil {
				telemetry.IncWSMessage(c.metricsContext(), "out", "ping")
			}
			c.writeMux.Unlock()

			if err != nil {
				// Check if we're shutting down before logging error and reconnecting
				select {
				case <-c.done:
					// Expected during shutdown
					return
				default:
					logger.Error("Ping failed: %v", err)
					telemetry.IncWSKeepaliveFailure(c.metricsContext(), "ping_write")
					telemetry.IncWSReconnect(c.metricsContext(), "ping_write")
					c.reconnect()
					return
				}
			}
		}
	}
}

// readPumpWithDisconnectDetection reads messages and triggers reconnect on error
func (c *Client) readPumpWithDisconnectDetection(started time.Time) {
	ctx := c.metricsContext()
	disconnectReason := "shutdown"
	disconnectResult := "success"

	defer func() {
		if c.conn != nil {
			c.conn.Close()
		}
		if !started.IsZero() {
			telemetry.ObserveWSSessionDuration(ctx, time.Since(started).Seconds(), disconnectResult)
		}
		telemetry.IncWSDisconnect(ctx, disconnectReason, disconnectResult)
		// Only attempt reconnect if we're not shutting down
		select {
		case <-c.done:
			// Shutting down, don't reconnect
			return
		default:
			telemetry.IncWSReconnect(ctx, disconnectReason)
			c.reconnect()
		}
	}()

	for {
		select {
		case <-c.done:
			disconnectReason = "shutdown"
			disconnectResult = "success"
			return
		default:
			var msg WSMessage
			err := c.conn.ReadJSON(&msg)
			if err == nil {
				telemetry.IncWSMessage(c.metricsContext(), "in", "text")
			}
			if err != nil {
				// Check if we're shutting down before logging error
				select {
				case <-c.done:
					// Expected during shutdown, don't log as error
					logger.Debug("WebSocket connection closed during shutdown")
					disconnectReason = "shutdown"
					disconnectResult = "success"
					return
				default:
					// Unexpected error during normal operation
					disconnectResult, disconnectReason = classifyWSDisconnect(err)
					if disconnectResult == "error" {
						if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure, websocket.CloseNormalClosure) {
							logger.Error("WebSocket read error: %v", err)
						} else {
							logger.Debug("WebSocket connection closed: %v", err)
						}
					}
					return // triggers reconnect via defer
				}
			}

			// Update config version from incoming message
			c.setConfigVersion(msg.ConfigVersion)

			c.handlersMux.RLock()
			if handler, ok := c.handlers[msg.Type]; ok {
				// Mark that we're processing a message
				c.processingMux.Lock()
				c.processingMessage = true
				c.processingMux.Unlock()
				c.processingWg.Add(1)

				handler(msg)

				// Mark that we're done processing
				c.processingWg.Done()
				c.processingMux.Lock()
				c.processingMessage = false
				c.processingMux.Unlock()
			}
			c.handlersMux.RUnlock()
		}
	}
}

func (c *Client) reconnect() {
	c.setConnected(false)
	telemetry.SetWSConnectionState(false)
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

// LoadClientCertificate Helper method to load client certificates (PKCS12 format)
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
