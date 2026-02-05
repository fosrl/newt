package auth

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/fosrl/newt/logger"
	"github.com/golang-jwt/jwt/v5"
)

// AuthConfig holds the authentication configuration synced from Pangolin
type AuthConfig struct {
	Enabled              bool     `json:"enabled"`
	PangolinURL          string   `json:"pangolinUrl"`          // e.g., "https://pangolin.example.com"
	JWTPublicKey         string   `json:"jwtPublicKey"`         // PEM-encoded RSA public key
	CookieName           string   `json:"cookieName"`           // Session cookie name
	CookieDomain         string   `json:"cookieDomain"`         // Shared cookie domain
	SessionValidationURL string   `json:"sessionValidationUrl"` // API endpoint to validate sessions
	AllowedEmails        []string `json:"allowedEmails"`        // Email whitelist (if enabled)
	EmailWhitelistEnabled bool    `json:"emailWhitelistEnabled"`
}

// ResourceAuthConfig holds auth configuration for a specific resource
type ResourceAuthConfig struct {
	ResourceID           int      `json:"resourceId"`
	Domain               string   `json:"domain"`               // Full domain for the resource
	SSO                  bool     `json:"sso"`                  // SSO enabled
	BlockAccess          bool     `json:"blockAccess"`          // Block all access
	EmailWhitelistEnabled bool    `json:"emailWhitelistEnabled"`
	AllowedEmails        []string `json:"allowedEmails"`
	TargetURL            string   `json:"targetUrl"`            // Backend target URL
	SSL                  bool     `json:"ssl"`                  // Use SSL for backend
}

// AuthProxyConfig is the full config message from Pangolin
type AuthProxyConfig struct {
	Action    string               `json:"action"` // "update", "remove", "start", "stop"
	Auth      AuthConfig           `json:"auth"`
	Resources []ResourceAuthConfig `json:"resources"`
}

// AuthProxy handles authentication for direct-routed resources
type AuthProxy struct {
	mu              sync.RWMutex
	config          AuthConfig
	resources       map[string]*ResourceAuthConfig // domain -> config
	servers         map[string]*http.Server        // domain -> server
	jwtPublicKey    *rsa.PublicKey
	httpClient      *http.Client
	running         bool
	ctx             context.Context
	cancel          context.CancelFunc
	listenAddr      string
}

// NewAuthProxy creates a new auth proxy
func NewAuthProxy() *AuthProxy {
	ctx, cancel := context.WithCancel(context.Background())
	listenAddr := os.Getenv("NEWT_AUTH_PROXY_BIND")
	if listenAddr == "" {
		listenAddr = ":80"
	}

	return &AuthProxy{
		resources: make(map[string]*ResourceAuthConfig),
		servers:   make(map[string]*http.Server),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		ctx:        ctx,
		cancel:     cancel,
		listenAddr: listenAddr,
	}
}

// UpdateConfig updates the global auth configuration
func (p *AuthProxy) UpdateConfig(config AuthConfig) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.config = config

	// Parse JWT public key if provided
	if config.JWTPublicKey != "" {
		key, err := parseRSAPublicKey(config.JWTPublicKey)
		if err != nil {
			return fmt.Errorf("failed to parse JWT public key: %w", err)
		}
		p.jwtPublicKey = key
		logger.Info("Auth Proxy: Updated JWT public key")
	}

	return nil
}

// UpdateResource updates or adds a resource auth configuration
func (p *AuthProxy) UpdateResource(resource ResourceAuthConfig) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	domain := strings.ToLower(resource.Domain)

	// Store the resource config
	p.resources[domain] = &resource

	logger.Info("Auth Proxy: Updated resource %s (SSO: %v, BlockAccess: %v)",
		domain, resource.SSO, resource.BlockAccess)

	return nil
}

// RemoveResource removes a resource configuration
func (p *AuthProxy) RemoveResource(domain string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	domain = strings.ToLower(domain)
	delete(p.resources, domain)

	// Stop server if running for this domain
	if server, exists := p.servers[domain]; exists {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(ctx)
		delete(p.servers, domain)
	}

	logger.Info("Auth Proxy: Removed resource %s", domain)
}

// Start starts the auth proxy
func (p *AuthProxy) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.running {
		return nil
	}

	listener, err := net.Listen("tcp", p.listenAddr)
	if err != nil {
		return fmt.Errorf("auth proxy failed to bind on %s: %w", p.listenAddr, err)
	}
	if err := listener.Close(); err != nil {
		return fmt.Errorf("auth proxy preflight close failed: %w", err)
	}

	p.ctx, p.cancel = context.WithCancel(context.Background())

	server := &http.Server{
		Addr:    p.listenAddr,
		Handler: p,
	}
	p.servers["__default__"] = server

	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("Auth Proxy: HTTP server error on %s: %v", p.listenAddr, err)
		}
	}()

	p.running = true
	logger.Info("Auth Proxy: Started on %s", p.listenAddr)
	return nil
}

// Stop stops the auth proxy
func (p *AuthProxy) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.running {
		return nil
	}

	p.cancel()

	// Shutdown all servers
	for domain, server := range p.servers {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		server.Shutdown(ctx)
		cancel()
		logger.Debug("Auth Proxy: Stopped server for %s", domain)
	}
	p.servers = make(map[string]*http.Server)

	p.running = false
	logger.Info("Auth Proxy: Stopped")
	return nil
}

// ServeHTTP handles incoming requests with authentication
func (p *AuthProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(r.Host)
	// Remove port if present
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	p.mu.RLock()
	resource, exists := p.resources[host]
	config := p.config
	p.mu.RUnlock()

	if !exists {
		http.Error(w, "Resource not found", http.StatusNotFound)
		return
	}

	// Check if access is blocked
	if resource.BlockAccess {
		http.Error(w, "Access blocked", http.StatusForbidden)
		return
	}

	// If SSO is enabled, validate authentication
	if resource.SSO && config.Enabled {
		user, err := p.validateAuth(r)
		if err != nil {
			logger.Debug("Auth Proxy: Auth validation failed for %s: %v", host, err)
			p.redirectToLogin(w, r, resource)
			return
		}

		// Check email whitelist if enabled
		if resource.EmailWhitelistEnabled && len(resource.AllowedEmails) > 0 {
			if !p.isEmailAllowed(user.Email, resource.AllowedEmails) {
				http.Error(w, "Access denied: email not in whitelist", http.StatusForbidden)
				return
			}
		}

		// Add user info to headers for the backend
		r.Header.Set("X-Auth-User", user.Email)
		r.Header.Set("X-Auth-User-ID", user.UserID)
	}

	// Proxy to backend
	p.proxyToBackend(w, r, resource)
}

// UserClaims represents the claims in a Pangolin JWT
type UserClaims struct {
	jwt.RegisteredClaims
	UserID    string   `json:"userId"`
	Email     string   `json:"email"`
	OrgID     string   `json:"orgId"`
	Resources []int    `json:"resources"` // Resource IDs the user can access
}

type sessionValidationData struct {
	Valid     bool   `json:"valid"`
	UserID    string `json:"userId"`
	Email     string `json:"email"`
	OrgID     string `json:"orgId"`
	ExpiresAt string `json:"expiresAt"`
}

type sessionValidationAPIResponse struct {
	Data    sessionValidationData `json:"data"`
	Success bool                  `json:"success"`
	Error   bool                  `json:"error"`
	Message string                `json:"message"`
}

// validateAuth validates the request authentication
func (p *AuthProxy) validateAuth(r *http.Request) (*UserClaims, error) {
	p.mu.RLock()
	config := p.config
	publicKey := p.jwtPublicKey
	p.mu.RUnlock()

	// Try to get token from cookie
	cookie, err := r.Cookie(config.CookieName)
	if err != nil {
		// Try Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			return nil, fmt.Errorf("no auth token found")
		}

		// Extract Bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			return nil, fmt.Errorf("invalid authorization header")
		}

		return p.validateJWT(parts[1], publicKey)
	}

	// Validate cookie token
	return p.validateJWT(cookie.Value, publicKey)
}

// validateJWT validates a JWT token
func (p *AuthProxy) validateJWT(tokenString string, publicKey *rsa.PublicKey) (*UserClaims, error) {
	if publicKey != nil {
		token, err := jwt.ParseWithClaims(tokenString, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return publicKey, nil
		})

		if err == nil {
			claims, ok := token.Claims.(*UserClaims)
			if ok && token.Valid {
				return claims, nil
			}
		}

		// If JWT validation fails (e.g. it's an opaque session token, or expired),
		// fall back to session validation against the Pangolin API.
		logger.Debug("Auth Proxy: JWT validation failed/skipped, falling back to session API")
	}

	return p.validateSession(tokenString)
}

// validateSession validates a session token against Pangolin's API
func (p *AuthProxy) validateSession(sessionToken string) (*UserClaims, error) {
	p.mu.RLock()
	config := p.config
	p.mu.RUnlock()

	if config.SessionValidationURL == "" {
		return nil, fmt.Errorf("session validation not configured")
	}

	req, err := http.NewRequest("GET", config.SessionValidationURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Cookie", fmt.Sprintf("%s=%s", config.CookieName, sessionToken))

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("session validation request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("session invalid: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var validationResp sessionValidationAPIResponse
	if err := json.Unmarshal(body, &validationResp); err != nil {
		return nil, fmt.Errorf("failed to parse session response: %w", err)
	}

	if !validationResp.Data.Valid {
		return nil, fmt.Errorf("session invalid")
	}

	if validationResp.Data.UserID == "" {
		return nil, fmt.Errorf("session validation response missing userId")
	}

	claims := UserClaims{
		UserID: validationResp.Data.UserID,
		Email:  validationResp.Data.Email,
		OrgID:  validationResp.Data.OrgID,
	}

	return &claims, nil
}

// redirectToLogin redirects the user to Pangolin's login page
func (p *AuthProxy) redirectToLogin(w http.ResponseWriter, r *http.Request, resource *ResourceAuthConfig) {
	p.mu.RLock()
	config := p.config
	p.mu.RUnlock()

	// Build the original URL for redirect after login
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	originalURL := fmt.Sprintf("%s://%s%s", scheme, r.Host, r.RequestURI)

	// Build login URL with redirect
	loginURL := fmt.Sprintf("%s/auth/login?redirect=%s&resource=%d",
		config.PangolinURL,
		url.QueryEscape(originalURL),
		resource.ResourceID,
	)

	http.Redirect(w, r, loginURL, http.StatusFound)
}

// isEmailAllowed checks if an email is in the allowed list
func (p *AuthProxy) isEmailAllowed(email string, allowedEmails []string) bool {
	email = strings.ToLower(email)
	for _, allowed := range allowedEmails {
		allowed = strings.ToLower(allowed)
		if allowed == email {
			return true
		}
		// Support wildcard domain matching like *@example.com
		if strings.HasPrefix(allowed, "*@") {
			domain := allowed[2:]
			if strings.HasSuffix(email, "@"+domain) {
				return true
			}
		}
	}
	return false
}

// proxyToBackend proxies the request to the backend target
func (p *AuthProxy) proxyToBackend(w http.ResponseWriter, r *http.Request, resource *ResourceAuthConfig) {
	targetURL, err := url.Parse(resource.TargetURL)
	if err != nil {
		http.Error(w, "Invalid backend configuration", http.StatusInternalServerError)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	// Modify the request
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = targetURL.Host
		req.Header.Set("X-Forwarded-Host", r.Host)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Real-IP", r.RemoteAddr)
	}

	// Handle errors
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		logger.Error("Auth Proxy: Backend error for %s: %v", resource.Domain, err)
		http.Error(w, "Backend unavailable", http.StatusBadGateway)
	}

	proxy.ServeHTTP(w, r)
}

// GetResource returns the auth config for a domain
func (p *AuthProxy) GetResource(domain string) *ResourceAuthConfig {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.resources[strings.ToLower(domain)]
}

// ReplaceResources replaces the full in-memory resource configuration set.
func (p *AuthProxy) ReplaceResources(resources []ResourceAuthConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()

	newResources := make(map[string]*ResourceAuthConfig, len(resources))
	for _, resource := range resources {
		resourceCopy := resource
		domain := strings.ToLower(resourceCopy.Domain)
		newResources[domain] = &resourceCopy
	}

	p.resources = newResources
	logger.Info("Auth Proxy: Replaced resource set with %d resources", len(resources))
}

// IsRunning returns whether the proxy is running
func (p *AuthProxy) IsRunning() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.running
}

// parseRSAPublicKey parses a PEM-encoded RSA public key
func parseRSAPublicKey(pemStr string) (*rsa.PublicKey, error) {
	// Try PEM decode first
	block, _ := pem.Decode([]byte(pemStr))
	if block != nil {
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("not an RSA public key")
		}
		return rsaPub, nil
	}

	// Try base64 decode
	decoded, err := base64.StdEncoding.DecodeString(pemStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	pub, err := x509.ParsePKIXPublicKey(decoded)
	if err != nil {
		return nil, err
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	return rsaPub, nil
}
