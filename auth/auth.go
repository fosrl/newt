package auth

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
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

// TargetConfig holds a single backend target
type TargetConfig struct {
	TargetURL       string `json:"targetUrl"`
	Path            string `json:"path,omitempty"`
	PathMatchType   string `json:"pathMatchType,omitempty"`   // exact, prefix, regex
	RewritePath     string `json:"rewritePath,omitempty"`
	RewritePathType string `json:"rewritePathType,omitempty"` // exact, prefix, regex, stripPrefix
	Priority        int    `json:"priority,omitempty"`
}

// ResourceAuthConfig holds auth configuration for a specific resource
type ResourceAuthConfig struct {
	ResourceID            int               `json:"resourceId"`
	Domain                string            `json:"domain"`               // Full domain for the resource
	SSO                   bool              `json:"sso"`                  // SSO enabled
	BlockAccess           bool              `json:"blockAccess"`          // Block all access
	EmailWhitelistEnabled bool              `json:"emailWhitelistEnabled"`
	AllowedEmails         []string          `json:"allowedEmails"`
	SSL                   bool              `json:"ssl"`                  // Frontend TLS
	Targets               []TargetConfig    `json:"targets"`
	StickySession         bool              `json:"stickySession,omitempty"`
	TLSServerName         string            `json:"tlsServerName,omitempty"`
	SetHostHeader         string            `json:"setHostHeader,omitempty"`
	Headers               map[string]string `json:"headers,omitempty"`
	PostAuthPath          string            `json:"postAuthPath,omitempty"`
	rrIndex               uint64            // internal: atomic round-robin counter
}

// TLSCertificateConfig holds a TLS certificate pushed from Pangolin
type TLSCertificateConfig struct {
	Domain    string `json:"domain"`    // Domain this cert covers (may be wildcard like *.example.com)
	CertPEM   string `json:"certPem"`   // PEM-encoded certificate chain
	KeyPEM    string `json:"keyPem"`    // PEM-encoded private key
	ExpiresAt int64  `json:"expiresAt"` // Unix timestamp when cert expires
	Wildcard  bool   `json:"wildcard"`  // Whether this is a wildcard cert
}

// AuthProxyConfig is the full config message from Pangolin
type AuthProxyConfig struct {
	Action          string                  `json:"action"` // "update", "remove", "start", "stop"
	Auth            AuthConfig              `json:"auth"`
	Resources       []ResourceAuthConfig    `json:"resources"`
	TLSCertificates []TLSCertificateConfig  `json:"tlsCertificates,omitempty"`
}

// AuthProxy handles authentication for direct-routed resources
type AuthProxy struct {
	mu              sync.RWMutex
	config          AuthConfig
	resources       map[string]*ResourceAuthConfig // domain -> config
	servers         map[string]*http.Server        // domain -> server
	jwtPublicKey    *rsa.PublicKey
	httpClient      *http.Client
	proxyTransport  *http.Transport
	proxyCache      map[string]*httputil.ReverseProxy // target URL -> reverse proxy
	sessionCacheTTL time.Duration
	sessionMu       sync.RWMutex
	sessionCache    map[string]cachedSession
	running         bool
	ctx             context.Context
	cancel          context.CancelFunc
	listenAddr      string
	httpsListenAddr string
	httpsServer     *http.Server
	certStore       map[string]*tls.Certificate // domain -> parsed TLS cert (lowercase)
	certWildcards   map[string]*tls.Certificate // base domain -> wildcard cert (e.g. "example.com" -> *.example.com cert)
	hasCerts        bool                        // whether any TLS certs have been loaded
	httpBindFailed  bool                        // true if HTTP port was already in use (e.g. Traefik colocated)
	httpsBindFailed bool                        // true if HTTPS port was already in use
}

// NewAuthProxy creates a new auth proxy
func NewAuthProxy() *AuthProxy {
	ctx, cancel := context.WithCancel(context.Background())
	listenAddr := os.Getenv("NEWT_AUTH_PROXY_BIND")
	if listenAddr == "" {
		listenAddr = ":80"
	}
	httpsListenAddr := os.Getenv("NEWT_AUTH_PROXY_HTTPS_BIND")
	if httpsListenAddr == "" {
		httpsListenAddr = ":443"
	}

	proxyTransport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	sessionTransport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   20,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	sessionCacheTTL := sessionCacheTTLFromEnv()

	return &AuthProxy{
		resources:       make(map[string]*ResourceAuthConfig),
		servers:         make(map[string]*http.Server),
		certStore:       make(map[string]*tls.Certificate),
		certWildcards:   make(map[string]*tls.Certificate),
		httpClient: &http.Client{
			Timeout:   10 * time.Second,
			Transport: sessionTransport,
		},
		proxyTransport:  proxyTransport,
		proxyCache:      make(map[string]*httputil.ReverseProxy),
		sessionCacheTTL: sessionCacheTTL,
		sessionCache:    make(map[string]cachedSession),
		ctx:             ctx,
		cancel:          cancel,
		listenAddr:      listenAddr,
		httpsListenAddr: httpsListenAddr,
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
	if _, ok := p.resources[domain]; ok {
		p.proxyCache = make(map[string]*httputil.ReverseProxy)
	}

	// Store the resource config
	p.resources[domain] = &resource

	logger.Info("Auth Proxy: Updated resource %s (SSO: %v, BlockAccess: %v, Targets: %d)",
		domain, resource.SSO, resource.BlockAccess, len(resource.Targets))

	return nil
}

// RemoveResource removes a resource configuration
func (p *AuthProxy) RemoveResource(domain string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	domain = strings.ToLower(domain)
	if existing, ok := p.resources[domain]; ok {
		if len(existing.Targets) > 0 {
			p.proxyCache = make(map[string]*httputil.ReverseProxy)
		}
	}
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

	p.ctx, p.cancel = context.WithCancel(context.Background())

	// Try to bind the HTTP port. If another process owns it (e.g. Traefik
	// colocated on the same machine), log a clear message and skip the HTTP
	// listener but still mark as running so certs/resources are stored.
	httpUp := false
	listener, err := net.Listen("tcp", p.listenAddr)
	if err != nil {
		p.httpBindFailed = true
		logger.Warn("Auth Proxy: HTTP port %s is already in use by another process "+
			"(likely Traefik/Gerbil on this machine). HTTP listener skipped. "+
			"Set NEWT_AUTH_PROXY_BIND to use a different port.", p.listenAddr)
	} else {
		listener.Close()
		p.httpBindFailed = false

		// HTTP server: serves requests directly when no TLS certs are available,
		// otherwise redirects to HTTPS
		httpHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p.mu.RLock()
			hasCerts := p.hasCerts
			p.mu.RUnlock()

			if hasCerts {
				// Redirect HTTP → HTTPS
				host := r.Host
				if h, _, err := net.SplitHostPort(host); err == nil {
					host = h
				}
				target := "https://" + host + r.RequestURI
				http.Redirect(w, r, target, http.StatusMovedPermanently)
				return
			}
			// No TLS certs loaded: serve directly on HTTP
			p.ServeHTTP(w, r)
		})

		server := &http.Server{
			Addr:    p.listenAddr,
			Handler: httpHandler,
		}
		p.servers["__default__"] = server

		go func() {
			if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("Auth Proxy: HTTP server error on %s: %v", p.listenAddr, err)
			}
		}()
		httpUp = true
	}

	// Start HTTPS server if we have certificates
	if p.hasCerts {
		p.startHTTPSServerLocked()
	}

	p.running = true

	if httpUp {
		logger.Info("Auth Proxy: Started on %s", p.listenAddr)
	} else {
		logger.Info("Auth Proxy: Started (HTTP skipped — port in use; HTTPS will be attempted when certs arrive)")
	}
	return nil
}

// startHTTPSServerLocked starts the HTTPS server. Must be called with p.mu held.
func (p *AuthProxy) startHTTPSServerLocked() {
	if p.httpsServer != nil {
		return // already running
	}
	if p.httpsBindFailed {
		return // previously failed — don't retry until restart
	}

	// Preflight check — if the HTTPS port is in use, record and skip
	ln, err := net.Listen("tcp", p.httpsListenAddr)
	if err != nil {
		p.httpsBindFailed = true
		logger.Warn("Auth Proxy: HTTPS port %s is already in use by another process "+
			"(likely Traefik/Gerbil on this machine). HTTPS listener skipped. "+
			"Set NEWT_AUTH_PROXY_HTTPS_BIND to use a different port.", p.httpsListenAddr)
		return
	}
	ln.Close()

	tlsConfig := &tls.Config{
		GetCertificate: p.getCertificate,
		MinVersion:     tls.VersionTLS12,
	}

	p.httpsServer = &http.Server{
		Addr:      p.httpsListenAddr,
		Handler:   p, // use the same ServeHTTP handler
		TLSConfig: tlsConfig,
	}

	go func() {
		// ListenAndServeTLS with empty cert/key files because GetCertificate handles it
		if err := p.httpsServer.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("Auth Proxy: HTTPS server error on %s: %v", p.httpsListenAddr, err)
		}
	}()

	logger.Info("Auth Proxy: HTTPS server started on %s", p.httpsListenAddr)
}

// stopHTTPSServerLocked stops the HTTPS server. Must be called with p.mu held.
func (p *AuthProxy) stopHTTPSServerLocked() {
	if p.httpsServer == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p.httpsServer.Shutdown(ctx)
	p.httpsServer = nil
	logger.Info("Auth Proxy: HTTPS server stopped")
}

// getCertificate is the tls.Config.GetCertificate callback for SNI-based cert selection
func (p *AuthProxy) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	serverName := strings.ToLower(hello.ServerName)

	// Try exact domain match first
	if cert, ok := p.certStore[serverName]; ok {
		return cert, nil
	}

	// Try wildcard match: for "sub.example.com", check if we have a wildcard cert for "example.com"
	parts := strings.SplitN(serverName, ".", 2)
	if len(parts) == 2 {
		baseDomain := parts[1]
		if cert, ok := p.certWildcards[baseDomain]; ok {
			return cert, nil
		}
	}

	return nil, fmt.Errorf("no certificate found for %s", serverName)
}

// Stop stops the auth proxy
func (p *AuthProxy) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.running {
		return nil
	}

	p.cancel()

	// Stop HTTPS server
	p.stopHTTPSServerLocked()

	// Shutdown all HTTP servers
	for domain, server := range p.servers {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		server.Shutdown(ctx)
		cancel()
		logger.Debug("Auth Proxy: Stopped server for %s", domain)
	}
	p.servers = make(map[string]*http.Server)
	p.proxyCache = make(map[string]*httputil.ReverseProxy)
	if p.proxyTransport != nil {
		p.proxyTransport.CloseIdleConnections()
	}

	p.sessionMu.Lock()
	p.sessionCache = make(map[string]cachedSession)
	p.sessionMu.Unlock()

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

type cachedSession struct {
	claims    UserClaims
	expiresAt time.Time
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
	if claims, ok := p.getCachedSession(sessionToken); ok {
		return claims, nil
	}

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

	var validationResp sessionValidationAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&validationResp); err != nil {
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

	p.cacheSession(sessionToken, &claims, validationResp.Data.ExpiresAt)

	return &claims, nil
}

// redirectToLogin redirects the user to Pangolin's login page
func (p *AuthProxy) redirectToLogin(w http.ResponseWriter, r *http.Request, resource *ResourceAuthConfig) {
	p.mu.RLock()
	config := p.config
	p.mu.RUnlock()

	// Build the redirect-after-login URL
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	// If postAuthPath is set, redirect to that path after login instead of the original URL
	redirectTarget := fmt.Sprintf("%s://%s%s", scheme, r.Host, r.RequestURI)
	if resource.PostAuthPath != "" {
		redirectTarget = fmt.Sprintf("%s://%s%s", scheme, r.Host, resource.PostAuthPath)
	}

	// Build login URL with redirect
	loginURL := fmt.Sprintf("%s/auth/login?redirect=%s&resource=%d",
		config.PangolinURL,
		url.QueryEscape(redirectTarget),
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

// proxyToBackend selects a backend target, applies path rewriting, and proxies the request
func (p *AuthProxy) proxyToBackend(w http.ResponseWriter, r *http.Request, resource *ResourceAuthConfig) {
	target := p.selectTarget(r, resource)
	if target == nil {
		http.Error(w, "No available backend", http.StatusBadGateway)
		return
	}

	// Apply path rewriting before proxying
	applyPathRewrite(r, target)

	proxy, err := p.getOrCreateResourceProxy(resource, target)
	if err != nil {
		logger.Error("Auth Proxy: Failed to create proxy for resource %d target %s: %v", resource.ResourceID, target.TargetURL, err)
		http.Error(w, "Invalid backend configuration", http.StatusInternalServerError)
		return
	}

	// Set sticky session cookie if enabled and there are multiple targets
	if resource.StickySession && len(resource.Targets) > 1 {
		http.SetCookie(w, &http.Cookie{
			Name:     "p_sticky",
			Value:    target.TargetURL,
			Path:     "/",
			Secure:   resource.SSL,
			HttpOnly: true,
		})
	}

	proxy.ServeHTTP(w, r)
}

// selectTarget picks a backend target based on path matching, sticky sessions, and round-robin
func (p *AuthProxy) selectTarget(r *http.Request, resource *ResourceAuthConfig) *TargetConfig {
	targets := resource.Targets
	if len(targets) == 0 {
		return nil
	}
	if len(targets) == 1 {
		if matchesPath(r.URL.Path, &targets[0]) {
			return &targets[0]
		}
		// Single target with no path constraint always matches
		if targets[0].Path == "" {
			return &targets[0]
		}
		return nil
	}

	// Filter targets by path match
	var matched []*TargetConfig
	for i := range targets {
		if matchesPath(r.URL.Path, &targets[i]) {
			matched = append(matched, &targets[i])
		}
	}

	// If no path-specific targets matched, fall back to targets without path constraints
	if len(matched) == 0 {
		for i := range targets {
			if targets[i].Path == "" {
				matched = append(matched, &targets[i])
			}
		}
	}

	if len(matched) == 0 {
		return nil
	}
	if len(matched) == 1 {
		return matched[0]
	}

	// Sticky session: check cookie for target affinity
	if resource.StickySession {
		if cookie, err := r.Cookie("p_sticky"); err == nil {
			for _, t := range matched {
				if t.TargetURL == cookie.Value {
					return t
				}
			}
		}
	}

	// Round-robin across matched targets
	idx := atomic.AddUint64(&resource.rrIndex, 1) - 1
	return matched[idx%uint64(len(matched))]
}

// matchesPath checks if a request path matches a target's path constraints
func matchesPath(reqPath string, target *TargetConfig) bool {
	if target.Path == "" {
		return true
	}

	path := target.Path
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	switch target.PathMatchType {
	case "exact":
		return reqPath == path
	case "prefix":
		return strings.HasPrefix(reqPath, path)
	case "regex":
		matched, err := regexp.MatchString(target.Path, reqPath)
		return err == nil && matched
	default:
		return true
	}
}

// applyPathRewrite modifies the request URL path based on the target's rewrite configuration
func applyPathRewrite(r *http.Request, target *TargetConfig) {
	if target.RewritePathType == "" {
		return
	}

	switch target.RewritePathType {
	case "stripPrefix":
		if target.PathMatchType == "prefix" && target.Path != "" {
			prefix := target.Path
			if !strings.HasPrefix(prefix, "/") {
				prefix = "/" + prefix
			}
			r.URL.Path = strings.TrimPrefix(r.URL.Path, prefix)
			if r.URL.Path == "" {
				r.URL.Path = "/"
			}
			// If rewritePath is set, prepend it (acts as addPrefix after strip)
			if target.RewritePath != "" {
				r.URL.Path = target.RewritePath + r.URL.Path
			}
		}
	case "prefix":
		if target.Path != "" {
			escaped := regexp.QuoteMeta(target.Path)
			re, err := regexp.Compile("^" + escaped + "(.*)")
			if err == nil {
				r.URL.Path = re.ReplaceAllString(r.URL.Path, target.RewritePath+"$1")
			}
		}
	case "exact":
		if target.Path != "" {
			escaped := regexp.QuoteMeta(target.Path)
			re, err := regexp.Compile("^" + escaped + "$")
			if err == nil {
				r.URL.Path = re.ReplaceAllString(r.URL.Path, target.RewritePath)
			}
		}
	case "regex":
		if target.Path != "" {
			re, err := regexp.Compile(target.Path)
			if err == nil {
				r.URL.Path = re.ReplaceAllString(r.URL.Path, target.RewritePath)
			}
		}
	}

	// Ensure path always starts with /
	if !strings.HasPrefix(r.URL.Path, "/") {
		r.URL.Path = "/" + r.URL.Path
	}

	// Update RawPath as well
	r.URL.RawPath = r.URL.Path
}

// UpdateCertificates updates the TLS certificate store with certificates pushed from Pangolin.
// If certs are loaded for the first time and the proxy is already running, it starts the HTTPS server.
func (p *AuthProxy) UpdateCertificates(certs []TLSCertificateConfig) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	newStore := make(map[string]*tls.Certificate)
	newWildcards := make(map[string]*tls.Certificate)
	loaded := 0

	for _, certCfg := range certs {
		tlsCert, err := tls.X509KeyPair([]byte(certCfg.CertPEM), []byte(certCfg.KeyPEM))
		if err != nil {
			logger.Error("Auth Proxy: Failed to parse TLS cert for %s: %v", certCfg.Domain, err)
			continue
		}

		domain := strings.ToLower(certCfg.Domain)

		if certCfg.Wildcard {
			// Wildcard cert: domain is stored as the base domain (e.g. "example.com")
			// and covers *.example.com
			// Strip leading "*." if present
			baseDomain := domain
			if strings.HasPrefix(baseDomain, "*.") {
				baseDomain = baseDomain[2:]
			}
			newWildcards[baseDomain] = &tlsCert
			// Also store as exact match for the base domain itself
			newStore[baseDomain] = &tlsCert
			logger.Info("Auth Proxy: Loaded wildcard TLS cert for *.%s", baseDomain)
		} else {
			newStore[domain] = &tlsCert
			logger.Info("Auth Proxy: Loaded TLS cert for %s", domain)
		}
		loaded++
	}

	p.certStore = newStore
	p.certWildcards = newWildcards
	hadCerts := p.hasCerts
	p.hasCerts = loaded > 0

	// If we just got certs for the first time and the proxy is already running, start HTTPS
	if p.hasCerts && !hadCerts && p.running {
		p.startHTTPSServerLocked()
	}

	// If we lost all certs, stop HTTPS
	if !p.hasCerts && hadCerts {
		p.stopHTTPSServerLocked()
	}

	logger.Info("Auth Proxy: Certificate store updated with %d cert(s)", loaded)
	return nil
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
	p.proxyCache = make(map[string]*httputil.ReverseProxy)
	logger.Info("Auth Proxy: Replaced resource set with %d resources", len(resources))
}

// IsRunning returns whether the proxy is running
func (p *AuthProxy) IsRunning() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.running
}

// BindStatus returns whether each listener is active, skipped (port in use), or not started.
func (p *AuthProxy) BindStatus() (httpOk, httpsOk, httpSkipped, httpsSkipped bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	httpOk = p.running && !p.httpBindFailed && p.servers["__default__"] != nil
	httpsOk = p.running && !p.httpsBindFailed && p.httpsServer != nil
	httpSkipped = p.httpBindFailed
	httpsSkipped = p.httpsBindFailed
	return
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

func (p *AuthProxy) getCachedSession(sessionToken string) (*UserClaims, bool) {
	if sessionToken == "" || p.sessionCacheTTL <= 0 {
		return nil, false
	}

	now := time.Now()
	p.sessionMu.RLock()
	entry, exists := p.sessionCache[sessionToken]
	p.sessionMu.RUnlock()

	if !exists {
		return nil, false
	}

	if now.After(entry.expiresAt) {
		p.sessionMu.Lock()
		if current, ok := p.sessionCache[sessionToken]; ok && now.After(current.expiresAt) {
			delete(p.sessionCache, sessionToken)
		}
		p.sessionMu.Unlock()
		return nil, false
	}

	claimsCopy := entry.claims
	return &claimsCopy, true
}

func (p *AuthProxy) cacheSession(sessionToken string, claims *UserClaims, apiExpiresAt string) {
	if sessionToken == "" || claims == nil || p.sessionCacheTTL <= 0 {
		return
	}

	now := time.Now()
	expiresAt := now.Add(p.sessionCacheTTL)
	if parsed, ok := parseSessionExpiry(apiExpiresAt); ok && parsed.Before(expiresAt) {
		expiresAt = parsed
	}

	if !expiresAt.After(now) {
		return
	}

	claimsCopy := *claims
	p.sessionMu.Lock()
	p.sessionCache[sessionToken] = cachedSession{claims: claimsCopy, expiresAt: expiresAt}
	p.sessionMu.Unlock()
}

// getOrCreateResourceProxy creates or retrieves a cached reverse proxy for a resource+target combination.
// Each proxy is configured with the resource's TLS settings, host header, and custom headers.
func (p *AuthProxy) getOrCreateResourceProxy(resource *ResourceAuthConfig, target *TargetConfig) (*httputil.ReverseProxy, error) {
	cacheKey := fmt.Sprintf("%d:%s", resource.ResourceID, target.TargetURL)

	p.mu.RLock()
	if proxy, ok := p.proxyCache[cacheKey]; ok {
		p.mu.RUnlock()
		return proxy, nil
	}
	p.mu.RUnlock()

	targetURL, err := url.Parse(target.TargetURL)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if proxy, ok := p.proxyCache[cacheKey]; ok {
		return proxy, nil
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	// Determine host header: prefer setHostHeader, else use target host
	hostHeader := targetURL.Host
	if resource.SetHostHeader != "" {
		hostHeader = resource.SetHostHeader
	}

	// Capture custom headers for the Director closure
	customHeaders := resource.Headers

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		originalHost := req.Host
		req.Host = hostHeader
		req.Header.Set("X-Forwarded-Host", originalHost)

		// X-Forwarded-Proto based on incoming connection TLS state
		if req.TLS != nil {
			req.Header.Set("X-Forwarded-Proto", "https")
		} else {
			req.Header.Set("X-Forwarded-Proto", "http")
		}

		// X-Real-IP from remote address
		clientIP := req.RemoteAddr
		if host, _, splitErr := net.SplitHostPort(req.RemoteAddr); splitErr == nil {
			clientIP = host
		}
		req.Header.Set("X-Real-IP", clientIP)

		// Apply custom headers from resource config
		for name, value := range customHeaders {
			req.Header.Set(name, value)
		}
	}

	// Transport: use per-resource TLS config for HTTPS backends or when tlsServerName is set
	transport := p.proxyTransport
	if targetURL.Scheme == "https" || resource.TLSServerName != "" {
		transport = p.proxyTransport.Clone()
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
		if resource.TLSServerName != "" {
			transport.TLSClientConfig.ServerName = resource.TLSServerName
		}
	}
	proxy.Transport = transport

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, proxyErr error) {
		domain := r.Header.Get("X-Forwarded-Host")
		if domain == "" {
			domain = r.Host
		}
		logger.Error("Auth Proxy: Backend error for %s → %s: %v", domain, target.TargetURL, proxyErr)
		http.Error(w, "Backend unavailable", http.StatusBadGateway)
	}

	p.proxyCache[cacheKey] = proxy
	return proxy, nil
}

func sessionCacheTTLFromEnv() time.Duration {
	const defaultTTL = 15 * time.Second
	raw := strings.TrimSpace(os.Getenv("NEWT_AUTH_SESSION_CACHE_TTL"))
	if raw == "" {
		return defaultTTL
	}

	ttl, err := time.ParseDuration(raw)
	if err != nil || ttl < 0 {
		logger.Warn("Auth Proxy: Invalid NEWT_AUTH_SESSION_CACHE_TTL=%q, using default %s", raw, defaultTTL)
		return defaultTTL
	}

	return ttl
}

func parseSessionExpiry(value string) (time.Time, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return time.Time{}, false
	}

	if t, err := time.Parse(time.RFC3339Nano, trimmed); err == nil {
		return t, true
	}
	if t, err := time.Parse(time.RFC3339, trimmed); err == nil {
		return t, true
	}

	return time.Time{}, false
}
