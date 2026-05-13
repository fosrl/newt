package browsergateway

import (
	"errors"
	"net"
	"net/http"
	"sync"
)

// Forwarding buffer size. RDP graphics traffic is bursty and TLS records cap
// at ~16 KiB, so 64 KiB lets a couple of records pile up per syscall/frame
// without wasting memory per session.
const forwardBufSize = 64 * 1024

// ListenPort is the port the browser gateway HTTP server listens on inside the
// WireGuard netstack. This is a fixed value shared between newt and pangolin.
const ListenPort = 8082

// HardcodedAuthToken is a temporary shared secret used during development.
// TODO: replace with a per-session token negotiated with pangolin.
const HardcodedAuthToken = "pangolin-browser-gateway-dev"

// Target represents an allowed proxy destination for the browser gateway.
// Only connections whose (Type, Destination, DestinationPort) match a
// registered Target will be forwarded; all others are rejected.
type Target struct {
	ID              int
	Type            string // "rdp" | "ssh" | "vnc"
	Destination     string
	DestinationPort int
}

// Config holds the configuration for a Gateway.
type Config struct {
	// AuthToken is the shared secret required by RDP clients in the RDCleanPath
	// ProxyAuth field, and by SSH clients as the authToken query parameter.
	AuthToken string
	// NativeSSH, when non-nil, configures a local PTY/shell SSH mode instead
	// of proxying to an external SSH server.
	NativeSSH *NativeSSHConfig
}

// Gateway is a browser-based RDP/SSH/VNC WebSocket proxy.
// Create one with New and mount it via RegisterHandlers or the individual
// HandleRDP / HandleSSH / HandleVNC http.HandlerFunc methods.
type Gateway struct {
	authToken string
	nativeSSH *NativeSSHConfig

	mu      sync.RWMutex
	targets map[int]Target // keyed by Target.ID

	server *http.Server
}

// New creates a new Gateway from the provided Config.
func New(cfg Config) *Gateway {
	return &Gateway{
		authToken: cfg.AuthToken,
		nativeSSH: cfg.NativeSSH,
		targets:   make(map[int]Target),
	}
}

// SetTargets replaces the entire allowed-destination list atomically.
func (g *Gateway) SetTargets(targets []Target) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.targets = make(map[int]Target, len(targets))
	for _, t := range targets {
		g.targets[t.ID] = t
	}
}

// AddTarget adds or updates a single allowed destination.
func (g *Gateway) AddTarget(t Target) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.targets[t.ID] = t
}

// RemoveTarget removes an allowed destination by its ID.
func (g *Gateway) RemoveTarget(id int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.targets, id)
}

// isAllowed reports whether a connection to (targetType, host, port) is
// permitted by the current target list.
func (g *Gateway) isAllowed(targetType, host string, port int) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	for _, t := range g.targets {
		if t.Type == targetType && t.Destination == host && t.DestinationPort == port {
			return true
		}
	}
	return false
}

// Start serves the browser gateway HTTP server on the provided listener.
// It returns nil when the listener is closed (normal shutdown).
func (g *Gateway) Start(ln net.Listener) error {
	mux := http.NewServeMux()
	g.RegisterHandlers(mux)
	g.server = &http.Server{Handler: mux}
	err := g.server.Serve(ln)
	if errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// RegisterHandlers registers the /rdp, /ssh, and /vnc routes on mux.
func (g *Gateway) RegisterHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/rdp", g.HandleRDP)
	mux.HandleFunc("/ssh", g.HandleSSH)
	mux.HandleFunc("/vnc", g.handleVNC)
}
