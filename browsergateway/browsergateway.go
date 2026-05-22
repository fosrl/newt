package browsergateway

import (
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
)

// Forwarding buffer size. RDP graphics traffic is bursty and TLS records cap
// at ~16 KiB, so 64 KiB lets a couple of records pile up per syscall/frame
// without wasting memory per session.
const forwardBufSize = 64 * 1024

// ListenPort is the port the browser gateway HTTP server listens on inside the
// WireGuard netstack. This is a fixed value shared between newt and pangolin.
// Targets do not overlap with this port because they start at 40000.
const ListenPort = 39999

// Target represents an allowed proxy destination for the browser gateway.
// Only connections whose (Type, Destination, DestinationPort, AuthToken) match a
// registered Target will be forwarded; all others are rejected.
type Target struct {
	ID              int
	Type            string // "rdp" | "ssh" | "vnc"
	Destination     string
	DestinationPort int
	AuthToken       string // per-target secret; must match the token supplied by the client
}

// Config holds the configuration for a Gateway.
type Config struct {
	// AuthToken is used only for NativeSSH mode (which has no external target
	// to match against). For all proxy targets (RDP/SSH/VNC), auth tokens are
	// stored per-Target and validated by isAllowed.
	AuthToken string
}

// Gateway is a browser-based RDP/SSH/VNC WebSocket proxy.
// Create one with New and mount it via RegisterHandlers or the individual
// HandleRDP / HandleSSH / HandleVNC http.HandlerFunc methods.
type Gateway struct {
	authToken string

	mu      sync.RWMutex
	targets map[int]Target // keyed by Target.ID

	server *http.Server
}

// New creates a new Gateway from the provided Config.
func New(cfg Config) *Gateway {
	return &Gateway{
		authToken: cfg.AuthToken,
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

// isAllowed reports whether a connection to (targetType, host, port) with the
// given authToken is permitted. The token is compared against the per-target
// AuthToken using constant-time comparison to prevent timing attacks.
func (g *Gateway) isAllowed(targetType, host string, port int, authToken string) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	for _, t := range g.targets {
		if t.Type == targetType && t.Destination == host && t.DestinationPort == port {
			return subtle.ConstantTimeCompare([]byte(authToken), []byte(t.AuthToken)) == 1
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
	if err == nil ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, http.ErrServerClosed) ||
		strings.Contains(err.Error(), "use of closed") ||
		strings.Contains(err.Error(), "invalid state") {
		return nil
	}
	return err
}

// RegisterHandlers registers the /rdp, /ssh, and /vnc routes on mux.
func (g *Gateway) RegisterHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/gateway/rdp", g.HandleRDP)
	mux.HandleFunc("/gateway/ssh", g.HandleSSH)
	mux.HandleFunc("/gateway/vnc", g.handleVNC)
}
