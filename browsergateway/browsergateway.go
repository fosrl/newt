package browsergateway

import (
	"net/http"
)

// Forwarding buffer size. RDP graphics traffic is bursty and TLS records cap
// at ~16 KiB, so 64 KiB lets a couple of records pile up per syscall/frame
// without wasting memory per session.
const forwardBufSize = 64 * 1024

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
}

// New creates a new Gateway from the provided Config.
func New(cfg Config) *Gateway {
	return &Gateway{
		authToken: cfg.AuthToken,
		nativeSSH: cfg.NativeSSH,
	}
}

// RegisterHandlers registers the /rdp, /ssh, and /vnc routes on mux.
func (g *Gateway) RegisterHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/rdp", g.HandleRDP)
	mux.HandleFunc("/ssh", g.HandleSSH)
	mux.HandleFunc("/vnc", g.handleVNC)
}
