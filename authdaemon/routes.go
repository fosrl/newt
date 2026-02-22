package authdaemon

import (
	"encoding/json"
	"net/http"
)

// registerRoutes registers all API routes. Add new endpoints here.
func (s *Server) registerRoutes() {
	s.mux.HandleFunc("/health", s.handleHealth)
	s.mux.HandleFunc("/connection", s.handleConnection)
}

// ConnectionMetadata is the metadata object in POST /connection.
type ConnectionMetadata struct {
	Sudo    bool `json:"sudo"`
	Homedir bool `json:"homedir"`
}

// ConnectionRequest is the JSON body for POST /connection.
type ConnectionRequest struct {
	CaCert   string             `json:"caCert"`
	NiceId   string             `json:"niceId"`
	Username string             `json:"username"`
	Metadata ConnectionMetadata `json:"metadata"`
}

// healthResponse is the JSON body for GET /health.
type healthResponse struct {
	Status string `json:"status"`
}

// handleHealth responds with 200 and {"status":"ok"}.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(healthResponse{Status: "ok"})
}

// handleConnection accepts POST with connection payload and delegates to ProcessConnection.
func (s *Server) handleConnection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var req ConnectionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	s.ProcessConnection(req)
	w.WriteHeader(http.StatusOK)
}
