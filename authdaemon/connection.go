package authdaemon

import (
	"github.com/fosrl/newt/logger"
)

// ProcessConnection runs the same logic as POST /connection: CA cert, user create/reconcile, principals.
// Use this when DisableHTTPS is true (e.g. embedded in Newt) instead of calling the API.
func (s *Server) ProcessConnection(req ConnectionRequest) {
	logger.Info("connection: niceId=%q username=%q metadata.sudo=%v metadata.homedir=%v",
		req.NiceId, req.Username, req.Metadata.Sudo, req.Metadata.Homedir)

	cfg := &s.cfg
	if cfg.CACertPath != "" {
		if err := writeCACertIfNotExists(cfg.CACertPath, req.CaCert, cfg.Force); err != nil {
			logger.Warn("auth-daemon: write CA cert: %v", err)
		}
	}
	if err := ensureUser(req.Username, req.Metadata); err != nil {
		logger.Warn("auth-daemon: ensure user: %v", err)
	}
	if cfg.PrincipalsFilePath != "" {
		if err := writePrincipals(cfg.PrincipalsFilePath, req.Username, req.NiceId); err != nil {
			logger.Warn("auth-daemon: write principals: %v", err)
		}
	}
}
