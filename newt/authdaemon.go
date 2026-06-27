package newt

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"github.com/fosrl/newt/authdaemon"
	"github.com/fosrl/newt/logger"
)

const (
	defaultPrincipalsPath = "/var/run/auth-daemon/principals"
	defaultCACertPath     = "/etc/ssh/ca.pem"
)

func (n *Newt) startAuthDaemon(ctx context.Context) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("auth-daemon is only supported on Linux, not %s", runtime.GOOS)
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("auth-daemon must be run as root (use sudo)")
	}

	principalsFile := n.config.AuthDaemonPrincipalsFile
	if principalsFile == "" {
		principalsFile = defaultPrincipalsPath
	}
	caCertPath := n.config.AuthDaemonCACertPath
	if caCertPath == "" {
		caCertPath = defaultCACertPath
	}

	cfg := authdaemon.Config{
		DisableHTTPS:           true,
		PresharedKey:           "this-key-is-not-used",
		PrincipalsFilePath:     principalsFile,
		CACertPath:             caCertPath,
		Force:                  true,
		GenerateRandomPassword: n.config.AuthDaemonGenerateRandomPassword,
	}

	srv, err := authdaemon.NewServer(cfg)
	if err != nil {
		return fmt.Errorf("create auth daemon server: %w", err)
	}

	n.authDaemonServer = srv

	go func() {
		logger.Debug("Auth daemon starting (native mode, no HTTP server)")
		if err := srv.Run(ctx); err != nil {
			logger.Error("Auth daemon error: %v", err)
		}
		logger.Info("Auth daemon stopped")
	}()

	return nil
}
