package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fosrl/newt/clients/permissions"
	"github.com/fosrl/newt/logger"
	newtpkg "github.com/fosrl/newt/newt"
	"github.com/fosrl/newt/newtconfig"
	"github.com/fosrl/newt/updates"
	"github.com/fosrl/newt/websocket"
)

var (
	newtVersion  = "version_replaceme"
	newtPlatform = ""
)

func main() {
	// Subcommand dispatch
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "auth-daemon":
			if len(os.Args) > 2 && os.Args[2] == "principals" {
				runPrincipalsCmd(os.Args[3:])
				return
			}
			fmt.Println("Error: auth-daemon subcommand requires 'principals' argument")
			fmt.Println()
			fmt.Println("Usage:")
			fmt.Println("  newt auth-daemon principals [options]")
			fmt.Println()
			return
		}
	}

	if isWindowsService() {
		runService("NewtWireguardService", false, os.Args[1:])
		return
	}

	if handleServiceCommand() {
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	runNewtMain(ctx)
}

func runNewtMain(ctx context.Context) {
	logger.Init(nil)

	cfg, err := newtconfig.Load(newtconfig.Options{
		Args:         os.Args[1:],
		Version:      newtVersion,
		Agent:        "newt",
		AgentVersion: newtVersion,
		Platform:     newtPlatform,
	})
	if err != nil {
		logger.Fatal("Configuration error: %v", err)
	}

	logger.Info("Newt version %s", cfg.Version)

	if cfg.UseNativeMainInterface {
		if err := permissions.CheckNativeInterfacePermissions(); err != nil {
			logger.Fatal("Insufficient permissions for native main tunnel interface: %v", err)
		}
	}

	logger.Debug("Endpoint: %v", cfg.Endpoint)
	logger.Debug("Log Level: %v", cfg.LogLevel)
	logger.Debug("Docker Network Validation Enabled: %v", cfg.DockerEnforceNetworkValidation)
	logger.Debug("Health Check Certificate Enforcement: %v", cfg.EnforceHealthcheckCert)
	if cfg.TLSClientCert != "" {
		logger.Debug("TLS Client Cert File: %v", cfg.TLSClientCert)
	}
	if cfg.TLSClientKey != "" {
		logger.Debug("TLS Client Key File: %v", cfg.TLSClientKey)
	}
	if len(cfg.TLSClientCAs) > 0 {
		logger.Debug("TLS CA Files: %v", cfg.TLSClientCAs)
	}
	if cfg.TLSPrivateKey != "" {
		logger.Debug("TLS PKCS12 File: %v", cfg.TLSPrivateKey)
	}
	if cfg.DNS != "" {
		logger.Debug("DNS: %v", cfg.DNS)
	}
	if cfg.DockerSocket != "" {
		logger.Debug("Docker Socket: %v", cfg.DockerSocket)
	}
	if cfg.MTU != 0 {
		logger.Debug("MTU: %v", cfg.MTU)
	}
	if cfg.UpdownScript != "" {
		logger.Debug("Up Down Script: %v", cfg.UpdownScript)
	}

	cfg.OnRestart = reexec

	n, err := newtpkg.Init(ctx, cfg)
	if err != nil {
		logger.Fatal("Failed to initialize newt: %v", err)
	}

	resolvedCfg := n.GetConfig()

	if err := updates.CheckForUpdate("fosrl", "newt", newtVersion); err != nil {
		logger.Error("Error checking for updates: %v\n", err)
	}

	// Initialize telemetry and the admin/metrics server
	stopTelemetry := n.StartTelemetry(ctx)
	defer stopTelemetry()

	// Build TLS config for self-update (reuse same TLS parameters as websocket client)
	var selfUpdateTLS *tls.Config
	if resolvedCfg.TLSClientCert != "" || resolvedCfg.TLSPrivateKey != "" {
		selfUpdateTLS, _ = websocket.BuildTLSConfig(
			resolvedCfg.TLSClientCert,
			resolvedCfg.TLSClientKey,
			resolvedCfg.TLSClientCAs,
			resolvedCfg.TLSPrivateKey,
		)
	}

	doUpdate := func() {
		logger.Debug("checkAndSelfUpdate: running periodic update check")
		if err := updates.CheckAndSelfUpdate(updates.SelfUpdateConfig{
			Endpoint:       resolvedCfg.Endpoint,
			NewtID:         resolvedCfg.ID,
			Secret:         resolvedCfg.Secret,
			CurrentVersion: newtVersion,
			Platform:       newtPlatform,
			TLSConfig:      selfUpdateTLS,
			Agent:          "newt",
			Restart:        updateRestart(),
		}); err != nil {
			if errors.Is(err, updates.ErrAutoUpdateUnsupportedInOfficialContainer) {
				logger.Debug("checkAndSelfUpdate: auto-update skipped: %v", err)
				return
			}
			logger.Error("Auto-update check failed: %v", err)
		}
	}
	go func() {
		time.Sleep(2 * time.Minute) // for production
		// time.Sleep(10 * time.Second) // for testing, check for updates after 10 seconds
		doUpdate()
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				doUpdate()
			case <-ctx.Done():
				return
			}
		}
	}()

	n.Start(ctx)
}

// runNewtMainWithArgs is used by the Windows service runner.
func runNewtMainWithArgs(ctx context.Context, args []string) {
	os.Args = append([]string{os.Args[0]}, args...)
	setupWindowsEventLog()
	runNewtMain(ctx)
}
