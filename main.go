package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fosrl/newt/clients/permissions"
	"github.com/fosrl/newt/internal/telemetry"
	"github.com/fosrl/newt/logger"
	newtpkg "github.com/fosrl/newt/newt"
	"github.com/fosrl/newt/updates"
	"github.com/fosrl/newt/websocket"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
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

	cfg := loadNewtConfig()

	if cfg.UseNativeMainInterface {
		if err := permissions.CheckNativeInterfacePermissions(); err != nil {
			logger.Fatal("Insufficient permissions for native main tunnel interface: %v", err)
		}
	}

	if err := validateTLSConfig(cfg); err != nil {
		logger.Fatal("TLS configuration error: %v", err)
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

	// Initialize telemetry
	tcfg := telemetry.FromEnv()
	tcfg.PromEnabled = resolvedCfg.MetricsEnabled
	tcfg.OTLPEnabled = resolvedCfg.OTLPEnabled
	if resolvedCfg.AdminAddr != "" {
		tcfg.AdminAddr = resolvedCfg.AdminAddr
	}
	tcfg.SiteID = resolvedCfg.ID
	tcfg.Region = resolvedCfg.Region
	tcfg.BuildVersion = newtVersion
	tcfg.BuildCommit = os.Getenv("NEWT_COMMIT")

	tel, telErr := telemetry.Init(ctx, tcfg)
	if telErr != nil {
		logger.Warn("Telemetry init failed: %v", telErr)
	}
	if tel != nil && (resolvedCfg.MetricsEnabled || resolvedCfg.PprofEnabled) {
		logger.Debug("Starting metrics server on %s", tcfg.AdminAddr)
		mux := http.NewServeMux()
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
		if tel.PrometheusHandler != nil {
			mux.Handle("/metrics", tel.PrometheusHandler)
		}
		if resolvedCfg.PprofEnabled {
			mux.HandleFunc("/debug/pprof/", pprof.Index)
			mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
			mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
			mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
			mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
			logger.Info("pprof debugging enabled on %s/debug/pprof/", tcfg.AdminAddr)
		}
		admin := &http.Server{
			Addr:              tcfg.AdminAddr,
			Handler:           otelhttp.NewHandler(mux, "newt-admin"),
			ReadTimeout:       5 * time.Second,
			WriteTimeout:      10 * time.Second,
			ReadHeaderTimeout: 5 * time.Second,
			IdleTimeout:       30 * time.Second,
		}
		go func() {
			if err := admin.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Warn("admin http error: %v", err)
			}
		}()
		defer func() {
			shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = admin.Shutdown(shutCtx)
		}()
		defer func() { _ = tel.Shutdown(context.Background()) }()
	}

	telemetry.UpdateSiteInfo(resolvedCfg.ID, resolvedCfg.Region)

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
		}); err != nil {
			if errors.Is(err, updates.ErrAutoUpdateUnsupportedInOfficialContainer) {
				logger.Debug("checkAndSelfUpdate: auto-update skipped: %v", err)
				return
			}
			logger.Error("Auto-update check failed: %v", err)
		}
	}
	go func() {
		time.Sleep(2 * time.Minute)
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
