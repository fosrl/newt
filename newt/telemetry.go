package newt

import (
	"context"
	"errors"
	"net/http"
	"net/http/pprof"
	"os"
	"time"

	"github.com/fosrl/newt/internal/telemetry"
	"github.com/fosrl/newt/logger"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// StartTelemetry initialises the OpenTelemetry exporters (Prometheus/OTLP)
// from the resolved config and, when metrics or pprof are enabled, starts
// the admin HTTP server (/healthz, /metrics, /debug/pprof/) on
// cfg.AdminAddr.
//
// It lives in this package rather than in the newt binary's main so that
// embedders (e.g. `pangolin up site`) get the same observability behavior
// as the standalone binary - internal/telemetry is not importable outside
// this module.
//
// Call after Init and before Start. The returned function stops the admin
// server and flushes exporters; it is always non-nil and safe to call.
// Failures are logged rather than returned, matching the standalone binary,
// since telemetry problems should never prevent the tunnel from running.
func (n *Newt) StartTelemetry(ctx context.Context) (shutdown func()) {
	cfg := n.config

	tcfg := telemetry.FromEnv()
	tcfg.PromEnabled = cfg.MetricsEnabled
	tcfg.OTLPEnabled = cfg.OTLPEnabled
	if cfg.AdminAddr != "" {
		tcfg.AdminAddr = cfg.AdminAddr
	}
	tcfg.SiteID = cfg.ID
	tcfg.Region = cfg.Region
	tcfg.BuildVersion = cfg.Version
	tcfg.BuildCommit = os.Getenv("NEWT_COMMIT")

	var shutdowns []func()
	shutdown = func() {
		for i := len(shutdowns) - 1; i >= 0; i-- {
			shutdowns[i]()
		}
	}

	tel, err := telemetry.Init(ctx, tcfg)
	if err != nil {
		logger.Warn("Telemetry init failed: %v", err)
	}
	if tel != nil {
		shutdowns = append(shutdowns, func() { _ = tel.Shutdown(context.Background()) })
	}

	if tel != nil && (cfg.MetricsEnabled || cfg.PprofEnabled) {
		logger.Debug("Starting metrics server on %s", tcfg.AdminAddr)
		mux := http.NewServeMux()
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
		if tel.PrometheusHandler != nil {
			mux.Handle("/metrics", tel.PrometheusHandler)
		}
		if cfg.PprofEnabled {
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
		shutdowns = append(shutdowns, func() {
			shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = admin.Shutdown(shutCtx)
		})
	}

	telemetry.UpdateSiteInfo(cfg.ID, cfg.Region)

	return shutdown
}
