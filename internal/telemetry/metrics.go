package telemetry

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Instruments and helpers for Newt metrics following the naming, units, and
// low-cardinality label guidance from the issue description.
//
// Counters end with _total, durations are in seconds, sizes in bytes.
// Only low-cardinality stable labels are supported: tunnel_id,
// transport, direction, result, reason, error_type.
var (
	initOnce sync.Once

	meter metric.Meter

	// Site / Registration
	mSiteRegistrations metric.Int64Counter
	mSiteOnline        metric.Int64ObservableGauge
	mSiteLastHeartbeat metric.Float64ObservableGauge

	// Tunnel / Sessions
	mTunnelSessions metric.Int64ObservableGauge
	mTunnelBytes    metric.Int64Counter
	mTunnelLatency  metric.Float64Histogram
	mReconnects     metric.Int64Counter

	// Connection / NAT
	mConnAttempts metric.Int64Counter
	mConnErrors   metric.Int64Counter

	// Config/Restart
	mConfigReloads metric.Int64Counter
	mRestartCount  metric.Int64Counter

	// Build info
	mBuildInfo metric.Int64ObservableGauge

	buildVersion string
	buildCommit  string
)

// attrsWithSite appends global site/region labels when present.
func attrsWithSite(extra ...attribute.KeyValue) []attribute.KeyValue {
	attrs := make([]attribute.KeyValue, 0, len(extra)+2)
	attrs = append(attrs, extra...)
	attrs = append(attrs, siteAttrs()...)
	return attrs
}

func registerInstruments() error {
	var err error
	initOnce.Do(func() {
		meter = otel.Meter("newt")

		// Site / Registration
		mSiteRegistrations, err = meter.Int64Counter("newt_site_registrations_total",
			metric.WithDescription("Total site registration attempts"))
		if err != nil {
			return
		}
		mSiteOnline, err = meter.Int64ObservableGauge("newt_site_online",
			metric.WithDescription("Site online (0/1)"))
		if err != nil {
			return
		}
		mSiteLastHeartbeat, err = meter.Float64ObservableGauge("newt_site_last_heartbeat_seconds",
			metric.WithDescription("Seconds since last site heartbeat"))
		if err != nil {
			return
		}

		// Tunnel / Sessions
		mTunnelSessions, err = meter.Int64ObservableGauge("newt_tunnel_sessions",
			metric.WithDescription("Active tunnel sessions"))
		if err != nil {
			return
		}
		mTunnelBytes, err = meter.Int64Counter("newt_tunnel_bytes_total",
			metric.WithDescription("Tunnel bytes in/out"))
		if err != nil {
			return
		}
		mTunnelLatency, err = meter.Float64Histogram("newt_tunnel_latency_seconds",
			metric.WithDescription("Per-tunnel latency in seconds"))
		if err != nil {
			return
		}
		mReconnects, err = meter.Int64Counter("newt_tunnel_reconnects_total",
			metric.WithDescription("Tunnel reconnect events"))
		if err != nil {
			return
		}

		// Connection / NAT
		mConnAttempts, err = meter.Int64Counter("newt_connection_attempts_total",
			metric.WithDescription("Connection attempts"))
		if err != nil {
			return
		}
		mConnErrors, err = meter.Int64Counter("newt_connection_errors_total",
			metric.WithDescription("Connection errors by type"))
		if err != nil {
			return
		}

		// Config/Restart
		mConfigReloads, _ = meter.Int64Counter("newt_config_reloads_total",
			metric.WithDescription("Configuration reloads"))
		mRestartCount, _ = meter.Int64Counter("newt_restart_count_total",
			metric.WithDescription("Process restart count (incremented on start)"))

		// Build info gauge (value 1 with version/commit attributes)
		mBuildInfo, _ = meter.Int64ObservableGauge("newt_build_info",
			metric.WithDescription("Newt build information (value is always 1)"))

		// Register a default callback for build info if version/commit set
		meter.RegisterCallback(func(ctx context.Context, o metric.Observer) error {
			if buildVersion == "" && buildCommit == "" {
				return nil
			}
			attrs := []attribute.KeyValue{}
			if buildVersion != "" {
				attrs = append(attrs, attribute.String("version", buildVersion))
			}
			if buildCommit != "" {
				attrs = append(attrs, attribute.String("commit", buildCommit))
			}
			attrs = append(attrs, siteAttrs()...)
			o.ObserveInt64(mBuildInfo, 1, metric.WithAttributes(attrs...))
			return nil
		}, mBuildInfo)
	})
	return err
}

// Observable registration: Newt can register a callback to report gauges.
// Call SetObservableCallback once to start observing online status, last
// heartbeat seconds, and active sessions.

var (
	obsOnce    sync.Once
	obsStopper func()
)

// SetObservableCallback registers a single callback that will be invoked
// on collection. Use the provided observer to emit values for the observable
// gauges defined here.
//
// Example inside your code (where you have access to current state):
//
//	telemetry.SetObservableCallback(func(ctx context.Context, o metric.Observer) error {
//	    o.ObserveInt64(mSiteOnline, 1)
//	    o.ObserveFloat64(mSiteLastHeartbeat, time.Since(lastHB).Seconds())
//	    o.ObserveInt64(mTunnelSessions, int64(len(activeSessions)))
//	    return nil
//	})
func SetObservableCallback(cb func(context.Context, metric.Observer) error) {
	obsOnce.Do(func() {
		meter.RegisterCallback(cb, mSiteOnline, mSiteLastHeartbeat, mTunnelSessions)
		obsStopper = func() { /* no-op; otel callbacks are unregistered when provider shuts down */ }
	})
}

// Build info registration
func RegisterBuildInfo(version, commit string) {
	buildVersion = version
	buildCommit = commit
	// Increment restart count on boot
	mRestartCount.Add(context.Background(), 1)
}

// Config reloads
func IncConfigReload(ctx context.Context, result string) {
	mConfigReloads.Add(ctx, 1, metric.WithAttributes(attrsWithSite(
		attribute.String("result", result),
	)...))
}

// Helpers for counters/histograms

func IncSiteRegistration(ctx context.Context, result string) {
	attrs := []attribute.KeyValue{
		attribute.String("result", result),
	}
	mSiteRegistrations.Add(ctx, 1, metric.WithAttributes(attrsWithSite(attrs...)...))
}

func AddTunnelBytes(ctx context.Context, tunnelID, direction string, n int64) {
	mTunnelBytes.Add(ctx, n, metric.WithAttributes(attrsWithSite(
		attribute.String("tunnel_id", tunnelID),
		attribute.String("direction", direction),
	)...))
}

// AddTunnelBytesSet adds bytes using a pre-built attribute.Set to avoid per-call allocations.
func AddTunnelBytesSet(ctx context.Context, n int64, attrs attribute.Set) {
	mTunnelBytes.Add(ctx, n, metric.WithAttributeSet(attrs))
}

func ObserveTunnelLatency(ctx context.Context, tunnelID, transport string, seconds float64) {
	mTunnelLatency.Record(ctx, seconds, metric.WithAttributes(attrsWithSite(
		attribute.String("tunnel_id", tunnelID),
		attribute.String("transport", transport),
	)...))
}

func IncReconnect(ctx context.Context, tunnelID, reason string) {
	mReconnects.Add(ctx, 1, metric.WithAttributes(attrsWithSite(
		attribute.String("tunnel_id", tunnelID),
		attribute.String("reason", reason),
	)...))
}

func IncConnAttempt(ctx context.Context, transport, result string) {
	mConnAttempts.Add(ctx, 1, metric.WithAttributes(attrsWithSite(
		attribute.String("transport", transport),
		attribute.String("result", result),
	)...))
}

func IncConnError(ctx context.Context, transport, typ string) {
	mConnErrors.Add(ctx, 1, metric.WithAttributes(attrsWithSite(
		attribute.String("transport", transport),
		attribute.String("error_type", typ),
	)...))
}
