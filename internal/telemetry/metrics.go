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
	mConfigReloads     metric.Int64Counter
	mRestartCount      metric.Int64Counter
	mConfigApply       metric.Float64Histogram
	mCertRotationTotal metric.Int64Counter

	// Build info
	mBuildInfo metric.Int64ObservableGauge

	// WebSocket
	mWSConnectLatency metric.Float64Histogram
	mWSMessages       metric.Int64Counter

	// Proxy
	mProxyActiveConns      metric.Int64ObservableGauge
	mProxyBufferBytes      metric.Int64ObservableGauge
	mProxyAsyncBacklogByte metric.Int64ObservableGauge
	mProxyDropsTotal       metric.Int64Counter

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
			metric.WithDescription("Tunnel bytes ingress/egress"),
			metric.WithUnit("By"))
		if err != nil {
			return
		}
		mTunnelLatency, err = meter.Float64Histogram("newt_tunnel_latency_seconds",
			metric.WithDescription("Per-tunnel latency in seconds"),
			metric.WithUnit("s"))
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
		mConfigApply, _ = meter.Float64Histogram("newt_config_apply_seconds",
			metric.WithDescription("Configuration apply duration in seconds"),
			metric.WithUnit("s"))
		mCertRotationTotal, _ = meter.Int64Counter("newt_cert_rotation_total",
			metric.WithDescription("Certificate rotation events (success/failure)"))

		// Build info gauge (value 1 with version/commit attributes)
		mBuildInfo, _ = meter.Int64ObservableGauge("newt_build_info",
			metric.WithDescription("Newt build information (value is always 1)"))

		// WebSocket
		mWSConnectLatency, _ = meter.Float64Histogram("newt_websocket_connect_latency_seconds",
			metric.WithDescription("WebSocket connect latency in seconds"),
			metric.WithUnit("s"))
		mWSMessages, _ = meter.Int64Counter("newt_websocket_messages_total",
			metric.WithDescription("WebSocket messages by direction and type"))

		// Proxy
		mProxyActiveConns, _ = meter.Int64ObservableGauge("newt_proxy_active_connections",
			metric.WithDescription("Proxy active connections per tunnel and protocol"))
		mProxyBufferBytes, _ = meter.Int64ObservableGauge("newt_proxy_buffer_bytes",
			metric.WithDescription("Proxy buffer bytes (may approximate async backlog)"),
			metric.WithUnit("By"))
		mProxyAsyncBacklogByte, _ = meter.Int64ObservableGauge("newt_proxy_async_backlog_bytes",
			metric.WithDescription("Unflushed async byte backlog per tunnel and protocol"),
			metric.WithUnit("By"))
		mProxyDropsTotal, _ = meter.Int64Counter("newt_proxy_drops_total",
			metric.WithDescription("Proxy drops due to write errors"))

		// Register a default callback for build info if version/commit set
		if _, e := meter.RegisterCallback(func(ctx context.Context, o metric.Observer) error {
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
		}, mBuildInfo); e != nil {
			// forward to global OTel error handler; Init will continue but build_info will be missing
			otel.Handle(e)
		}
	})
	return err
}

// Observable registration: Newt can register a callback to report gauges.
// Call SetObservableCallback once to start observing online status, last
// heartbeat seconds, and active sessions.

var (
	obsOnce      sync.Once
	obsStopper   func()
	proxyObsOnce sync.Once
	proxyStopper func()
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
	if _, e := meter.RegisterCallback(cb, mSiteOnline, mSiteLastHeartbeat, mTunnelSessions); e != nil {
			otel.Handle(e)
		}
		obsStopper = func() { /* no-op; otel callbacks are unregistered when provider shuts down */ }
	})
}

// SetProxyObservableCallback registers a callback to observe proxy gauges.
func SetProxyObservableCallback(cb func(context.Context, metric.Observer) error) {
	proxyObsOnce.Do(func() {
	if _, e := meter.RegisterCallback(cb, mProxyActiveConns, mProxyBufferBytes, mProxyAsyncBacklogByte); e != nil {
			otel.Handle(e)
		}
		proxyStopper = func() {}
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

// --- WebSocket helpers ---

func ObserveWSConnectLatency(ctx context.Context, seconds float64, result, errorType string) {
	attrs := []attribute.KeyValue{
		attribute.String("transport", "websocket"),
		attribute.String("result", result),
	}
	if errorType != "" {
		attrs = append(attrs, attribute.String("error_type", errorType))
	}
	mWSConnectLatency.Record(ctx, seconds, metric.WithAttributes(attrsWithSite(attrs...)...))
}

func IncWSMessage(ctx context.Context, direction, msgType string) {
	mWSMessages.Add(ctx, 1, metric.WithAttributes(attrsWithSite(
		attribute.String("direction", direction),
		attribute.String("msg_type", msgType),
	)...))
}

// --- Proxy helpers ---

func ObserveProxyActiveConnsObs(o metric.Observer, value int64, attrs []attribute.KeyValue) {
	o.ObserveInt64(mProxyActiveConns, value, metric.WithAttributes(attrs...))
}

func ObserveProxyBufferBytesObs(o metric.Observer, value int64, attrs []attribute.KeyValue) {
	o.ObserveInt64(mProxyBufferBytes, value, metric.WithAttributes(attrs...))
}

func ObserveProxyAsyncBacklogObs(o metric.Observer, value int64, attrs []attribute.KeyValue) {
	o.ObserveInt64(mProxyAsyncBacklogByte, value, metric.WithAttributes(attrs...))
}

func IncProxyDrops(ctx context.Context, tunnelID, protocol string) {
	mProxyDropsTotal.Add(ctx, 1, metric.WithAttributes(attrsWithSite(
		attribute.String("tunnel_id", tunnelID),
		attribute.String("protocol", protocol),
	)...))
}

// --- Config/PKI helpers ---

func ObserveConfigApply(ctx context.Context, phase, result string, seconds float64) {
	mConfigApply.Record(ctx, seconds, metric.WithAttributes(attrsWithSite(
		attribute.String("phase", phase),
		attribute.String("result", result),
	)...))
}

func IncCertRotation(ctx context.Context, result string) {
	mCertRotationTotal.Add(ctx, 1, metric.WithAttributes(attrsWithSite(
		attribute.String("result", result),
	)...))
}

func ObserveTunnelLatency(ctx context.Context, tunnelID, transport string, seconds float64) {
	mTunnelLatency.Record(ctx, seconds, metric.WithAttributes(attrsWithSite(
		attribute.String("tunnel_id", tunnelID),
		attribute.String("transport", transport),
	)...))
}

func IncReconnect(ctx context.Context, tunnelID, initiator, reason string) {
	mReconnects.Add(ctx, 1, metric.WithAttributes(attrsWithSite(
		attribute.String("tunnel_id", tunnelID),
		attribute.String("initiator", initiator),
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
