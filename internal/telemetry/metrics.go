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
	mWSConnectLatency   metric.Float64Histogram
	mWSMessages         metric.Int64Counter
	mWSDisconnects      metric.Int64Counter
	mWSKeepaliveFailure metric.Int64Counter
	mWSSessionDuration  metric.Float64Histogram

	// Proxy
	mProxyActiveConns      metric.Int64ObservableGauge
	mProxyBufferBytes      metric.Int64ObservableGauge
	mProxyAsyncBacklogByte metric.Int64ObservableGauge
	mProxyDropsTotal       metric.Int64Counter
	mProxyAcceptsTotal     metric.Int64Counter
	mProxyConnDuration     metric.Float64Histogram

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
		if e := registerSiteInstruments(); e != nil {
			err = e
			return
		}
		if e := registerTunnelInstruments(); e != nil {
			err = e
			return
		}
		if e := registerConnInstruments(); e != nil {
			err = e
			return
		}
		if e := registerConfigInstruments(); e != nil {
			err = e
			return
		}
		if e := registerBuildWSProxyInstruments(); e != nil {
			err = e
			return
		}
	})
	return err
}

func registerSiteInstruments() error {
	var err error
	mSiteRegistrations, err = meter.Int64Counter("newt_site_registrations_total",
		metric.WithDescription("Total site registration attempts"))
	if err != nil {
		return err
	}
	mSiteOnline, err = meter.Int64ObservableGauge("newt_site_online",
		metric.WithDescription("Site online (0/1)"))
	if err != nil {
		return err
	}
	mSiteLastHeartbeat, err = meter.Float64ObservableGauge("newt_site_last_heartbeat_seconds",
		metric.WithDescription("Seconds since last site heartbeat"))
	if err != nil {
		return err
	}
	return nil
}

func registerTunnelInstruments() error {
	var err error
	mTunnelSessions, err = meter.Int64ObservableGauge("newt_tunnel_sessions",
		metric.WithDescription("Active tunnel sessions"))
	if err != nil {
		return err
	}
	mTunnelBytes, err = meter.Int64Counter("newt_tunnel_bytes_total",
		metric.WithDescription("Tunnel bytes ingress/egress"),
		metric.WithUnit("By"))
	if err != nil {
		return err
	}
	mTunnelLatency, err = meter.Float64Histogram("newt_tunnel_latency_seconds",
		metric.WithDescription("Per-tunnel latency in seconds"),
		metric.WithUnit("s"))
	if err != nil {
		return err
	}
	mReconnects, err = meter.Int64Counter("newt_tunnel_reconnects_total",
		metric.WithDescription("Tunnel reconnect events"))
	if err != nil {
		return err
	}
	return nil
}

func registerConnInstruments() error {
	var err error
	mConnAttempts, err = meter.Int64Counter("newt_connection_attempts_total",
		metric.WithDescription("Connection attempts"))
	if err != nil {
		return err
	}
	mConnErrors, err = meter.Int64Counter("newt_connection_errors_total",
		metric.WithDescription("Connection errors by type"))
	if err != nil {
		return err
	}
	return nil
}

func registerConfigInstruments() error {
	mConfigReloads, _ = meter.Int64Counter("newt_config_reloads_total",
		metric.WithDescription("Configuration reloads"))
	mRestartCount, _ = meter.Int64Counter("newt_restart_count_total",
		metric.WithDescription("Process restart count (incremented on start)"))
	mConfigApply, _ = meter.Float64Histogram("newt_config_apply_seconds",
		metric.WithDescription("Configuration apply duration in seconds"),
		metric.WithUnit("s"))
	mCertRotationTotal, _ = meter.Int64Counter("newt_cert_rotation_total",
		metric.WithDescription("Certificate rotation events (success/failure)"))
	return nil
}

func registerBuildWSProxyInstruments() error {
	// Build info gauge (value 1 with version/commit attributes)
	mBuildInfo, _ = meter.Int64ObservableGauge("newt_build_info",
		metric.WithDescription("Newt build information (value is always 1)"))
	// WebSocket
	mWSConnectLatency, _ = meter.Float64Histogram("newt_websocket_connect_latency_seconds",
		metric.WithDescription("WebSocket connect latency in seconds"),
		metric.WithUnit("s"))
	mWSMessages, _ = meter.Int64Counter("newt_websocket_messages_total",
		metric.WithDescription("WebSocket messages by direction and type"))
	mWSDisconnects, _ = meter.Int64Counter("newt_websocket_disconnects_total",
		metric.WithDescription("WebSocket disconnects by reason/result"))
	mWSKeepaliveFailure, _ = meter.Int64Counter("newt_websocket_keepalive_failures_total",
		metric.WithDescription("WebSocket keepalive (ping/pong) failures"))
	mWSSessionDuration, _ = meter.Float64Histogram("newt_websocket_session_duration_seconds",
		metric.WithDescription("Duration of established WebSocket sessions"),
		metric.WithUnit("s"))
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
	mProxyAcceptsTotal, _ = meter.Int64Counter("newt_proxy_accept_total",
		metric.WithDescription("Proxy connection accepts by protocol and result"))
	mProxyConnDuration, _ = meter.Float64Histogram("newt_proxy_connection_duration_seconds",
		metric.WithDescription("Duration of completed proxy connections"),
		metric.WithUnit("s"))
	// Register a default callback for build info if version/commit set
	reg, e := meter.RegisterCallback(func(ctx context.Context, o metric.Observer) error {
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
	if e != nil {
		otel.Handle(e)
	} else {
		// Provide a functional stopper that unregisters the callback
		obsStopper = func() { _ = reg.Unregister() }
	}
	return nil
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
		reg, e := meter.RegisterCallback(cb, mSiteOnline, mSiteLastHeartbeat, mTunnelSessions)
		if e != nil {
			otel.Handle(e)
			obsStopper = func() {
				// no-op: registration failed; keep stopper callable
			}
			return
		}
		// Provide a functional stopper mirroring proxy/build-info behavior
		obsStopper = func() { _ = reg.Unregister() }
	})
}

// SetProxyObservableCallback registers a callback to observe proxy gauges.
func SetProxyObservableCallback(cb func(context.Context, metric.Observer) error) {
	proxyObsOnce.Do(func() {
		reg, e := meter.RegisterCallback(cb, mProxyActiveConns, mProxyBufferBytes, mProxyAsyncBacklogByte)
		if e != nil {
			otel.Handle(e)
			proxyStopper = func() {
				// no-op: registration failed; keep stopper callable
			}
			return
		}
		// Provide a functional stopper to unregister later if needed
		proxyStopper = func() { _ = reg.Unregister() }
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
	attrs := []attribute.KeyValue{
		attribute.String("direction", direction),
	}
	if ShouldIncludeTunnelID() && tunnelID != "" {
		attrs = append(attrs, attribute.String("tunnel_id", tunnelID))
	}
	mTunnelBytes.Add(ctx, n, metric.WithAttributes(attrsWithSite(attrs...)...))
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

func IncWSDisconnect(ctx context.Context, reason, result string) {
	mWSDisconnects.Add(ctx, 1, metric.WithAttributes(attrsWithSite(
		attribute.String("reason", reason),
		attribute.String("result", result),
	)...))
}

func IncWSKeepaliveFailure(ctx context.Context, reason string) {
	mWSKeepaliveFailure.Add(ctx, 1, metric.WithAttributes(attrsWithSite(
		attribute.String("reason", reason),
	)...))
}

func ObserveWSSessionDuration(ctx context.Context, seconds float64, result string) {
	mWSSessionDuration.Record(ctx, seconds, metric.WithAttributes(attrsWithSite(
		attribute.String("result", result),
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
	attrs := []attribute.KeyValue{
		attribute.String("protocol", protocol),
	}
	if ShouldIncludeTunnelID() && tunnelID != "" {
		attrs = append(attrs, attribute.String("tunnel_id", tunnelID))
	}
	mProxyDropsTotal.Add(ctx, 1, metric.WithAttributes(attrsWithSite(attrs...)...))
}

func IncProxyAccept(ctx context.Context, tunnelID, protocol, result, reason string) {
	attrs := []attribute.KeyValue{
		attribute.String("protocol", protocol),
		attribute.String("result", result),
	}
	if reason != "" {
		attrs = append(attrs, attribute.String("reason", reason))
	}
	if ShouldIncludeTunnelID() && tunnelID != "" {
		attrs = append(attrs, attribute.String("tunnel_id", tunnelID))
	}
	mProxyAcceptsTotal.Add(ctx, 1, metric.WithAttributes(attrsWithSite(attrs...)...))
}

func ObserveProxyConnectionDuration(ctx context.Context, tunnelID, protocol, result string, seconds float64) {
	attrs := []attribute.KeyValue{
		attribute.String("protocol", protocol),
		attribute.String("result", result),
	}
	if ShouldIncludeTunnelID() && tunnelID != "" {
		attrs = append(attrs, attribute.String("tunnel_id", tunnelID))
	}
	mProxyConnDuration.Record(ctx, seconds, metric.WithAttributes(attrsWithSite(attrs...)...))
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
	attrs := []attribute.KeyValue{
		attribute.String("transport", transport),
	}
	if ShouldIncludeTunnelID() && tunnelID != "" {
		attrs = append(attrs, attribute.String("tunnel_id", tunnelID))
	}
	mTunnelLatency.Record(ctx, seconds, metric.WithAttributes(attrsWithSite(attrs...)...))
}

func IncReconnect(ctx context.Context, tunnelID, initiator, reason string) {
	attrs := []attribute.KeyValue{
		attribute.String("initiator", initiator),
		attribute.String("reason", reason),
	}
	if ShouldIncludeTunnelID() && tunnelID != "" {
		attrs = append(attrs, attribute.String("tunnel_id", tunnelID))
	}
	mReconnects.Add(ctx, 1, metric.WithAttributes(attrsWithSite(attrs...)...))
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
