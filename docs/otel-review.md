# Newt OpenTelemetry Review

## Overview

This document summarises the current OpenTelemetry (OTel) instrumentation in Newt, assesses
compliance with OTel guidelines, and lists concrete improvements to pursue before release.
It is based on the implementation in `internal/telemetry` and the call-sites that emit
metrics and traces across the code base.

## Current metric instrumentation

All instruments are registered in `internal/telemetry/metrics.go`. They are grouped
into site, tunnel, connection, configuration, build, WebSocket, and proxy domains.
A global attribute filter (see `buildMeterProvider`) constrains exposed label keys to
`site_id`, `region`, and a curated list of low-cardinality dimensions so that Prometheus
exports stay bounded.

- **Site lifecycle**: `newt_site_registrations_total`, `newt_site_online`, and
  `newt_site_last_heartbeat_timestamp_seconds` capture registration attempts and liveness. They
  are fed either manually (`IncSiteRegistration`) or via the `TelemetryView` state
  callback that publishes observable gauges for the active site.
- **Tunnel health and usage**: Counters and histograms track bytes, latency, reconnects,
  and active sessions per tunnel (`newt_tunnel_*` family). Attribute helpers respect
  the `NEWT_METRICS_INCLUDE_TUNNEL_ID` toggle to keep cardinality manageable on larger
  fleets.
- **Connection attempts**: `newt_connection_attempts_total` and
  `newt_connection_errors_total` are emitted throughout the WebSocket client to classify
  authentication, dial, and transport failures.
- **Operations/configuration**: `newt_config_reloads_total`,
  `process_start_time_seconds`, `newt_config_apply_seconds`, and
  `newt_cert_rotation_total` provide visibility into blueprint reloads, process boots,
  configuration timings, and certificate rotation outcomes.
- **Build metadata**: `newt_build_info` records the binary version/commit together
  with optional site metadata when build information is supplied at startup.
- **WebSocket control-plane**: `newt_websocket_connect_latency_seconds`,
  `newt_websocket_messages_total`, `newt_websocket_connected`, and
  `newt_websocket_reconnects_total` report connect latency, ping/pong/text activity,
  connection state, and reconnect reasons.
- **Proxy data-plane**: Observable gauges (`newt_proxy_active_connections`,
  `newt_proxy_buffer_bytes`, `newt_proxy_async_backlog_bytes`) plus counters for
  drops, accepts, connection lifecycle events (`newt_proxy_connections_total`), and
  duration histograms (`newt_proxy_connection_duration_seconds`) surface backlog,
  drop behaviour, and churn alongside per-protocol byte counters.

Refer to `docs/observability.md` for a tabular catalogue with instrument types,
attributes, and sample exposition lines.

## Tracing coverage

Tracing is optional and enabled only when OTLP export is configured. When active:

- The admin HTTP mux is wrapped with `otelhttp.NewHandler`, producing spans for
  `/metrics` and `/healthz` requests.
- The WebSocket dial path creates a `ws.connect` span around the gRPC-based handshake.

No other subsystems currently create spans, so data-plane operations, blueprint fetches,
Docker discovery, and WireGuard reconfiguration happen without trace context.

## Guideline & best-practice alignment

The implementation adheres to most OTel Go recommendations:

- **Naming & units** – Every instrument follows the `newt_*` prefix with `_total`
  suffixes for counters and `_seconds`/`_bytes` unit conventions. Histograms are
  registered with explicit second-based buckets.
- **Resource attributes** – Service name/version and optional `site_id`/`region`
  populate the `resource.Resource`. Metric labels mirror these by default (and on
  per-site gauges) but can be disabled with `NEWT_METRICS_INCLUDE_SITE_LABELS=false`
  to avoid unnecessary cardinality growth.
- **Attribute hygiene** – A single attribute filter (`sdkmetric.WithView`) enforces
  the allow-list of label keys to prevent accidental high-cardinality emission.
- **Runtime metrics** – Go runtime instrumentation is enabled automatically through
  `runtime.Start`.
- **Configuration via environment** – `telemetry.FromEnv` honours `OTEL_*` variables
  alongside `NEWT_*` overrides so operators can configure exporters without code
  changes.
- **Shutdown handling** – `Setup.Shutdown` iterates exporters in reverse order to
  flush buffers before process exit.

## Adjustments & improvements

The review identified a few actionable adjustments:

1. **Record registration failures** – `newt_site_registrations_total` is currently
   incremented only on success. Emit `result="failure"` samples whenever Pangolin
   rejects a registration or credential exchange so operators can alert on churn.
2. **Surface config reload failures** – `telemetry.IncConfigReload` is invoked with
   `result="success"` only. Callers should record a failure result when blueprint
   parsing or application aborts before success counters are incremented.
3. **Expose robust uptime** – Document using `time() - process_start_time_seconds`
   to derive uptime now that the restart counter has been replaced with a timestamp
   gauge.
4. **Propagate contexts where available** – Many emitters call metric helpers with
   `context.Background()`. Passing real contexts (when inexpensive) would allow future
   exporters to correlate spans and metrics.
5. **Extend tracing coverage** – Instrument critical flows such as blueprint fetches,
   WireGuard reconfiguration, proxy accept loops, and Docker discovery to provide end
   to end visibility when OTLP tracing is enabled.

## Metrics to add before release

Prioritised additions that would close visibility gaps:

1. **Config reload error taxonomy** – Split reload attempts into a dedicated
   `newt_config_reload_errors_total{phase}` counter to make blueprint validation failures
   visible alongside the existing success counter.
2. **Config source visibility** – Export `newt_config_source_info{source,version}` so
   operators can audit the active blueprint origin/commit during incidents.
3. **Certificate expiry** – Emit `newt_cert_expiry_timestamp_seconds` (per cert) to
   enable proactive alerts before mTLS credentials lapse.
4. **Blueprint/config pull latency** – Measuring Pangolin blueprint fetch durations and
   HTTP status distribution would expose slow control-plane operations.
5. **Tunnel setup latency** – Histograms for DNS resolution and tunnel handshakes would
   help correlate connect latency spikes with network dependencies.

These metrics rely on data that is already available in the code paths mentioned
above and would round out operational dashboards.

## Tracing wishlist

To benefit from tracing when OTLP is active, add spans around:

- Pangolin REST calls (wrap the HTTP client with `otelhttp.NewTransport`).
- Docker discovery cycles and target registration callbacks.
- WireGuard reconfiguration (interface bring-up, peer updates).
- Proxy dial/accept loops for both TCP and UDP targets.

Capturing these stages will let operators correlate latency spikes with reconnects
and proxy drops using distributed traces in addition to the metric signals.
