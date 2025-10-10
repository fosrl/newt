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
  `newt_site_last_heartbeat_seconds` capture registration attempts and liveness. They
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
  `newt_restart_count_total`, `newt_config_apply_seconds`, and
  `newt_cert_rotation_total` provide visibility into blueprint reloads, process boots,
  configuration timings, and certificate rotation outcomes.
- **Build metadata**: `newt_build_info` records the binary version/commit together
  with a monotonic restart counter when build information is supplied at startup.
- **WebSocket control-plane**: `newt_websocket_connect_latency_seconds` and
  `newt_websocket_messages_total` report connect latency and ping/pong/text activity.
- **Proxy data-plane**: Observable gauges (`newt_proxy_active_connections`,
  `newt_proxy_buffer_bytes`, `newt_proxy_async_backlog_bytes`) and the
  `newt_proxy_drops_total` counter are fed from the proxy manager to monitor backlog
  and drop behaviour alongside per-protocol byte counters.

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
  populate the `resource.Resource` and are also injected as metric attributes for
  compatibility with Prometheus queries.
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
3. **Harmonise restart count behaviour** – `newt_restart_count_total` increments only
   when build metadata is provided. Consider moving the increment out of
   `RegisterBuildInfo` so the counter advances even for ad-hoc builds without version
   strings.
4. **Propagate contexts where available** – Many emitters call metric helpers with
   `context.Background()`. Passing real contexts (when inexpensive) would allow future
   exporters to correlate spans and metrics.
5. **Extend tracing coverage** – Instrument critical flows such as blueprint fetches,
   WireGuard reconfiguration, proxy accept loops, and Docker discovery to provide end
   to end visibility when OTLP tracing is enabled.

## Metrics to add before release

Prioritised additions that would close visibility gaps:

1. **WebSocket disconnect outcomes** – A counter (e.g., `newt_websocket_disconnects_total`)
   partitioned by `reason` would complement the existing connect latency histogram and
   explain reconnect storms.
2. **Keepalive/heartbeat failures** – Counting ping timeouts or heartbeat misses would
   make `newt_site_last_heartbeat_seconds` actionable by providing discrete events.
3. **Proxy connection lifecycle** – Add counters/histograms for proxy accept events and
   connection durations to correlate drops with load and backlog metrics.
4. **Blueprint/config pull latency** – Measuring Pangolin blueprint fetch durations and
   HTTP status distribution would expose slow control-plane operations.
5. **Certificate rotation attempts** – Complement `newt_cert_rotation_total` with a
   duration histogram to observe slow PKI updates and detect stuck rotations.

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
