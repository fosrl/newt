# OpenTelemetry Review

## Metric inventory
The table below lists every instrument registered by `internal/telemetry/metrics.go`, the helper that emits it, and an example time-series. Attribute sets automatically add `site_id` (and optionally `region`) via `attrsWithSite` unless the observable callback overrides them. 【F:internal/telemetry/metrics.go†L23-L205】【F:internal/telemetry/metrics.go†L289-L403】

| Metric | Instrument & unit | Purpose | Emission path | Example series |
| --- | --- | --- | --- | --- |
| `newt_site_registrations_total` | Counter | Counts Pangolin registration attempts keyed by result (`success`, `failure`). | `telemetry.IncSiteRegistration` (called after registration completes). | `newt_site_registrations_total{result="success",site_id="abc"} 1` |
| `newt_site_online` | Observable gauge | 0/1 heartbeat for the active site, driven by the registered `StateView`. | `telemetry.SetObservableCallback` via `state.TelemetryView`. | `newt_site_online{site_id="self"} 1` |
| `newt_site_last_heartbeat_seconds` | Observable gauge | Seconds since the last Pangolin heartbeat. | Same callback as above using `state.TelemetryView.TouchHeartbeat`. | `newt_site_last_heartbeat_seconds{site_id="self"} 3.2` |
| `newt_tunnel_sessions` | Observable gauge | Active sessions per tunnel; collapses to site total when `tunnel_id` emission is disabled. | `state.TelemetryView.SessionsByTunnel` via `RegisterStateView`. | `newt_tunnel_sessions{site_id="self",tunnel_id="wgpub"} 2` |
| `newt_tunnel_bytes_total` | Counter (`By`) | Traffic accounting per tunnel, direction (`ingress`/`egress`), protocol (`tcp`/`udp`). | Proxy manager counting writers (`AddTunnelBytes`/`AddTunnelBytesSet`). | `newt_tunnel_bytes_total{direction="egress",protocol="tcp",site_id="self",tunnel_id="wgpub"} 8192` |
| `newt_tunnel_latency_seconds` | Histogram (`s`) | RTT samples from WireGuard stack and health pings per tunnel/transport. | `telemetry.ObserveTunnelLatency` from tunnel health checks. | `newt_tunnel_latency_seconds_bucket{transport="wireguard",le="0.05",tunnel_id="wgpub"} 4` |
| `newt_tunnel_reconnects_total` | Counter | Reconnect attempts bucketed by initiator (`client`/`server`) and reason enums. | `telemetry.IncReconnect` across websocket, WG, and utility flows. | `newt_tunnel_reconnects_total{initiator="client",reason="timeout",tunnel_id="wgpub"} 3` |
| `newt_connection_attempts_total` | Counter | Auth and WebSocket attempt counts by transport (`auth`, `websocket`) and result (`success`/`failure`). | `telemetry.IncConnAttempt` in auth/token and dial paths. | `newt_connection_attempts_total{transport="websocket",result="failure",site_id="self"} 2` |
| `newt_connection_errors_total` | Counter | Connection error tally keyed by transport and canonical error type (`dial_timeout`, `tls_handshake`, `auth_failed`, `io_error`). | `telemetry.IncConnError` in auth/websocket flows. | `newt_connection_errors_total{transport="auth",error_type="auth_failed",site_id="self"} 1` |
| `newt_config_reloads_total` | Counter | Successful/failed config reload attempts. | `telemetry.IncConfigReload` during WireGuard config reloads. | `newt_config_reloads_total{result="success",site_id="self"} 1` |
| `newt_restart_count_total` | Counter | Bumps to 1 at process boot for build info scrapers. | `telemetry.RegisterBuildInfo` called from `Init`. | `newt_restart_count_total{site_id="self"} 1` |
| `newt_config_apply_seconds` | Histogram (`s`) | Measures interface/peer apply duration per phase and result. | `telemetry.ObserveConfigApply` around config updates. | `newt_config_apply_seconds_bucket{phase="peer",result="success",le="0.1"} 5` |
| `newt_cert_rotation_total` | Counter | Certificate rotation events tagged by result. | `telemetry.IncCertRotation` during PKI updates. | `newt_cert_rotation_total{result="success",site_id="self"} 1` |
| `newt_build_info` | Observable gauge | Constant 1 with `version`/`commit` attributes to expose build metadata. | Callback registered in `registerBuildWSProxyInstruments`. | `newt_build_info{version="1.2.3",commit="abc123",site_id="self"} 1` |
| `newt_websocket_connect_latency_seconds` | Histogram (`s`) | Dial latency for Pangolin WebSocket connects annotated with result/error_type. | `telemetry.ObserveWSConnectLatency` inside `Client.establishConnection`. | `newt_websocket_connect_latency_seconds_bucket{result="success",transport="websocket",le="0.5"} 1` |
| `newt_websocket_messages_total` | Counter | Counts inbound/outbound WebSocket messages by direction and logical message type. | `telemetry.IncWSMessage` for ping/pong/text events. | `newt_websocket_messages_total{direction="out",msg_type="ping",site_id="self"} 4` |
| `newt_websocket_disconnects_total` | Counter | Tracks WebSocket disconnects grouped by `reason` (`shutdown`, `unexpected_close`, etc.) and `result`. | Emitted from `Client.readPumpWithDisconnectDetection` defer block. | `newt_websocket_disconnects_total{reason="unexpected_close",result="error",site_id="self"} 1` |
| `newt_websocket_keepalive_failures_total` | Counter | Failed WebSocket ping/pong keepalive attempts by reason. | Incremented in `Client.pingMonitor` when `WriteControl` fails. | `newt_websocket_keepalive_failures_total{reason="ping_write",site_id="self"} 1` |
| `newt_websocket_session_duration_seconds` | Histogram (`s`) | Duration of WebSocket sessions by outcome (`result`). | Observed when the read pump exits. | `newt_websocket_session_duration_seconds_sum{result="success",site_id="self"} 120` |
| `newt_proxy_active_connections` | Observable gauge | Active TCP/UDP proxy connections per tunnel and protocol. | Proxy manager callback via `SetProxyObservableCallback`. | `newt_proxy_active_connections{protocol="tcp",tunnel_id="wgpub"} 3` |
| `newt_proxy_buffer_bytes` | Observable gauge (`By`) | Size of proxy buffer pools (synchronous path) per tunnel/protocol. | Same proxy callback as above. | `newt_proxy_buffer_bytes{protocol="tcp",tunnel_id="wgpub"} 10240` |
| `newt_proxy_async_backlog_bytes` | Observable gauge (`By`) | Unflushed async byte backlog when deferred accounting is enabled. | Proxy callback when async accounting is turned on. | `newt_proxy_async_backlog_bytes{protocol="udp",tunnel_id="wgpub"} 4096` |
| `newt_proxy_drops_total` | Counter | Proxy write-drop events per protocol/tunnel. | `telemetry.IncProxyDrops` on UDP drop paths. | `newt_proxy_drops_total{protocol="udp",tunnel_id="wgpub"} 2` |
| `newt_proxy_accept_total` | Counter | Proxy accept attempts labelled by protocol, result, and reason. | `telemetry.IncProxyAccept` in TCP accept loop and UDP dial paths. | `newt_proxy_accept_total{protocol="tcp",result="failure",reason="timeout",site_id="self"} 1` |
| `newt_proxy_connection_duration_seconds` | Histogram (`s`) | Lifecycle duration for proxied TCP/UDP connections by result. | `telemetry.ObserveProxyConnectionDuration` when TCP/UDP handlers complete. | `newt_proxy_connection_duration_seconds_sum{protocol="udp",result="success",site_id="self"} 30` |

In addition, Go runtime metrics are automatically exported when telemetry is initialised. 【F:internal/telemetry/telemetry.go†L147-L155】

## Tracing footprint
* Tracing is enabled only when OTLP export is turned on; `telemetry.Init` wires a batch `TracerProvider` and sets it globally. 【F:internal/telemetry/telemetry.go†L135-L155】
* The admin HTTP mux (`/metrics`, `/healthz`) is wrapped with `otelhttp.NewHandler`, so any inbound admin requests produce spans. 【F:main.go†L373-L387】
* WebSocket dials create a `ws.connect` span around the outbound handshake, but subsequent control-plane HTTP requests (token fetch, blueprint sync) use plain `http.Client` without propagation. 【F:websocket/client.go†L417-L459】

Overall span coverage is limited to the WebSocket connect loop and admin server; tunnel setup, Docker discovery, config application, and health pings currently emit only metrics.

## Guideline & best-practice adherence
* **Resource & exporter configuration:** `telemetry.FromEnv` honours OTEL env-vars, sets service name/version, and promotes `site_id`/`region` resource attributes before building the provider. Exporters default to Prometheus with optional OTLP, aligning with OTel deployment guidance. 【F:internal/telemetry/telemetry.go†L56-L206】
* **Low-cardinality enforcement:** A view-level attribute allow-list retains only approved keys (`tunnel_id`, `transport`, `protocol`, etc.), protecting Prometheus cardinality while still surfacing `site_id`/`region`. 【F:internal/telemetry/telemetry.go†L209-L231】
* **Units and naming:** Instrument helpers enforce `_total` suffixes for counters, `_seconds` for durations, and attach `metric.WithUnit("By"|"s")` for size/time metrics, matching OTel semantic conventions. 【F:internal/telemetry/metrics.go†L23-L192】
* **Runtime metrics & shutdown:** The runtime instrumentation is enabled, and `Setup.Shutdown` drains exporters in reverse order to avoid data loss. 【F:internal/telemetry/telemetry.go†L147-L261】
* **Site-aware observables:** `state.TelemetryView` provides thread-safe snapshots to feed `newt_site_online`/`_last_heartbeat_seconds`/`_tunnel_sessions`, ensuring gauges report cohesive per-site data even when `tunnel_id` labels are disabled. 【F:internal/state/telemetry_view.go†L11-L79】

## Gaps & recommended improvements
1. **Tracing coverage:** Instrument the Pangolin REST calls (`getToken`, blueprint downloads) with `otelhttp.NewTransport` or explicit spans, and consider spans for WireGuard handshake/config apply to enable end-to-end traces when OTLP is on. 【F:websocket/client.go†L240-L360】
2. **Histogram coverage:** Introduce `newt_site_registration_latency_seconds` (bootstrap) and `newt_ping_roundtrip_seconds` (heartbeat) to capture SLO-critical latencies before release. Existing latency buckets (`0.005s` → `30s`) can be reused. 【F:internal/telemetry/telemetry.go†L209-L218】
3. **Control-plane throughput:** Add `newt_websocket_payload_bytes_total` (direction/msg_type) or reuse the tunnel counter with a `transport="websocket"` label to quantify command traffic volume and detect back-pressure.
4. **Docker discovery metrics:** If Docker auto-discovery is enabled, expose counters for container add/remove events and failures so operators can trace missing backends to discovery issues.

## Pre-release metric backlog
Prior to GA, we recommend landing the following high-value instruments:
* **Bootstrap latency:** `newt_site_registration_latency_seconds` histogram emitted around the initial Pangolin registration HTTP call to detect slow control-plane responses.
* **Session duration:** `newt_websocket_session_duration_seconds` histogram recorded when a WebSocket closes (result + reason) to quantify stability.
* **Heartbeat lag:** `newt_ping_roundtrip_seconds` histogram from ping/pong monitors to capture tunnel health, complementing the heartbeat gauge.
* **Proxy accept errors:** `newt_proxy_accept_errors_total` counter keyed by protocol/reason to surface listener pressure distinct from data-plane drops.
* **Discovery events:** `newt_discovery_events_total` counter with `action` (`add`, `remove`, `error`) and `source` (`docker`, `file`) to audit service inventory churn.

Implementing the above will round out visibility into control-plane responsiveness, connection stability, and discovery health while preserving the existing low-cardinality discipline.
