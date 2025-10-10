<!-- markdownlint-disable MD033 -->
# OpenTelemetry Observability for Newt

This document describes how Newt exposes metrics using the OpenTelemetry (OTel) Go SDK, how to enable Prometheus scraping, and how to send data to an OpenTelemetry Collector for further export.

Goals

- Provide a /metrics endpoint in Prometheus exposition format (via OTel Prometheus exporter)
- Keep metrics backend-agnostic; optional OTLP export to a Collector
- Use OTel semantic conventions where applicable and enforce SI units
- Low-cardinality, stable labels only

Enable via flags (ENV mirrors)

- --metrics (default: true) ↔ NEWT_METRICS_PROMETHEUS_ENABLED
- --metrics-admin-addr (default: 127.0.0.1:2112) ↔ NEWT_ADMIN_ADDR
- --otlp (default: false) ↔ NEWT_METRICS_OTLP_ENABLED

Enable exporters via environment variables (no code changes required)

- NEWT_METRICS_PROMETHEUS_ENABLED=true|false (default: true)
- NEWT_METRICS_OTLP_ENABLED=true|false (default: false)
- OTEL_EXPORTER_OTLP_ENDPOINT=collector:4317
- OTEL_EXPORTER_OTLP_INSECURE=true|false (default: true for dev)
- OTEL_SERVICE_NAME=newt (default)
- OTEL_SERVICE_VERSION=<version>
- OTEL_RESOURCE_ATTRIBUTES=service.instance.id=<id>,site_id=<id>
- OTEL_METRIC_EXPORT_INTERVAL=15s (default)
- NEWT_ADMIN_ADDR=127.0.0.1:2112 (default admin HTTP with /metrics)
- NEWT_METRICS_INCLUDE_SITE_LABELS=true|false (default: true; disable to drop site_id/region as metric labels and rely on resource attributes only)

Runtime behavior

- When Prometheus exporter is enabled, Newt serves /metrics on NEWT_ADMIN_ADDR (default :2112)
- When OTLP is enabled, metrics and traces are exported to OTLP gRPC endpoint
- Go runtime metrics (goroutines, GC, memory) are exported automatically

Metric catalog (current)

Unless otherwise noted, `site_id` and `region` are available via resource attributes and, by default, as metric labels. Set `NEWT_METRICS_INCLUDE_SITE_LABELS=false` to drop them from counter/histogram label sets in high-cardinality environments.

| Metric | Instrument | Key attributes | Purpose | Example |
| --- | --- | --- | --- | --- |
| `newt_build_info` | Observable gauge (Int64) | `version`, `commit`, `site_id`, `region` (optional when site labels enabled) | Emits build metadata with value `1` for scrape-time verification. | `newt_build_info{version="1.5.0"} 1` |
| `newt_site_registrations_total` | Counter (Int64) | `result` (`success`/`failure`), `site_id`, `region` (optional) | Counts Pangolin registration attempts. | `newt_site_registrations_total{result="success",site_id="acme-edge-1"} 1` |
| `newt_site_online` | Observable gauge (Int64) | `site_id` | Reports whether the site is currently connected (`1`) or offline (`0`). | `newt_site_online{site_id="acme-edge-1"} 1` |
| `newt_site_last_heartbeat_timestamp_seconds` | Observable gauge (Float64) | `site_id` | Unix timestamp of the most recent Pangolin heartbeat (derive age via `time() - metric`). | `newt_site_last_heartbeat_timestamp_seconds{site_id="acme-edge-1"} 1.728e+09` |
| `newt_tunnel_sessions` | Observable gauge (Int64) | `site_id`, `tunnel_id` (when enabled) | Counts active tunnel sessions per peer; collapses to per-site when tunnel IDs are disabled. | `newt_tunnel_sessions{site_id="acme-edge-1",tunnel_id="wgpub..."} 3` |
| `newt_tunnel_bytes_total` | Counter (Int64) | `direction` (`ingress`/`egress`), `protocol` (`tcp`/`udp`), `tunnel_id` (optional), `site_id`, `region` (optional) | Measures proxied traffic volume across tunnels. | `newt_tunnel_bytes_total{direction="ingress",protocol="tcp",site_id="acme-edge-1"} 4096` |
| `newt_tunnel_latency_seconds` | Histogram (Float64) | `transport` (e.g., `wireguard`), `tunnel_id` (optional), `site_id`, `region` (optional) | Captures RTT or configuration-driven latency samples. | `newt_tunnel_latency_seconds_bucket{transport="wireguard",le="0.5"} 42` |
| `newt_tunnel_reconnects_total` | Counter (Int64) | `initiator` (`client`/`server`), `reason` (enumerated), `tunnel_id` (optional), `site_id`, `region` (optional) | Tracks reconnect causes for troubleshooting flaps. | `newt_tunnel_reconnects_total{initiator="client",reason="timeout",site_id="acme-edge-1"} 5` |
| `newt_connection_attempts_total` | Counter (Int64) | `transport` (`auth`/`websocket`), `result`, `site_id`, `region` (optional) | Measures control-plane dial attempts and their outcomes. | `newt_connection_attempts_total{transport="websocket",result="success",site_id="acme-edge-1"} 8` |
| `newt_connection_errors_total` | Counter (Int64) | `transport`, `error_type`, `site_id`, `region` (optional) | Buckets connection failures by normalized error class. | `newt_connection_errors_total{transport="websocket",error_type="tls_handshake",site_id="acme-edge-1"} 1` |
| `newt_config_reloads_total` | Counter (Int64) | `result`, `site_id`, `region` (optional) | Counts remote blueprint/config reloads. | `newt_config_reloads_total{result="success",site_id="acme-edge-1"} 3` |
| `process_start_time_seconds` | Observable gauge (Float64) | — | Unix timestamp of the Newt process start time (use `time() - process_start_time_seconds` for uptime). | `process_start_time_seconds 1.728e+09` |
| `newt_config_apply_seconds` | Histogram (Float64) | `phase` (`interface`/`peer`), `result`, `site_id`, `region` (optional) | Measures time spent applying WireGuard configuration phases. | `newt_config_apply_seconds_sum{phase="peer",result="success",site_id="acme-edge-1"} 0.48` |
| `newt_cert_rotation_total` | Counter (Int64) | `result`, `site_id`, `region` (optional) | Tracks client certificate rotation attempts. | `newt_cert_rotation_total{result="success",site_id="acme-edge-1"} 2` |
| `newt_websocket_connect_latency_seconds` | Histogram (Float64) | `transport="websocket"`, `result`, `error_type` (on failure), `site_id`, `region` (optional) | Measures WebSocket dial latency and exposes failure buckets. | `newt_websocket_connect_latency_seconds_bucket{result="success",le="0.5",site_id="acme-edge-1"} 9` |
| `newt_websocket_messages_total` | Counter (Int64) | `direction` (`in`/`out`), `msg_type` (`text`/`ping`/`pong`), `site_id`, `region` (optional) | Accounts for control WebSocket traffic volume by type. | `newt_websocket_messages_total{direction="out",msg_type="ping",site_id="acme-edge-1"} 12` |
| `newt_websocket_connected` | Observable gauge (Int64) | `site_id`, `region` (optional) | Reports current WebSocket connectivity (`1` when connected). | `newt_websocket_connected{site_id="acme-edge-1"} 1` |
| `newt_websocket_reconnects_total` | Counter (Int64) | `reason` (`tls_handshake`, `dial_timeout`, `io_error`, `ping_write`, `timeout`, etc.), `site_id`, `region` (optional) | Counts reconnect attempts with normalized reasons for failure analysis. | `newt_websocket_reconnects_total{reason="timeout",site_id="acme-edge-1"} 3` |
| `newt_proxy_active_connections` | Observable gauge (Int64) | `protocol` (`tcp`/`udp`), `direction` (`ingress`/`egress`), `tunnel_id` (optional), `site_id`, `region` (optional) | Current proxy connections per tunnel and protocol. | `newt_proxy_active_connections{protocol="tcp",direction="egress",site_id="acme-edge-1"} 4` |
| `newt_proxy_buffer_bytes` | Observable gauge (Int64) | `protocol`, `direction`, `tunnel_id` (optional), `site_id`, `region` (optional) | Volume of buffered data awaiting flush in proxy queues. | `newt_proxy_buffer_bytes{protocol="udp",direction="egress",site_id="acme-edge-1"} 2048` |
| `newt_proxy_async_backlog_bytes` | Observable gauge (Int64) | `protocol`, `direction`, `tunnel_id` (optional), `site_id`, `region` (optional) | Tracks async write backlog when deferred flushing is enabled. | `newt_proxy_async_backlog_bytes{protocol="tcp",direction="egress",site_id="acme-edge-1"} 512` |
| `newt_proxy_drops_total` | Counter (Int64) | `protocol`, `tunnel_id` (optional), `site_id`, `region` (optional) | Counts proxy drop events caused by downstream write errors. | `newt_proxy_drops_total{protocol="udp",site_id="acme-edge-1"} 1` |
| `newt_proxy_connections_total` | Counter (Int64) | `event` (`opened`/`closed`), `protocol`, `tunnel_id` (optional), `site_id`, `region` (optional) | Tracks proxy connection lifecycle events for rate/SLO calculations. | `newt_proxy_connections_total{event="opened",protocol="tcp",site_id="acme-edge-1"} 10` |

Conventions

- Durations in seconds (unit: s), names end with _seconds
- Sizes in bytes (unit: By), names end with _bytes
- Counters end with _total
- Labels must be low-cardinality and stable

Histogram buckets

- Latency (seconds): 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30

Local quickstart

1) Direct Prometheus scrape (do not also scrape the Collector)
   NEWT_METRICS_PROMETHEUS_ENABLED=true \
   NEWT_METRICS_OTLP_ENABLED=false \
   NEWT_ADMIN_ADDR="127.0.0.1:2112" \
   ./newt

   curl -s <http://localhost:2112/metrics> | grep ^newt_

2) Using the Collector (compose-style)
   NEWT_METRICS_PROMETHEUS_ENABLED=true \
   NEWT_METRICS_OTLP_ENABLED=true \
   OTEL_EXPORTER_OTLP_ENDPOINT=collector:4317 \
   OTEL_EXPORTER_OTLP_INSECURE=true \
   OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE=cumulative \
   ./newt

   Collector config example: examples/otel-collector.yaml
   Prometheus scrape config: examples/prometheus.yml

Adding new metrics

- Use helpers in internal/telemetry/metrics.go for counters/histograms
- Keep labels low-cardinality
- Add observable gauges through SetObservableCallback

Optional tracing

- When --otlp is enabled, you can wrap outbound HTTP clients with otelhttp.NewTransport to create spans for HTTP requests to Pangolin. This affects traces only and does not add metric labels.

OTLP TLS example

- Enable TLS to Collector with a custom CA and headers:

```sh
NEWT_METRICS_OTLP_ENABLED=true \
OTEL_EXPORTER_OTLP_ENDPOINT=collector:4317 \
OTEL_EXPORTER_OTLP_INSECURE=false \
OTEL_EXPORTER_OTLP_CERTIFICATE=/etc/otel/custom-ca.pem \
OTEL_EXPORTER_OTLP_HEADERS="Authorization=Bearer abc123,tenant=acme" \
./newt
```

Prometheus scrape strategy (choose one)

Important: Do not scrape both Newt (2112) and the Collector’s Prometheus exporter (8889) at the same time for the same process. Doing so will double-count cumulative counters.

A) Scrape Newt directly:

```yaml
global:
  scrape_interval: 15s
scrape_configs:
  - job_name: newt
    static_configs:
      - targets: ["newt:2112"]
```

B) Scrape the Collector’s Prometheus exporter:

```yaml
global:
  scrape_interval: 15s
scrape_configs:
  - job_name: otel-collector
    static_configs:
      - targets: ["otel-collector:8889"]
```

Reason mapping (source → reason)

- Server instructs reconnect/terminate → server_request
- Heartbeat/Ping threshold exceeded → timeout
- Peer closed connection gracefully → peer_close
- Route/Interface change detected → network_change
- Auth/token failure (HTTP 401/403) → auth_error
- TLS/WG handshake error → handshake_error
- Config reloaded/applied (causing reconnection) → config_change
- Other/unclassified errors → error

PromQL snippets

- Throughput in (5m):

```sh
sum(rate(newt_tunnel_bytes_total{direction="ingress"}[5m]))
```

- P95 latency (seconds):

```sh
histogram_quantile(0.95, sum(rate(newt_tunnel_latency_seconds_bucket[5m])) by (le))
```

- Active sessions:

```sh
sum(newt_tunnel_sessions)
```

Compatibility notes

- Gauges do not use the _total suffix (e.g., newt_tunnel_sessions).
- site_id/region remain resource attributes. Metric labels for these fields appear on per-site gauges (e.g., `newt_site_online`) and, by default, on counters/histograms; disable them with `NEWT_METRICS_INCLUDE_SITE_LABELS=false` if needed. `tunnel_id` is a metric label (WireGuard public key). Never expose secrets in labels.
- NEWT_METRICS_INCLUDE_TUNNEL_ID (default: true) toggles whether tunnel_id is included as a label on bytes/sessions/proxy/reconnect metrics. Disable in high-cardinality environments.
- Avoid double-scraping: scrape either Newt (/metrics) or the Collector's Prometheus exporter, not both.
- Prometheus does not accept remote_write; use Mimir/Cortex/VM/Thanos-Receive for remote_write.
- No free text in labels; use only the enumerated constants for reason, protocol (tcp|udp), and transport (e.g., websocket|wireguard).

Further reading

- See docs/METRICS_RECOMMENDATIONS.md for roadmap, label guidance (transport vs protocol), and example alerts.

Cardinality tips

- tunnel_id can grow in larger fleets. Use relabeling to drop or retain a subset, for example:

```yaml
# Drop all tunnel_id on bytes to reduce series
- source_labels: [__name__]
  regex: newt_tunnel_bytes_total
  action: keep
- action: labeldrop
  regex: tunnel_id

# Or drop only high-churn tunnels
- source_labels: [tunnel_id]
  regex: .*
  action: drop
```

Quickstart: direkte Prometheus-Erfassung (empfohlen)

```sh
# Start (direkter /metrics-Scrape, keine Doppel-Erfassung)
docker compose -f docker-compose.metrics.yml up -d

# Smoke-Checks
./scripts/smoke-metrics.sh
# Tunnel-IDs ausblenden (optional):
# EXPECT_TUNNEL_ID=false NEWT_METRICS_INCLUDE_TUNNEL_ID=false ./scripts/smoke-metrics.sh
```

- Prometheus UI: <http://localhost:9090>
- Standard-Scrape-Intervall: 15s
- Kein OTLP aktiv (NEWT_METRICS_OTLP_ENABLED=false in docker-compose.metrics.yml)

Häufige PromQL-Schnelltests

```yaml
# Online-Status einer Site in den letzten 5 Minuten
max_over_time(newt_site_online{site_id="$site"}[5m])

# TCP egress-Bytes pro Site/Tunnel (10m)
sum by (site_id, tunnel_id) (increase(newt_tunnel_bytes_total{protocol="tcp",direction="egress"}[10m]))

# WebSocket-Connect P95
histogram_quantile(0.95, sum by (le, site_id) (rate(newt_websocket_connect_latency_seconds_bucket[5m])))

# Reconnects nach Initiator
increase(newt_tunnel_reconnects_total{site_id="$site"}[30m]) by (initiator, reason)
```

Troubleshooting

- curl :2112/metrics – ensure endpoint is reachable and includes newt_* metrics
- Check Collector logs for OTLP connection issues
- Verify Prometheus Targets are UP and scraping Newt or Collector
