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

Runtime behavior

- When Prometheus exporter is enabled, Newt serves /metrics on NEWT_ADMIN_ADDR (default :2112)
- When OTLP is enabled, metrics and traces are exported to OTLP gRPC endpoint
- Go runtime metrics (goroutines, GC, memory) are exported automatically

Metric catalog (initial)

- newt_build_info (gauge) labels: version, commit, site_id[, region]; value is always 1
- newt_site_registrations_total (counter) labels: result, site_id[, region]
- newt_site_online (observable gauge) labels: site_id (0/1)
- newt_site_last_heartbeat_seconds (observable gauge) labels: site_id
- newt_tunnel_sessions (observable gauge) labels: site_id, tunnel_id, transport (transport e.g. wireguard)
- newt_tunnel_bytes_total (counter) labels: site_id, tunnel_id, protocol (tcp|udp), direction (in|out)
- newt_tunnel_latency_seconds (histogram) labels: site_id, tunnel_id, transport (e.g., wireguard)
- newt_tunnel_reconnects_total (counter) labels: site_id, tunnel_id, reason
- newt_connection_attempts_total (counter) labels: site_id, transport, result
- newt_connection_errors_total (counter) labels: site_id, transport, error_type

Conventions

- Durations in seconds, names end with _seconds
- Sizes in bytes, names end with _bytes
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
      - targets: ["collector:8889"]
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
sum(rate(newt_tunnel_bytes_total{direction="in"}[5m]))
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
- site_id is emitted as both resource attribute and metric label on all newt_* series; region is included as a metric label only when set. tunnel_id is a metric label (WireGuard public key). Never expose secrets in labels.
- Avoid double-scraping: scrape either Newt (/metrics) or the Collector's Prometheus exporter, not both.
- Prometheus does not accept remote_write; use Mimir/Cortex/VM/Thanos-Receive for remote_write.
- No free text in labels; use only the enumerated constants for reason, protocol (tcp|udp), and transport (e.g., websocket|wireguard).

Further reading

- See docs/METRICS_RECOMMENDATIONS.md for roadmap, label guidance (transport vs protocol), and example alerts.

Troubleshooting

- curl :2112/metrics – ensure endpoint is reachable and includes newt_* metrics
- Check Collector logs for OTLP connection issues
- Verify Prometheus Targets are UP and scraping Newt or Collector
