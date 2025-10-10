# Newt Metrics: Recommendations, Gaps, and Roadmap

This document captures the current state of Newt metrics, prioritized fixes, and a pragmatic roadmap for near-term improvements.

1) Current setup (summary)

   - Export: Prometheus exposition (default), optional OTLP (gRPC)
   - Existing instruments:
     - Sites: newt_site_registrations_total, newt_site_online (0/1), newt_site_last_heartbeat_timestamp_seconds
     - Tunnel/Traffic: newt_tunnel_sessions, newt_tunnel_bytes_total, newt_tunnel_latency_seconds, newt_tunnel_reconnects_total
     - Connection lifecycle: newt_connection_attempts_total, newt_connection_errors_total
     - Operations: newt_config_reloads_total, process_start_time_seconds, newt_build_info
     - Operations: newt_config_reloads_total, process_start_time_seconds, newt_config_apply_seconds, newt_cert_rotation_total
     - Build metadata: newt_build_info
     - Control plane: newt_websocket_connect_latency_seconds, newt_websocket_messages_total, newt_websocket_connected, newt_websocket_reconnects_total
     - Proxy: newt_proxy_active_connections, newt_proxy_buffer_bytes, newt_proxy_async_backlog_bytes, newt_proxy_drops_total, newt_proxy_accept_total, newt_proxy_connection_duration_seconds, newt_proxy_connections_total
     - Go runtime: GC, heap, goroutines via runtime instrumentation

2) Main issues addressed now

   - Attribute filter (allow-list) extended to include site_id and region in addition to existing keys (tunnel_id, transport, protocol, direction, result, reason, error_type, version, commit).
   - site_id and region propagation: site_id/region remain resource attributes. Metric labels mirror them on per-site gauges and counters by default; set `NEWT_METRICS_INCLUDE_SITE_LABELS=false` to drop them for multi-tenant scrapes.
   - Label semantics clarified:
     - transport: control-plane mechanism (e.g., websocket, wireguard)
     - protocol: L4 payload type (tcp, udp)
     - newt_tunnel_bytes_total uses protocol and direction, not transport.
   - Robustness improvements: removed duplicate clear logic on reconnect; avoided empty site_id by reading NEWT_SITE_ID/NEWT_ID and OTEL_RESOURCE_ATTRIBUTES.

3) Remaining gaps and deviations

   - Some call sites still need initiator label on reconnect outcomes (client vs server). This is planned.
   - Config apply duration and cert rotation counters are planned.
   - Registration and config reload failures are not yet emitted; add failure code paths so result labels expose churn.
   - Document using `process_start_time_seconds` (and `time()` in PromQL) to derive uptime; no explicit restart counter is needed.
   - Metric helpers often use `context.Background()`. Where lightweight contexts exist (e.g., HTTP handlers), propagate them to ease future correlation.
   - Tracing coverage is limited to admin HTTP and WebSocket connect spans; extend to blueprint fetches, proxy accept loops, and WireGuard updates when OTLP is enabled.

4) Roadmap (phased)

   - Phase 1 (done in this iteration)
     - Fix attribute filter (site_id, region)
     - Propagate site_id (and optional region) across metrics
     - Correct label semantics (transport vs protocol); fix sessions transport labelling
     - Documentation alignment
   - Phase 2 (next)
     - Reconnect: add initiator label (client/server)
     - Config & PKI: newt_config_apply_seconds{phase,result}; newt_cert_rotation_total{result}
     - WebSocket disconnect and keepalive failure counters
     - Proxy connection lifecycle metrics (accept totals, duration histogram)
     - Pangolin blueprint/config fetch latency and status metrics
     - Certificate rotation duration histogram to complement success/failure counter

5) Operational guidance

   - Do not double scrape: scrape either Newt (/metrics) or the Collector’s Prometheus exporter (not both) to avoid double-counting cumulative counters.
   - For high cardinality tunnel_id, consider relabeling or dropping per-tunnel series in Prometheus to control cardinality.
   - OTLP troubleshooting: enable TLS via OTEL_EXPORTER_OTLP_CERTIFICATE, use OTEL_EXPORTER_OTLP_HEADERS for auth; verify endpoint reachability.

6) Example alerts/recording rules (suggestions)

   - Reconnect spikes:
     - increase(newt_tunnel_reconnects_total[5m]) by (site_id)
   - Sustained connection errors:
     - rate(newt_connection_errors_total[5m]) by (site_id,transport,error_type)
   - Heartbeat gaps:
     - max_over_time(time() - newt_site_last_heartbeat_timestamp_seconds[15m]) by (site_id)
   - Proxy drops:
     - increase(newt_proxy_drops_total[5m]) by (site_id,protocol)
   - WebSocket connect p95 (when added):
     - histogram_quantile(0.95, sum(rate(newt_websocket_connect_latency_seconds_bucket[5m])) by (le,site_id))

7) Collector configuration

   - Direct scrape variant requires no attribute promotion since site_id is already a metric label.
   - Transform/promote variant remains optional for environments that rely on resource-to-label promotion.
