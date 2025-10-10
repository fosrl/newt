# Newt Metrics: Recommendations, Gaps, and Roadmap

This document captures the current state of Newt metrics, prioritized fixes, and a pragmatic roadmap for near-term improvements.

1) Current setup (summary)

   - Export: Prometheus exposition (default), optional OTLP (gRPC)
   - Existing instruments:
     - Sites: newt_site_registrations_total, newt_site_online (0/1), newt_site_last_heartbeat_seconds
     - Tunnel/Traffic: newt_tunnel_sessions, newt_tunnel_bytes_total, newt_tunnel_latency_seconds, newt_tunnel_reconnects_total
     - Connection lifecycle: newt_connection_attempts_total, newt_connection_errors_total
     - Operations: newt_config_reloads_total, newt_restart_count_total, newt_build_info
     - Go runtime: GC, heap, goroutines via runtime instrumentation

2) Main issues addressed now

   - Attribute filter (allow-list) extended to include site_id and region in addition to existing keys (tunnel_id, transport, protocol, direction, result, reason, error_type, version, commit).
   - site_id and region propagation: site_id is now attached as a metric label across newt_*; region is added as a metric label when set. Both remain resource attributes for consistency with OTEL.
   - Label semantics clarified:
     - transport: control-plane mechanism (e.g., websocket, wireguard)
     - protocol: L4 payload type (tcp, udp)
     - newt_tunnel_bytes_total uses protocol and direction, not transport.
   - Robustness improvements: removed duplicate clear logic on reconnect; avoided empty site_id by reading NEWT_SITE_ID/NEWT_ID and OTEL_RESOURCE_ATTRIBUTES.

3) Remaining gaps and deviations

   - Some call sites still need initiator label on reconnect outcomes (client vs server). This is planned.
   - WebSocket and Proxy metrics (connect latency, messages, active connections, buffer/drops, async backlog) are planned additions.
   - Config apply duration and cert rotation counters are planned.

4) Roadmap (phased)

   - Phase 1 (done in this iteration)
     - Fix attribute filter (site_id, region)
     - Propagate site_id (and optional region) across metrics
     - Correct label semantics (transport vs protocol); fix sessions transport labelling
     - Documentation alignment
   - Phase 2 (next)
     - WebSocket: newt_websocket_connect_latency_seconds; newt_websocket_messages_total{direction,msg_type}
     - Proxy: newt_proxy_active_connections, newt_proxy_buffer_bytes, newt_proxy_drops_total, newt_proxy_async_backlog_bytes
     - Reconnect: add initiator label (client/server)
     - Config & PKI: newt_config_apply_seconds{phase,result}; newt_cert_rotation_total{result}

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
     - max_over_time(newt_site_last_heartbeat_seconds[15m]) by (site_id)
   - Proxy drops:
     - increase(newt_proxy_drops_total[5m]) by (site_id,protocol)
   - WebSocket connect p95 (when added):
     - histogram_quantile(0.95, sum(rate(newt_websocket_connect_latency_seconds_bucket[5m])) by (le,site_id))

7) Collector configuration

   - Direct scrape variant requires no attribute promotion since site_id is already a metric label.
   - Transform/promote variant remains optional for environments that rely on resource-to-label promotion.

8) Testing

- curl :2112/metrics | grep ^newt_
- Verify presence of site_id across series; region appears when set.
- Ensure disallowed attributes are filtered; allowed (site_id) retained.
