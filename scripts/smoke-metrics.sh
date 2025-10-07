#!/usr/bin/env bash
set -euo pipefail

NEWTHOST=${NEWTHOST:-localhost}
NEWTPORT=${NEWTPORT:-2112}
METRICS_URL="http://${NEWTHOST}:${NEWTPORT}/metrics"

probe() {
  local name=$1
  local pattern=$2
  echo "[probe] ${name}"
  curl -sf "${METRICS_URL}" | grep -E "${pattern}" || {
    echo "[warn] ${name} not found"
    return 1
  }
}

# Basic presence
probe "newt_* presence" "^newt_" || true

# Site gauges with site_id
probe "site_online with site_id" "^newt_site_online\{.*site_id=\"[^\"]+\"" || true
probe "last_heartbeat with site_id" "^newt_site_last_heartbeat_seconds\{.*site_id=\"[^\"]+\"" || true

# Bytes with direction ingress/egress and protocol
probe "tunnel bytes ingress" "^newt_tunnel_bytes_total\{.*direction=\"ingress\".*protocol=\"(tcp|udp)\"" || true
probe "tunnel bytes egress" "^newt_tunnel_bytes_total\{.*direction=\"egress\".*protocol=\"(tcp|udp)\"" || true

# WebSocket metrics (when OTLP/WS used)
probe "websocket connect latency buckets" "^newt_websocket_connect_latency_seconds_bucket" || true
probe "websocket messages total" "^newt_websocket_messages_total\{.*(direction|msg_type)=" || true

# Proxy metrics (when proxy active)
probe "proxy active connections" "^newt_proxy_active_connections\{" || true
probe "proxy buffer bytes" "^newt_proxy_buffer_bytes\{" || true
probe "proxy drops total" "^newt_proxy_drops_total\{" || true

# Config apply
probe "config apply seconds buckets" "^newt_config_apply_seconds_bucket\{" || true

echo "Smoke checks completed (warnings above are acceptable if the feature isn't exercised yet)."

