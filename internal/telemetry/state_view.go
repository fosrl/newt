package telemetry

import (
	"context"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// StateView provides a read-only view for observable gauges.
// Implementations must be concurrency-safe and avoid blocking operations.
// All methods should be fast and use RLocks where applicable.
type StateView interface {
	// ListSites returns a stable, low-cardinality list of site IDs to expose.
	ListSites() []string
	// Online returns whether the site is online.
	Online(siteID string) (online bool, ok bool)
	// LastHeartbeat returns the last heartbeat time for a site.
	LastHeartbeat(siteID string) (t time.Time, ok bool)
	// ActiveSessions returns the current number of active sessions for a site (across tunnels),
	// or scoped to site if your model is site-scoped.
	ActiveSessions(siteID string) (n int64, ok bool)
}

var (
	stateView atomic.Value // of type StateView
)

// RegisterStateView sets the global StateView used by the default observable callback.
func RegisterStateView(v StateView) {
	stateView.Store(v)
	// If instruments are registered, ensure a callback exists.
	if v != nil {
		SetObservableCallback(func(ctx context.Context, o metric.Observer) error {
			if any := stateView.Load(); any != nil {
				if sv, ok := any.(StateView); ok {
					for _, siteID := range sv.ListSites() {
						observeSiteOnlineFor(o, sv, siteID)
						observeLastHeartbeatFor(o, sv, siteID)
						observeSessionsFor(o, siteID, sv)
					}
				}
			}
			return nil
		})
	}
}

func observeSiteOnlineFor(o metric.Observer, sv StateView, siteID string) {
	if online, ok := sv.Online(siteID); ok {
		val := int64(0)
		if online {
			val = 1
		}
		o.ObserveInt64(mSiteOnline, val, metric.WithAttributes(
			attribute.String("site_id", siteID),
		))
	}
}

func observeLastHeartbeatFor(o metric.Observer, sv StateView, siteID string) {
	if t, ok := sv.LastHeartbeat(siteID); ok {
		ts := float64(t.UnixNano()) / 1e9
		o.ObserveFloat64(mSiteLastHeartbeat, ts, metric.WithAttributes(
			attribute.String("site_id", siteID),
		))
	}
}

func observeSessionsFor(o metric.Observer, siteID string, any interface{}) {
	if tm, ok := any.(interface{ SessionsByTunnel() map[string]int64 }); ok {
		sessions := tm.SessionsByTunnel()
		// If tunnel_id labels are enabled, preserve existing per-tunnel observations
		if ShouldIncludeTunnelID() {
			for tid, n := range sessions {
				attrs := []attribute.KeyValue{
					attribute.String("site_id", siteID),
				}
				if tid != "" {
					attrs = append(attrs, attribute.String("tunnel_id", tid))
				}
				o.ObserveInt64(mTunnelSessions, n, metric.WithAttributes(attrs...))
			}
			return
		}
		// When tunnel_id is disabled, collapse per-tunnel counts into a single site-level value
		var total int64
		for _, n := range sessions {
			total += n
		}
		// If there are no per-tunnel entries, fall back to ActiveSessions() if available
		if total == 0 {
			if svAny := stateView.Load(); svAny != nil {
				if sv, ok := svAny.(StateView); ok {
					if n, ok2 := sv.ActiveSessions(siteID); ok2 {
						total = n
					}
				}
			}
		}
		o.ObserveInt64(mTunnelSessions, total, metric.WithAttributes(attribute.String("site_id", siteID)))
		return
	}
}
