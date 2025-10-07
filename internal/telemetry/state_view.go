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
						if online, ok := sv.Online(siteID); ok {
							val := int64(0)
							if online {
								val = 1
							}
							o.ObserveInt64(mSiteOnline, val, metric.WithAttributes(
								attribute.String("site_id", getSiteID()),
							))
						}
						if t, ok := sv.LastHeartbeat(siteID); ok {
							secs := time.Since(t).Seconds()
							o.ObserveFloat64(mSiteLastHeartbeat, secs, metric.WithAttributes(
								attribute.String("site_id", getSiteID()),
							))
						}
						// If the view supports per-tunnel sessions, report them labeled by tunnel_id.
						if tm, ok := any.(interface{ SessionsByTunnel() map[string]int64 }); ok {
							for tid, n := range tm.SessionsByTunnel() {
								o.ObserveInt64(mTunnelSessions, n, metric.WithAttributes(
									attribute.String("site_id", getSiteID()),
									attribute.String("tunnel_id", tid),
								))
							}
						}
					}
				}
			}
			return nil
		})
	}
}
