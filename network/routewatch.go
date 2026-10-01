package network

import (
	"context"
	"time"
)

const (
	// routeChangeSettle is how long the routing table must be quiet after a
	// change before onChange runs, so the burst of updates a single network
	// switch produces (link, addresses, routes) is handled once, after it has
	// finished.
	routeChangeSettle = time.Second
	// routeChangeMaxDelay bounds how long continuous churn can postpone
	// onChange.
	routeChangeMaxDelay = 5 * time.Second
)

// WatchRouteChanges calls onChange whenever the host's routing table,
// interface addresses or link state change - debounced, so one network switch
// results in one call - until ctx is done. Only events from the OS are
// watched: changes this process makes itself (e.g. adding bypass routes) also
// trigger it, so onChange must be idempotent. A no-op where ManagesHostRoutes
// is false, since there are no host routes to keep up to date there.
func WatchRouteChanges(ctx context.Context, onChange func()) error {
	if !ManagesHostRoutes() {
		return nil
	}

	trigger := make(chan struct{}, 1)
	notify := func() {
		select {
		case trigger <- struct{}{}:
		default:
		}
	}

	if err := watchRouteEvents(ctx, notify); err != nil {
		return err
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-trigger:
			}

			settle := time.NewTimer(routeChangeSettle)
			maxDelay := time.NewTimer(routeChangeMaxDelay)
		wait:
			for {
				select {
				case <-ctx.Done():
					settle.Stop()
					maxDelay.Stop()
					return
				case <-trigger:
					settle.Reset(routeChangeSettle)
				case <-settle.C:
					break wait
				case <-maxDelay.C:
					break wait
				}
			}
			settle.Stop()
			maxDelay.Stop()

			onChange()
		}
	}()

	return nil
}
