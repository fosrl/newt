//go:build !linux && !darwin && !windows

package network

import "context"

func watchRouteEvents(ctx context.Context, notify func()) error {
	return nil
}
