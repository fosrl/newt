package network

import (
	"context"
	"time"

	"github.com/fosrl/newt/logger"
	"github.com/vishvananda/netlink"
)

// watchRouteEvents calls notify for every netlink route, address and link
// update. netlink ends a subscription on any receive error (e.g. the socket
// buffer overflowing during a burst), so it resubscribes when that happens,
// notifying once in case the lost messages mattered.
func watchRouteEvents(ctx context.Context, notify func()) error {
	done, routes, addrs, links, err := subscribeRouteEvents()
	if err != nil {
		return err
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				stopRouteEvents(done, routes, addrs, links)
				return
			case _, ok := <-routes:
				if ok {
					notify()
					continue
				}
			case _, ok := <-addrs:
				if ok {
					notify()
					continue
				}
			case _, ok := <-links:
				if ok {
					notify()
					continue
				}
			}

			// A subscription ended without ctx being done.
			logger.Warn("Route change subscription ended, resubscribing")
			stopRouteEvents(done, routes, addrs, links)
			notify()
			for {
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Second):
				}
				done, routes, addrs, links, err = subscribeRouteEvents()
				if err == nil {
					break
				}
				logger.Warn("Failed to resubscribe to route changes: %v", err)
			}
		}
	}()

	return nil
}

func subscribeRouteEvents() (chan struct{}, chan netlink.RouteUpdate, chan netlink.AddrUpdate, chan netlink.LinkUpdate, error) {
	done := make(chan struct{})
	routes := make(chan netlink.RouteUpdate, 64)
	addrs := make(chan netlink.AddrUpdate, 64)
	links := make(chan netlink.LinkUpdate, 64)

	if err := netlink.RouteSubscribe(routes, done); err != nil {
		close(done)
		return nil, nil, nil, nil, err
	}
	if err := netlink.AddrSubscribe(addrs, done); err != nil {
		stopRouteEvents(done, routes, nil, nil)
		return nil, nil, nil, nil, err
	}
	if err := netlink.LinkSubscribe(links, done); err != nil {
		stopRouteEvents(done, routes, addrs, nil)
		return nil, nil, nil, nil, err
	}
	return done, routes, addrs, links, nil
}

// stopRouteEvents ends the subscriptions and drains their channels in the
// background: netlink's receive goroutines block sending to a full channel
// and only exit (closing it) once they observe the closed socket.
func stopRouteEvents(done chan struct{}, routes chan netlink.RouteUpdate, addrs chan netlink.AddrUpdate, links chan netlink.LinkUpdate) {
	close(done)
	go func() {
		if routes != nil {
			for range routes {
			}
		}
		if addrs != nil {
			for range addrs {
			}
		}
		if links != nil {
			for range links {
			}
		}
	}()
}
