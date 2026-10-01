package network

import (
	"context"
	"os"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// watchRouteEvents calls notify for routing socket messages that can change
// the physical path: routes added/removed/changed, interface addresses
// added/removed, and interface state changes. ARP/NDP neighbor entries
// (cloned host routes) and RTM_GET replies - which include those to our own
// `route get` calls - are ignored, as they would otherwise trigger constantly.
func watchRouteEvents(ctx context.Context, notify func()) error {
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return err
	}
	// Non-blocking so os.NewFile registers it with the runtime poller and
	// Close interrupts a pending Read.
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return err
	}
	f := os.NewFile(uintptr(fd), "route")

	go func() {
		<-ctx.Done()
		f.Close()
	}()

	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := f.Read(buf)
			if err != nil {
				return
			}
			if isRelevantRouteMessage(buf[:n]) {
				notify()
			}
		}
	}()

	return nil
}

func isRelevantRouteMessage(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	switch int(b[3]) { // rtm_type, common to every routing message header
	case unix.RTM_NEWADDR, unix.RTM_DELADDR, unix.RTM_IFINFO:
		return true
	case unix.RTM_ADD, unix.RTM_DELETE, unix.RTM_CHANGE:
		msgs, err := route.ParseRIB(route.RIBTypeRoute, b)
		if err != nil || len(msgs) == 0 {
			return true
		}
		if m, ok := msgs[0].(*route.RouteMessage); ok && m.Flags&(unix.RTF_LLINFO|unix.RTF_WASCLONED) != 0 {
			return false
		}
		return true
	}
	return false
}
