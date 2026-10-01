package network

import (
	"context"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// watchRouteEvents calls notify for every route, interface and unicast
// address change notification.
func watchRouteEvents(ctx context.Context, notify func()) error {
	routeCb, err := winipcfg.RegisterRouteChangeCallback(func(winipcfg.MibNotificationType, *winipcfg.MibIPforwardRow2) {
		notify()
	})
	if err != nil {
		return err
	}
	ifaceCb, err := winipcfg.RegisterInterfaceChangeCallback(func(winipcfg.MibNotificationType, *winipcfg.MibIPInterfaceRow) {
		notify()
	})
	if err != nil {
		_ = routeCb.Unregister()
		return err
	}
	addrCb, err := winipcfg.RegisterUnicastAddressChangeCallback(func(winipcfg.MibNotificationType, *winipcfg.MibUnicastIPAddressRow) {
		notify()
	})
	if err != nil {
		_ = routeCb.Unregister()
		_ = ifaceCb.Unregister()
		return err
	}

	go func() {
		<-ctx.Done()
		_ = routeCb.Unregister()
		_ = ifaceCb.Unregister()
		_ = addrCb.Unregister()
	}()

	return nil
}
