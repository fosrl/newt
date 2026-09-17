//go:build linux

package kernelwg

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Open creates a kernel WireGuard interface in the current network namespace.
func Open(c Config) (*Device, error) {
	if err := validate(c); err != nil {
		return nil, err
	}
	client, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	return open(c, &linuxOperations{client: client})
}

type linuxOperations struct{ client *wgctrl.Client }

func (*linuxOperations) lookup(name string) (link, error) {
	l, err := netlink.LinkByName(name)
	var missing netlink.LinkNotFoundError
	if errors.As(err, &missing) {
		return link{}, errLinkNotFound
	}
	if err != nil {
		return link{}, err
	}
	return link{name: l.Attrs().Name, kind: l.Type(), alias: l.Attrs().Alias, index: l.Attrs().Index}, nil
}

func (*linuxOperations) create(name, alias string, mtu int) (link, error) {
	l := &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: name, Alias: alias, MTU: mtu}}
	if err := netlink.LinkAdd(l); err != nil {
		return link{}, err
	}
	return link{name: name, kind: "wireguard", alias: alias, index: l.Index}, nil
}

func netlinkLink(l link) netlink.Link {
	return &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Index: l.index, Name: l.name}}
}

func (*linuxOperations) remove(l link) error { return netlink.LinkDel(netlinkLink(l)) }

func (*linuxOperations) address(l link, prefix netip.Prefix) error {
	addresses := ipNets([]netip.Prefix{prefix})
	return netlink.AddrAdd(netlinkLink(l), &netlink.Addr{IPNet: &addresses[0], Flags: unix.IFA_F_NOPREFIXROUTE})
}

func (*linuxOperations) up(l link) error { return netlink.LinkSetUp(netlinkLink(l)) }

func (o *linuxOperations) configure(name string, c wgtypes.Config) error {
	return o.client.ConfigureDevice(name, c)
}

func route(l link, prefix netip.Prefix, source netip.Addr) *netlink.Route {
	dst := ipNets([]netip.Prefix{prefix})
	return &netlink.Route{LinkIndex: l.index, Dst: &dst[0], Src: net.IP(source.AsSlice()),
		Scope: netlink.SCOPE_LINK, Table: unix.RT_TABLE_MAIN, Protocol: unix.RTPROT_STATIC}
}

func (*linuxOperations) addRoute(l link, prefix netip.Prefix, source netip.Addr) error {
	r := route(l, prefix, source)
	// RouteAdd is exclusive for a route's prefix AND metric. A different
	// existing metric could otherwise coexist and silently lose precedence to
	// ours. Refuse any exact main-table prefix before adding, regardless of
	// metric; overlapping prefixes and policy-routing tables are not managed.
	existing, err := netlink.RouteListFiltered(netlink.FAMILY_V4,
		&netlink.Route{Table: r.Table, Dst: r.Dst}, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_DST)
	if err != nil {
		return fmt.Errorf("inspect existing routes for %s: %w", prefix, err)
	}
	if len(existing) != 0 {
		return fmt.Errorf("main-table route for %s already exists; refusing to change its precedence", prefix)
	}
	return netlink.RouteAdd(r)
}

func (*linuxOperations) delRoute(l link, prefix netip.Prefix, source netip.Addr) error {
	return netlink.RouteDel(route(l, prefix, source))
}

func (o *linuxOperations) close() error { return o.client.Close() }
