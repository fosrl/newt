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

func (o *linuxOperations) create(name, alias string, mtu int) (link, error) {
	return createLinuxLink(name, alias, mtu, netlink.LinkAdd, o.lookup, netlink.LinkSetAlias)
}

func createLinuxLink(name, alias string, mtu int,
	add func(netlink.Link) error,
	lookup func(string) (link, error),
	setAlias func(netlink.Link, string) error,
) (link, error) {
	// Linux does not apply IFLA_IFALIAS when creating a link. Assign it in a
	// separate operation after verifying the exclusively created interface.
	l := &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: name, MTU: mtu}}
	if err := add(l); err != nil {
		return link{}, err
	}
	created := link{name: name, kind: "wireguard", index: l.Index}
	if created.index <= 0 {
		// Without an index or installed ownership marker, adopting a name
		// could capture another administrator's replacement interface.
		return created, errors.New("created WireGuard interface has no known index; refusing to modify or remove it")
	}
	current, err := lookup(name)
	if err != nil {
		return created, fmt.Errorf("inspect newly created WireGuard interface: %w", err)
	}
	if current != created {
		return created, errors.New("newly created WireGuard interface changed before assigning ownership marker")
	}
	if err := setAlias(netlinkLink(created), alias); err != nil {
		// A failed operation may still have applied. Preserve only a verified
		// identity for open's rollback; never adopt a foreign alias or index.
		current, lookupErr := lookup(name)
		if lookupErr == nil && current.name == created.name && current.kind == created.kind &&
			current.index == created.index && (current.alias == "" || current.alias == alias) {
			created.alias = current.alias
		}
		return created, errors.Join(fmt.Errorf("set WireGuard ownership marker: %w", err), lookupErr)
	}
	created.alias = alias
	return created, nil
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
