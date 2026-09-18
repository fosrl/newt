// Package kernelwg manages one Linux kernel WireGuard interface for Newt's
// main tunnel. It never adopts an existing interface or replaces host routes.
package kernelwg

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Config describes a single-peer, IPv4 main tunnel. The outer endpoint may be
// IPv6. ProtectedIPs are control-plane addresses that must remain outside it.
type Config struct {
	Name          string
	Owner         string
	PrivateKey    wgtypes.Key
	PeerPublicKey wgtypes.Key
	Endpoint      *net.UDPAddr
	Address       netip.Prefix
	AllowedIPs    []netip.Prefix
	ProtectedIPs  []netip.Addr
	MTU           int
}

type link struct {
	name, kind, alias string
	index             int
}

var errLinkNotFound = errors.New("interface not found")

// operations keeps privileged OS operations separate from lifecycle logic.
type operations interface {
	lookup(string) (link, error)
	create(name, alias string, mtu int) (link, error)
	remove(link) error
	address(link, netip.Prefix) error
	up(link) error
	configure(string, wgtypes.Config) error
	addRoute(link, netip.Prefix, netip.Addr) error
	delRoute(link, netip.Prefix, netip.Addr) error
	close() error
}

// Device owns its interface and the routes attached to it. Methods are safe for
// concurrent use. A failed route update should cause the caller to reconnect:
// rollback errors are returned, rather than hiding potentially partial state.
type Device struct {
	mu     sync.Mutex
	config Config
	link   link
	ops    operations
	closed bool
}

func validate(c Config) error {
	if c.Name == "" || c.Name == "." || c.Name == ".." || len(c.Name) > 15 ||
		strings.ContainsAny(c.Name, "/:\x00") || strings.IndexFunc(c.Name, unicode.IsSpace) >= 0 {
		return errors.New("kernel WireGuard interface name must be 1-15 bytes without whitespace, '/', ':', or NUL, excluding . and ..")
	}
	if c.Owner == "" || len(c.Owner) > 128 || strings.ContainsRune(c.Owner, '\x00') {
		return errors.New("kernel WireGuard owner must be 1-128 bytes without NUL characters")
	}
	if c.MTU < 576 || c.MTU > 65535 {
		return errors.New("kernel WireGuard MTU must be between 576 and 65535")
	}
	if !c.Address.IsValid() || !c.Address.Addr().Is4() || c.Address.Bits() != 32 || !c.Address.Addr().IsGlobalUnicast() {
		return errors.New("kernel WireGuard requires a unicast IPv4 /32 tunnel address")
	}
	if c.PrivateKey == (wgtypes.Key{}) || c.PeerPublicKey == (wgtypes.Key{}) {
		return errors.New("kernel WireGuard requires nonzero private and peer public keys")
	}
	if c.Endpoint == nil || c.Endpoint.Port < 1 || c.Endpoint.Port > 65535 {
		return errors.New("kernel WireGuard requires a resolved UDP endpoint")
	}
	ip, ok := netip.AddrFromSlice(c.Endpoint.IP)
	if !ok || ip.Unmap().IsUnspecified() || ip.Unmap().IsMulticast() {
		return errors.New("kernel WireGuard requires a unicast endpoint address")
	}
	_, err := allowedIPs(c, c.AllowedIPs)
	return err
}

func allowedIPs(c Config, prefixes []netip.Prefix) ([]netip.Prefix, error) {
	endpoint, _ := netip.AddrFromSlice(c.Endpoint.IP)
	protected := append([]netip.Addr{c.Address.Addr(), endpoint.Unmap()}, c.ProtectedIPs...)
	result := make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		if !prefix.IsValid() || !prefix.Addr().Is4() || prefix.Bits() == 0 {
			return nil, fmt.Errorf("kernel WireGuard only supports non-default IPv4 AllowedIPs: %s", prefix)
		}
		prefix = prefix.Masked()
		for _, addr := range protected {
			if prefix.Contains(addr.Unmap()) {
				return nil, fmt.Errorf("kernel WireGuard route %s includes protected address %s", prefix, addr)
			}
		}
		if !slices.Contains(result, prefix) {
			result = append(result, prefix)
		}
	}
	return result, nil
}

func open(c Config, ops operations) (_ *Device, err error) {
	d := &Device{config: c, ops: ops}
	defer func() {
		if err != nil {
			err = errors.Join(err, d.Close())
		}
	}()
	if err = validate(c); err != nil {
		return nil, err
	}
	d.config.AllowedIPs, _ = allowedIPs(c, c.AllowedIPs)
	d.config.ProtectedIPs = slices.Clone(c.ProtectedIPs)
	endpoint := *c.Endpoint
	endpoint.IP = slices.Clone(c.Endpoint.IP)
	d.config.Endpoint = &endpoint
	if _, lookupErr := ops.lookup(c.Name); !errors.Is(lookupErr, errLinkNotFound) {
		if lookupErr != nil {
			return nil, fmt.Errorf("inspect kernel WireGuard interface: %w", lookupErr)
		}
		return nil, fmt.Errorf("interface %s already exists; refusing to modify it (remove stale Newt interfaces manually after verifying ownership)", c.Name)
	}
	token := make([]byte, 16)
	if _, err = rand.Read(token); err != nil {
		return nil, fmt.Errorf("generate interface ownership marker: %w", err)
	}
	d.link, err = ops.create(c.Name, fmt.Sprintf("newt:%s:%x", c.Owner, token), c.MTU)
	if err != nil {
		return nil, fmt.Errorf("create kernel WireGuard interface (requires Linux WireGuard support and CAP_NET_ADMIN): %w", err)
	}
	if err = d.checkOwned(); err != nil {
		return nil, err
	}
	keepalive := 5 * time.Second
	listenPort := 0 // Let the kernel allocate a port, independent of Olm's socket.
	if err = ops.configure(c.Name, wgtypes.Config{
		PrivateKey: &c.PrivateKey, ListenPort: &listenPort, ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{{PublicKey: c.PeerPublicKey, Endpoint: &endpoint,
			PersistentKeepaliveInterval: &keepalive, ReplaceAllowedIPs: true,
			AllowedIPs: ipNets(d.config.AllowedIPs)}},
	}); err != nil {
		return nil, fmt.Errorf("configure kernel WireGuard peer: %w", err)
	}
	d.config.PrivateKey = wgtypes.Key{}
	if err = ops.address(d.link, c.Address); err != nil {
		return nil, fmt.Errorf("assign kernel WireGuard address: %w", err)
	}
	if err = ops.up(d.link); err != nil {
		return nil, fmt.Errorf("bring up kernel WireGuard interface: %w", err)
	}
	for _, prefix := range d.config.AllowedIPs {
		if err = ops.addRoute(d.link, prefix, c.Address.Addr()); err != nil {
			return nil, fmt.Errorf("add kernel WireGuard route %s: %w", prefix, err)
		}
	}
	return d, nil
}

func ipNets(prefixes []netip.Prefix) []net.IPNet {
	result := make([]net.IPNet, 0, len(prefixes))
	for _, prefix := range prefixes {
		result = append(result, net.IPNet{IP: net.IP(prefix.Addr().AsSlice()), Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen())})
	}
	return result
}

func (d *Device) checkOwned() error {
	current, err := d.ops.lookup(d.link.name)
	if err != nil {
		return err
	}
	// LinkAdd learns the index with a follow-up lookup. If that lookup failed,
	// recover it only from the unique marker assigned during our successful
	// creation; an existing interface never receives such a marker from us.
	if d.link.index == 0 && d.link.alias != "" && current.index > 0 && current.name == d.link.name && current.kind == d.link.kind && current.alias == d.link.alias {
		d.link.index = current.index
	}
	if d.link.index == 0 || current != d.link || current.kind != "wireguard" {
		return fmt.Errorf("ownership of interface %s changed; refusing to modify it (expected name=%q type=%q index=%d alias=%q, got name=%q type=%q index=%d alias=%q)",
			d.link.name, d.link.name, d.link.kind, d.link.index, d.link.alias,
			current.name, current.kind, current.index, current.alias)
	}
	return nil
}

func (d *Device) configureAllowed(prefixes []netip.Prefix) error {
	return d.ops.configure(d.link.name, wgtypes.Config{Peers: []wgtypes.PeerConfig{{
		PublicKey: d.config.PeerPublicKey, UpdateOnly: true, ReplaceAllowedIPs: true,
		AllowedIPs: ipNets(prefixes),
	}}})
}

// SetAllowedIPs replaces this peer's AllowedIPs and the matching owned routes.
// Existing OS routes are never replaced. Changes are rolled back on failure;
// any rollback failure is included in the returned error.
func (d *Device) SetAllowedIPs(prefixes []netip.Prefix) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return errors.New("kernel WireGuard device is closed")
	}
	next, err := allowedIPs(d.config, prefixes)
	if err != nil {
		return err
	}
	if err := d.checkOwned(); err != nil {
		return err
	}
	previous := d.config.AllowedIPs
	var added, removed []netip.Prefix
	rollback := func(cause error, restorePeer bool) error {
		for _, prefix := range removed {
			if err := d.ops.addRoute(d.link, prefix, d.config.Address.Addr()); err != nil {
				cause = errors.Join(cause, fmt.Errorf("restore route %s: %w", prefix, err))
			}
		}
		if restorePeer {
			if err := d.configureAllowed(previous); err != nil {
				cause = errors.Join(cause, fmt.Errorf("restore WireGuard AllowedIPs: %w", err))
			}
		}
		for _, prefix := range added {
			if err := d.ops.delRoute(d.link, prefix, d.config.Address.Addr()); err != nil {
				cause = errors.Join(cause, fmt.Errorf("roll back route %s: %w", prefix, err))
			}
		}
		return cause
	}
	for _, prefix := range next {
		if !slices.Contains(previous, prefix) {
			if err := d.ops.addRoute(d.link, prefix, d.config.Address.Addr()); err != nil {
				return rollback(fmt.Errorf("add route %s: %w", prefix, err), false)
			}
			added = append(added, prefix)
		}
	}
	if err := d.configureAllowed(next); err != nil {
		return rollback(fmt.Errorf("update WireGuard AllowedIPs: %w", err), true)
	}
	for _, prefix := range previous {
		if !slices.Contains(next, prefix) {
			if err := d.ops.delRoute(d.link, prefix, d.config.Address.Addr()); err != nil {
				return rollback(fmt.Errorf("remove route %s: %w", prefix, err), true)
			}
			removed = append(removed, prefix)
		}
	}
	d.config.AllowedIPs = next
	return nil
}

// Close removes only this instance's interface. Linux removes its attached
// routes and addresses with it. SIGKILL cannot run Close; stale interfaces must
// be inspected and removed by the operator before restarting.
func (d *Device) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	var err error
	if d.link.name != "" {
		if ownershipErr := d.checkOwned(); ownershipErr == nil {
			err = d.ops.remove(d.link)
		} else if !errors.Is(ownershipErr, errLinkNotFound) {
			err = ownershipErr
		}
	}
	if err != nil {
		err = fmt.Errorf("remove owned kernel WireGuard interface %s: %w", d.link.name, err)
	}
	d.closed = true
	return errors.Join(err, d.ops.close())
}
