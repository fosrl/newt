//go:build linux

package kernelwg

import (
	"errors"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
)

// TestLinuxKernelLifecycle is explicitly opt-in and performs all networking
// changes in a fresh network namespace. It requires CAP_SYS_ADMIN,
// CAP_NET_ADMIN, and host kernel WireGuard support; it does not change host
// routes. This checks the real kernel adapter, not Pangolin or stream throughput.
func TestLinuxKernelLifecycle(t *testing.T) {
	if os.Getenv("NEWT_KERNEL_WG_INTEGRATION") != "1" {
		t.Skip("set NEWT_KERNEL_WG_INTEGRATION=1 on Linux with namespace/network capabilities")
	}
	runtime.LockOSThread()
	original, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	isolated, err := netns.New()
	if err != nil {
		_ = original.Close()
		runtime.UnlockOSThread()
		t.Fatalf("create isolated network namespace: %v", err)
	}
	defer func() {
		err := netns.Set(original)
		_ = isolated.Close()
		_ = original.Close()
		if err != nil {
			// Do not return a thread in the wrong namespace to the runtime.
			t.Errorf("restore original network namespace: %v", err)
			return
		}
		runtime.UnlockOSThread()
	}()
	c := testConfig()
	d, err := Open(c)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := d.Close(); err != nil {
			t.Errorf("close test WireGuard interface: %v", err)
		}
	}()
	l, err := netlink.LinkByName(c.Name)
	if err != nil {
		t.Fatal(err)
	}
	if l.Type() != "wireguard" || l.Attrs().MTU != c.MTU || l.Attrs().Alias != d.link.alias || l.Attrs().Index != d.link.index {
		t.Fatalf("unexpected kernel interface: %+v", l)
	}
	addresses, err := netlink.AddrList(l, netlink.FAMILY_V4)
	if err != nil || len(addresses) != 1 || addresses[0].IPNet.String() != c.Address.String() {
		t.Fatalf("unexpected addresses: %v (error %v)", addresses, err)
	}
	control, err := wgctrl.New()
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	state, err := control.Device(c.Name)
	if err != nil {
		t.Fatal(err)
	}
	if state.ListenPort == 0 || len(state.Peers) != 1 || state.Peers[0].PublicKey != c.PeerPublicKey || state.Peers[0].PersistentKeepaliveInterval != 5*time.Second {
		t.Fatalf("unexpected kernel WireGuard peer: %+v", state)
	}
	next := netip.MustParsePrefix("10.42.0.0/24")
	if err := d.SetAllowedIPs([]netip.Prefix{next}); err != nil {
		t.Fatal(err)
	}
	routes, err := netlink.RouteList(l, netlink.FAMILY_V4)
	if err != nil || len(routes) != 1 || routes[0].Dst.String() != next.String() || routes[0].Src.String() != c.Address.Addr().String() {
		t.Fatalf("unexpected routes after update: %v (error %v)", routes, err)
	}
	state, err = control.Device(c.Name)
	if err != nil || len(state.Peers) != 1 || len(state.Peers[0].AllowedIPs) != 1 || state.Peers[0].AllowedIPs[0].String() != next.String() {
		t.Fatalf("unexpected peer after update: %v (error %v)", state, err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = netlink.LinkByName(c.Name)
	var missing netlink.LinkNotFoundError
	if !errors.As(err, &missing) {
		t.Fatalf("interface remains after Close: %v", err)
	}

	// Even a higher-metric exact route belongs to someone else. A metric-zero
	// Newt route would take precedence without replacing the original route.
	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(loopback); err != nil {
		t.Fatal(err)
	}
	destination := ipNets(c.AllowedIPs)[0]
	foreign := &netlink.Route{LinkIndex: loopback.Attrs().Index, Dst: &destination,
		Priority: 1000, Table: unix.RT_TABLE_MAIN, Scope: netlink.SCOPE_LINK}
	if err := netlink.RouteAdd(foreign); err != nil {
		t.Fatal(err)
	}
	if other, err := Open(c); err == nil {
		_ = other.Close()
		t.Fatal("existing main-table route with a different metric was accepted")
	} else if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("unexpected route conflict error: %v", err)
	}
	routes, err = netlink.RouteListFiltered(netlink.FAMILY_V4,
		&netlink.Route{Table: unix.RT_TABLE_MAIN, Dst: &destination}, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_DST)
	if err != nil || len(routes) != 1 || routes[0].Priority != 1000 || routes[0].LinkIndex != loopback.Attrs().Index {
		t.Fatalf("foreign route changed: %v (error %v)", routes, err)
	}
	_, err = netlink.LinkByName(c.Name)
	if !errors.As(err, &missing) {
		t.Fatalf("route conflict left an interface behind: %v", err)
	}
}
