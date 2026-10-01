//go:build linux

package network

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func ipCmd(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("ip %v: %v %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestBypassReconcileNetns exercises bypass routes against a real kernel
// routing table, with a gateway route (0.0.0.0/1 + 128.0.0.0/1) on a fake
// tunnel interface: adding a bypass while the gateway route is installed, and
// WatchRouteChanges + ReconcileBypassRoute following the physical network
// through an interface switch, a default route move, and going offline. It
// modifies the routing table, so it only runs inside a throwaway network
// namespace:
//
//	NETNS_TEST=1 unshare -rn go test ./network -run TestBypassReconcileNetns -v
func TestBypassReconcileNetns(t *testing.T) {
	if os.Getenv("NETNS_TEST") == "" {
		t.Skip()
	}
	ipCmd(t, "link", "add", "phys0", "type", "dummy")
	ipCmd(t, "link", "set", "phys0", "up")
	ipCmd(t, "addr", "add", "10.0.0.2/24", "dev", "phys0")
	ipCmd(t, "route", "add", "default", "via", "10.0.0.1", "dev", "phys0")
	ipCmd(t, "link", "add", "tun0", "type", "dummy")
	ipCmd(t, "link", "set", "tun0", "up")
	ipCmd(t, "addr", "add", "100.64.0.2/32", "dev", "tun0")
	ipCmd(t, "route", "add", "0.0.0.0/1", "dev", "tun0")
	ipCmd(t, "route", "add", "128.0.0.0/1", "dev", "tun0")

	// Added while the gateway route is already installed.
	if err := LinuxAddBypassRoute("1.1.1.1", "tun0"); err != nil {
		t.Fatal(err)
	}
	t.Logf("initial: %s", ipCmd(t, "route", "get", "1.1.1.1"))

	var calls atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := WatchRouteChanges(ctx, func() {
		calls.Add(1)
		changed, err := ReconcileBypassRoute("1.1.1.1", "tun0")
		t.Logf("reconcile #%d: changed=%v err=%v", calls.Load(), changed, err)
	}); err != nil {
		t.Fatal(err)
	}
	routeVia := func(want string) func() bool {
		return func() bool {
			out, _ := exec.Command("ip", "route", "show", "1.1.1.1/32").CombinedOutput()
			return strings.Contains(string(out), want)
		}
	}

	// 1. Physical interface disappears; a new network comes up elsewhere.
	ipCmd(t, "link", "del", "phys0")
	ipCmd(t, "link", "add", "phys1", "type", "dummy")
	ipCmd(t, "link", "set", "phys1", "up")
	ipCmd(t, "addr", "add", "192.168.5.2/24", "dev", "phys1")
	ipCmd(t, "route", "add", "default", "via", "192.168.5.1", "dev", "phys1")
	waitFor(t, "bypass via phys1", routeVia("via 192.168.5.1 dev phys1"))
	t.Logf("after interface switch: %s", ipCmd(t, "route", "get", "1.1.1.1"))

	// 2. Default moves to another interface while the old one stays up.
	ipCmd(t, "link", "add", "phys2", "type", "dummy")
	ipCmd(t, "link", "set", "phys2", "up")
	ipCmd(t, "addr", "add", "10.9.0.2/24", "dev", "phys2")
	ipCmd(t, "route", "replace", "default", "via", "10.9.0.1", "dev", "phys2")
	waitFor(t, "bypass via phys2", routeVia("via 10.9.0.1 dev phys2"))
	t.Logf("after default moved: %s", ipCmd(t, "route", "get", "1.1.1.1"))

	// 3. No feedback loop: our own route changes settle to a no-op.
	time.Sleep(2500 * time.Millisecond)
	settled := calls.Load()
	time.Sleep(3 * time.Second)
	if calls.Load() != settled {
		t.Fatalf("reconcile keeps firing: %d -> %d", settled, calls.Load())
	}
	t.Logf("settled after %d reconcile calls", settled)

	// 4. Offline: reported as ErrNoPhysicalRoute.
	cancel()
	time.Sleep(200 * time.Millisecond)
	ipCmd(t, "route", "del", "default")
	if _, err := ReconcileBypassRoute("1.1.1.1", "tun0"); !errors.Is(err, ErrNoPhysicalRoute) {
		t.Fatalf("expected ErrNoPhysicalRoute, got %v", err)
	}
}
