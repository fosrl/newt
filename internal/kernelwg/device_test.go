package kernelwg

import (
	"errors"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var injectedError = errors.New("injected failure")

type fakeRoute struct {
	owner int
	src   netip.Addr
}

type fakeOperations struct {
	createWithoutIndex bool
	links              map[string]link
	routes             map[netip.Prefix]fakeRoute
	allowed            []netip.Prefix
	initial            wgtypes.Config
	mtu                int
	addr               netip.Prefix
	isUp               bool
	closed             bool
	calls              []string
	failures           map[string]int
	callCounts         map[string]int
}

func newFake() *fakeOperations {
	return &fakeOperations{
		links:    map[string]link{"wg0": {name: "wg0", kind: "wireguard", alias: "existing VPN", index: 2}},
		routes:   map[netip.Prefix]fakeRoute{netip.MustParsePrefix("192.168.1.0/24"): {owner: 2}},
		failures: make(map[string]int), callCounts: make(map[string]int),
	}
}

func (f *fakeOperations) step(name string) error {
	f.calls = append(f.calls, name)
	f.callCounts[name]++
	if f.failures[name] == f.callCounts[name] {
		return injectedError
	}
	return nil
}

func (f *fakeOperations) lookup(name string) (link, error) {
	if err := f.step("lookup"); err != nil {
		return link{}, err
	}
	l, ok := f.links[name]
	if !ok {
		return link{}, errLinkNotFound
	}
	return l, nil
}

func (f *fakeOperations) create(name, alias string, mtu int) (link, error) {
	if err := f.step("create"); err != nil {
		return link{}, err
	}
	if _, exists := f.links[name]; exists {
		return link{}, errors.New("interface exists")
	}
	l := link{name: name, kind: "wireguard", alias: alias, index: 10}
	f.links[name] = l
	f.mtu = mtu
	if f.createWithoutIndex {
		l.index = 0
	}
	return l, nil
}

func (f *fakeOperations) remove(l link) error {
	if err := f.step("remove"); err != nil {
		return err
	}
	delete(f.links, l.name)
	for prefix, route := range f.routes {
		if route.owner == l.index {
			delete(f.routes, prefix)
		}
	}
	return nil
}

func (f *fakeOperations) address(_ link, prefix netip.Prefix) error {
	if err := f.step("address"); err != nil {
		return err
	}
	f.addr = prefix
	return nil
}

func (f *fakeOperations) up(link) error {
	if err := f.step("up"); err != nil {
		return err
	}
	f.isUp = true
	return nil
}

func (f *fakeOperations) configure(_ string, c wgtypes.Config) error {
	if c.PrivateKey != nil {
		f.initial = c
	}
	f.allowed = nil
	for _, prefix := range c.Peers[0].AllowedIPs {
		f.allowed = append(f.allowed, netip.MustParsePrefix(prefix.String()))
	}
	// A kernel configuration can partially apply before it reports an error.
	return f.step("configure")
}

func (f *fakeOperations) addRoute(l link, prefix netip.Prefix, source netip.Addr) error {
	if err := f.step("addRoute"); err != nil {
		return err
	}
	if _, exists := f.routes[prefix]; exists {
		return errors.New("route exists")
	}
	f.routes[prefix] = fakeRoute{owner: l.index, src: source}
	return nil
}

func (f *fakeOperations) delRoute(l link, prefix netip.Prefix, source netip.Addr) error {
	if err := f.step("delRoute"); err != nil {
		return err
	}
	if f.routes[prefix] != (fakeRoute{owner: l.index, src: source}) {
		return errors.New("route missing or foreign")
	}
	delete(f.routes, prefix)
	return nil
}

func (f *fakeOperations) close() error {
	f.closed = true
	return f.step("close")
}

func testConfig() Config {
	return Config{Name: "newt-wg0", Owner: "test-site", PrivateKey: wgtypes.Key{1}, PeerPublicKey: wgtypes.Key{2},
		Endpoint: &net.UDPAddr{IP: net.ParseIP("203.0.113.20"), Port: 51820},
		Address:  netip.MustParsePrefix("100.90.0.2/32"), MTU: 1280,
		AllowedIPs:   []netip.Prefix{netip.MustParsePrefix("100.90.0.1/32")},
		ProtectedIPs: []netip.Addr{netip.MustParseAddr("198.51.100.10")}}
}

func TestOpenAndCloseOwnOnlyCreatedInterface(t *testing.T) {
	f := newFake()
	c := testConfig()
	d, err := open(c, f)
	if err != nil {
		t.Fatal(err)
	}
	if !f.isUp || f.mtu != c.MTU || f.addr != c.Address {
		t.Fatalf("incomplete setup: up=%v mtu=%d address=%s", f.isUp, f.mtu, f.addr)
	}
	if f.initial.ListenPort == nil || *f.initial.ListenPort != 0 || !f.initial.ReplacePeers {
		t.Fatalf("unexpected WireGuard configuration: %+v", f.initial)
	}
	peer := f.initial.Peers[0]
	if peer.PersistentKeepaliveInterval == nil || *peer.PersistentKeepaliveInterval != 5*time.Second || peer.Endpoint.String() != c.Endpoint.String() {
		t.Fatal("missing peer endpoint or keepalive")
	}
	if f.routes[c.AllowedIPs[0]].src != c.Address.Addr() {
		t.Fatal("route does not prefer the tunnel source address")
	}
	if !strings.HasPrefix(f.links[c.Name].alias, "newt:test-site:") {
		t.Fatal("missing ownership marker")
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if len(f.links) != 1 || f.links["wg0"].alias != "existing VPN" || len(f.routes) != 1 || f.callCounts["remove"] != 1 || !f.closed {
		t.Fatal("cleanup altered foreign state or was not idempotent")
	}
	if err := d.SetAllowedIPs(c.AllowedIPs); err == nil {
		t.Fatal("update after close succeeded")
	}
}

func TestOpenRollsBackAtEverySetupStage(t *testing.T) {
	for _, stage := range []string{"create", "configure", "address", "up", "addRoute"} {
		t.Run(stage, func(t *testing.T) {
			f := newFake()
			f.failures[stage] = 1
			if d, err := open(testConfig(), f); !errors.Is(err, injectedError) || d != nil {
				t.Fatalf("expected setup failure, got device=%v err=%v", d, err)
			}
			if len(f.links) != 1 || len(f.routes) != 1 || !f.closed {
				t.Fatal("failed setup leaked resources or changed foreign routes")
			}
		})
	}
	t.Run("second route", func(t *testing.T) {
		f := newFake()
		f.failures["addRoute"] = 2
		c := testConfig()
		c.AllowedIPs = append(c.AllowedIPs, netip.MustParsePrefix("10.30.0.0/24"))
		if _, err := open(c, f); !errors.Is(err, injectedError) {
			t.Fatal(err)
		}
		if len(f.routes) != 1 || len(f.links) != 1 {
			t.Fatal("earlier successful route not cleaned up")
		}
	})
}

func TestOpenRecoversCreatedLinkIndexForSetupAndRollback(t *testing.T) {
	for _, failure := range []string{"", "configure", "lookup"} {
		name := failure
		if name == "" {
			name = "success"
		}
		t.Run(name, func(t *testing.T) {
			f := newFake()
			f.createWithoutIndex = true
			if failure == "lookup" {
				// Lose the initial lookup after creation; rollback must retry
				// ownership validation and recover the index using our marker.
				f.failures["lookup"] = 2
			} else if failure != "" {
				f.failures[failure] = 1
			}
			d, err := open(testConfig(), f)
			if failure == "" {
				if err != nil {
					t.Fatal(err)
				}
				if d.link.index != 10 || f.routes[testConfig().AllowedIPs[0]].owner != 10 {
					t.Fatal("created interface index was not recovered before setup")
				}
				if err := d.Close(); err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, injectedError) || d != nil {
				t.Fatalf("expected injected failure, got device=%v error=%v", d, err)
			}
			if len(f.links) != 1 || f.links["wg0"].alias != "existing VPN" || len(f.routes) != 1 || !f.closed {
				t.Fatal("rollback leaked the created link or modified foreign state")
			}
		})
	}
}

func TestExistingInterfaceAndRoutesAreNeverReplaced(t *testing.T) {
	t.Run("interface", func(t *testing.T) {
		f := newFake()
		c := testConfig()
		c.Name = "wg0"
		if _, err := open(c, f); err == nil || !strings.Contains(err.Error(), "already exists") {
			t.Fatalf("expected refusal, got %v", err)
		}
		if len(f.links) != 1 || f.callCounts["create"] != 0 || f.callCounts["remove"] != 0 || !f.closed {
			t.Fatal("existing interface touched")
		}
	})
	t.Run("route", func(t *testing.T) {
		f := newFake()
		c := testConfig()
		c.AllowedIPs = append(c.AllowedIPs, netip.MustParsePrefix("192.168.1.0/24"))
		if _, err := open(c, f); err == nil {
			t.Fatal("existing route accepted")
		}
		if len(f.links) != 1 || len(f.routes) != 1 || f.routes[c.AllowedIPs[1]].owner != 2 {
			t.Fatal("existing route changed")
		}
	})
}

func TestSetAllowedIPsRollback(t *testing.T) {
	for _, stage := range []string{"addRoute", "configure", "delRoute"} {
		t.Run(stage, func(t *testing.T) {
			f := newFake()
			c := testConfig()
			c.AllowedIPs = append(c.AllowedIPs, netip.MustParsePrefix("10.20.0.0/24"))
			d, err := open(c, f)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = d.Close() })
			beforeRoutes := make(map[netip.Prefix]fakeRoute)
			for k, v := range f.routes {
				beforeRoutes[k] = v
			}
			// Fail after some work has succeeded, including restoration of a
			// deleted old route and removal of a newly added route.
			offset := 2
			if stage == "configure" {
				offset = 1
			}
			f.failures[stage] = f.callCounts[stage] + offset
			err = d.SetAllowedIPs([]netip.Prefix{netip.MustParsePrefix("10.30.0.0/24"), netip.MustParsePrefix("10.40.0.0/24")})
			if !errors.Is(err, injectedError) {
				t.Fatalf("expected injected failure, got %v", err)
			}
			if !reflect.DeepEqual(f.routes, beforeRoutes) || !slices.Equal(f.allowed, c.AllowedIPs) || !slices.Equal(d.config.AllowedIPs, c.AllowedIPs) {
				t.Fatalf("rollback did not restore previous state: routes=%v allowed=%v", f.routes, f.allowed)
			}
		})
	}
}

func TestSetAllowedIPsDeduplicatesAndClears(t *testing.T) {
	f := newFake()
	d, err := open(testConfig(), f)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	if err := d.SetAllowedIPs([]netip.Prefix{netip.MustParsePrefix("10.30.0.1/24"), netip.MustParsePrefix("10.30.0.0/24")}); err != nil {
		t.Fatal(err)
	}
	if len(f.allowed) != 1 || f.allowed[0].String() != "10.30.0.0/24" || len(f.routes) != 2 {
		t.Fatal("prefixes not canonicalized or deduplicated")
	}
	if err := d.SetAllowedIPs(nil); err != nil {
		t.Fatal(err)
	}
	if len(f.allowed) != 0 || len(f.routes) != 1 {
		t.Fatal("old peer routes not removed")
	}
}

func TestRollbackErrorsAreReportedAndCloseStillCleansUp(t *testing.T) {
	f := newFake()
	d, err := open(testConfig(), f)
	if err != nil {
		t.Fatal(err)
	}
	f.failures["configure"] = f.callCounts["configure"] + 1
	f.failures["delRoute"] = f.callCounts["delRoute"] + 1
	err = d.SetAllowedIPs([]netip.Prefix{netip.MustParsePrefix("10.30.0.0/24")})
	if err == nil || !strings.Contains(err.Error(), "update WireGuard") || !strings.Contains(err.Error(), "roll back route") {
		t.Fatalf("rollback failure hidden: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if len(f.routes) != 1 || len(f.links) != 1 {
		t.Fatal("Close did not remove resources remaining after failed rollback")
	}
}

func TestCloseAfterExternalRemoval(t *testing.T) {
	f := newFake()
	d, err := open(testConfig(), f)
	if err != nil {
		t.Fatal(err)
	}
	delete(f.links, testConfig().Name)
	if err := d.Close(); err != nil || !f.closed || f.callCounts["remove"] != 0 {
		t.Fatalf("close after external removal failed: %v", err)
	}
}

func TestRejectedUpdateDoesNotChangeRoutes(t *testing.T) {
	f := newFake()
	c := testConfig()
	d, err := open(c, f)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	configureCalls := f.callCounts["configure"]
	if err := d.SetAllowedIPs([]netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}); err == nil {
		t.Fatal("control-plane route was accepted")
	}
	if f.callCounts["configure"] != configureCalls || len(f.routes) != 2 || !slices.Equal(f.allowed, c.AllowedIPs) {
		t.Fatal("rejected route changed active connection")
	}
}

func TestCloseRefusesChangedOwnership(t *testing.T) {
	for _, field := range []string{"index", "alias", "kind", "name"} {
		t.Run(field, func(t *testing.T) {
			f := newFake()
			c := testConfig()
			d, err := open(c, f)
			if err != nil {
				t.Fatal(err)
			}
			changed := f.links[c.Name]
			switch field {
			case "index":
				changed.index++
			case "alias":
				changed.alias = "someone else"
			case "kind":
				changed.kind = "dummy"
			case "name":
				changed.name = "renamed"
			}
			f.links[c.Name] = changed
			if err := d.SetAllowedIPs(c.AllowedIPs); err == nil {
				t.Fatal("update accepted changed ownership")
			}
			if err := d.Close(); err == nil || f.callCounts["remove"] != 0 || !f.closed {
				t.Fatal("close failed to preserve replacement interface or release control client")
			}
		})
	}
}

func TestValidationRejectsUnsafeRoutesBeforeMutation(t *testing.T) {
	tests := map[string]func(*Config){
		"name":                 func(c *Config) { c.Name = "too-long-interface" },
		"owner NUL":            func(c *Config) { c.Owner = "test\x00site" },
		"address":              func(c *Config) { c.Address = netip.MustParsePrefix("100.90.0.0/24") },
		"ipv6 address":         func(c *Config) { c.Address = netip.MustParsePrefix("fd00::2/128") },
		"zero key":             func(c *Config) { c.PrivateKey = wgtypes.Key{} },
		"endpoint":             func(c *Config) { c.Endpoint = nil },
		"unspecified endpoint": func(c *Config) { c.Endpoint.IP = net.ParseIP("0.0.0.0") },
		"multicast endpoint":   func(c *Config) { c.Endpoint.IP = net.ParseIP("224.0.0.1") },
		"mtu":                  func(c *Config) { c.MTU = 1 },
		"default":              func(c *Config) { c.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")} },
		"outer endpoint":       func(c *Config) { c.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")} },
		"control endpoint":     func(c *Config) { c.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")} },
		"local subnet":         func(c *Config) { c.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("100.90.0.0/24")} },
		"local host":           func(c *Config) { c.AllowedIPs = []netip.Prefix{c.Address} },
		"ipv6 route":           func(c *Config) { c.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("fd00::/64")} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			f := newFake()
			c := testConfig()
			mutate(&c)
			if _, err := open(c, f); err == nil {
				t.Fatal("unsafe configuration accepted")
			}
			if f.callCounts["create"] != 0 || !f.closed {
				t.Fatal("validation mutated networking or leaked client")
			}
		})
	}
	t.Run("IPv6 outer endpoint", func(t *testing.T) {
		f := newFake()
		c := testConfig()
		c.Endpoint.IP = net.ParseIP("2001:db8::1")
		d, err := open(c, f)
		if err != nil {
			t.Fatal(err)
		}
		_ = d.Close()
	})
}

func TestInterfaceNamesMatchLinuxValidation(t *testing.T) {
	for _, name := range []string{"newt@wg", "newt.wg", "newt-wg", "newt_wg", "nüwt", "123456789012345"} {
		t.Run("valid "+name, func(t *testing.T) {
			c := testConfig()
			c.Name = name
			if err := validate(c); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, name := range []string{"", ".", "..", "newt:wg", "newt/wg", "newt\x00wg", "newt wg", "newt\twg", "newt\nwg", "1234567890123456", strings.Repeat("é", 8)} {
		t.Run("invalid "+name, func(t *testing.T) {
			c := testConfig()
			c.Name = name
			if err := validate(c); err == nil {
				t.Fatal("invalid Linux interface name accepted")
			}
		})
	}
}
