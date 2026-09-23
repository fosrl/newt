//go:build linux

package kernelwg

import (
	"errors"
	"slices"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestLinuxCreateExplicitlySetsAliasAfterLinkAdd(t *testing.T) {
	var current link
	var calls []string
	created, err := createLinuxLink("newt-wg", "newt:test:unique", 1280,
		func(l netlink.Link) error {
			calls = append(calls, "add")
			if l.Type() != "wireguard" || l.Attrs().MTU != 1280 || l.Attrs().Alias != "" {
				t.Fatalf("unexpected creation attributes: %+v", l)
			}
			// Match the real kernel: an alias in RTM_NEWLINK is ignored.
			l.Attrs().Index = 42
			current = link{name: l.Attrs().Name, kind: l.Type(), index: 42}
			return nil
		},
		func(string) (link, error) {
			calls = append(calls, "lookup")
			return current, nil
		},
		func(l netlink.Link, alias string) error {
			calls = append(calls, "alias")
			if l.Attrs().Index != current.index || l.Attrs().Name != current.name {
				t.Fatal("ownership marker assigned to an unverified interface")
			}
			current.alias = alias
			return nil
		})
	if err != nil || created != current || created.alias != "newt:test:unique" {
		t.Fatalf("create result=%+v actual=%+v error=%v", created, current, err)
	}
	if !slices.Equal(calls, []string{"add", "lookup", "alias"}) {
		t.Fatalf("creation did not explicitly set the marker after verifying the link: %v", calls)
	}
}

func TestLinuxCreateReturnsOwnedPartialLinkForRollback(t *testing.T) {
	for _, applyBeforeError := range []bool{false, true} {
		name := "setter rejected"
		if applyBeforeError {
			name = "setter partially applied"
		}
		t.Run(name, func(t *testing.T) {
			current := link{name: "newt-wg", kind: "wireguard", index: 42}
			created, err := createLinuxLink(current.name, "newt:test:unique", 1280,
				func(l netlink.Link) error { l.Attrs().Index = current.index; return nil },
				func(string) (link, error) { return current, nil },
				func(_ netlink.Link, alias string) error {
					if applyBeforeError {
						current.alias = alias
					}
					return injectedError
				})
			if !errors.Is(err, injectedError) || created != current {
				t.Fatalf("cannot roll back partially created link: result=%+v actual=%+v error=%v", created, current, err)
			}
			f := newFake()
			f.links[current.name] = current
			d := &Device{link: created, ops: f}
			if err := d.Close(); err != nil {
				t.Fatal(err)
			}
			if _, exists := f.links[current.name]; exists {
				t.Fatal("partial link was not rolled back")
			}
		})
	}
}

func TestLinuxCreateRefusesChangedOrUnknownIdentity(t *testing.T) {
	for _, field := range []string{"index", "alias", "kind", "unknown index"} {
		t.Run(field, func(t *testing.T) {
			current := link{name: "newt-wg", kind: "wireguard", index: 42}
			setCalled := false
			created, err := createLinuxLink(current.name, "newt:test:unique", 1280,
				func(l netlink.Link) error {
					l.Attrs().Index = current.index
					switch field {
					case "index":
						current.index++
					case "alias":
						current.alias = "another administrator"
					case "kind":
						current.kind = "dummy"
					case "unknown index":
						l.Attrs().Index = 0
					}
					return nil
				},
				func(string) (link, error) { return current, nil },
				func(netlink.Link, string) error { setCalled = true; return nil })
			if err == nil || setCalled {
				t.Fatalf("unexpectedly claimed changed interface: result=%+v error=%v", created, err)
			}
			f := newFake()
			f.links[current.name] = current
			d := &Device{link: created, ops: f}
			if err := d.Close(); err == nil || f.callCounts["remove"] != 0 {
				t.Fatal("cleanup adopted a foreign or unidentified interface")
			}
		})
	}
}
