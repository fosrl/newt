package newt

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/fosrl/newt/exitnode"
	"github.com/fosrl/newt/internal/telemetry"
	"github.com/fosrl/newt/proxy"
	"github.com/fosrl/newt/websocket"
)

func TestMainProxyStartupFailurePolicy(t *testing.T) {
	if err := telemetry.EnsureInstruments(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		config Config
		fatal  bool
	}{
		{name: "userspace"},
		{name: "native TUN", config: Config{UseNativeMainInterface: true}},
		{name: "kernel", config: Config{UseKernelMainInterface: true}, fatal: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			occupied, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer occupied.Close()
			// Use an ordinary host socket in each case to trigger the same
			// deterministic listener failure without privileged tunnel setup.
			pm := proxy.NewProxyManagerNative("127.0.0.1")
			defer pm.Stop()
			if err := pm.AddTarget("udp", "127.0.0.1", occupied.LocalAddr().(*net.UDPAddr).Port, "127.0.0.1:1"); err != nil {
				t.Fatal(err)
			}
			n := &Newt{config: tc.config, pm: pm}
			if err := n.startMainProxy(); (err != nil) != tc.fatal {
				t.Fatalf("proxy startup returned %v; fatal for this backend = %v", err, tc.fatal)
			}
		})
	}
}

func TestCloseCancelsEndpointLookupDuringConnect(t *testing.T) {
	if err := telemetry.EnsureInstruments(); err != nil {
		t.Fatal(err)
	}
	n := &Newt{}
	n.shutdownCtx, n.shutdownCancel = context.WithCancel(context.Background())
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	previous := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			once.Do(func() { close(started) })
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-release:
				return nil, errors.New("lookup released by test cleanup")
			}
		},
	}
	setupDone := make(chan struct{})
	go func() {
		defer close(setupDone)
		n.handleConnect(context.Background(), websocket.WSMessage{Data: map[string]interface{}{"endpoint": "blocked.invalid:51820"}})
	}()
	t.Cleanup(func() {
		close(release)
		n.shutdownCancel()
		waitLifecycle(t, setupDone)
		net.DefaultResolver = previous
		n.Close()
	})
	waitLifecycle(t, started)
	shutdownDone := make(chan struct{})
	go func() {
		n.Close()
		close(shutdownDone)
	}()
	waitLifecycle(t, shutdownDone)
	waitLifecycle(t, setupDone)
}

type setupRoundTripper func(*http.Request) (*http.Response, error)

func (f setupRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestCloseCancelsExitNodeSelectionUnderLifecycleLock(t *testing.T) {
	for _, cancelCaller := range []bool{false, true} {
		name := "Close"
		if cancelCaller {
			name = "caller context"
		}
		t.Run(name, func(t *testing.T) {
			n := &Newt{}
			n.shutdownCtx, n.shutdownCancel = context.WithCancel(context.Background())
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			started := make(chan struct{})
			release := make(chan struct{})
			var once sync.Once
			previous := http.DefaultTransport
			http.DefaultTransport = setupRoundTripper(func(r *http.Request) (*http.Response, error) {
				once.Do(func() { close(started) })
				select {
				case <-r.Context().Done():
					return nil, r.Context().Err()
				case <-release:
					return nil, errors.New("probe released by test cleanup")
				}
			})
			var selectionErr error
			selectionDone := make(chan struct{})
			handler := n.withMainLifecycle(func(websocket.WSMessage) {
				_, selectionErr = n.pingExitNodes(ctx, []exitnode.ExitNode{{Endpoint: "first.invalid"}, {Endpoint: "second.invalid"}})
			})
			go func() {
				handler(websocket.WSMessage{})
				close(selectionDone)
			}()
			t.Cleanup(func() {
				close(release)
				cancel()
				n.shutdownCancel()
				waitLifecycle(t, selectionDone)
				http.DefaultTransport = previous
				n.Close()
			})
			waitLifecycle(t, started)
			shutdownDone := make(chan struct{})
			if cancelCaller {
				cancel()
				close(shutdownDone)
			} else {
				go func() {
					n.Close()
					close(shutdownDone)
				}()
			}
			select {
			case <-shutdownDone:
			case <-time.After(3 * time.Second):
				t.Fatal("shutdown waited for exit-node HTTP timeout")
			}
			waitLifecycle(t, selectionDone)
			if !errors.Is(selectionErr, context.Canceled) {
				t.Fatalf("selection returned %v; want canceled", selectionErr)
			}
		})
	}
}
