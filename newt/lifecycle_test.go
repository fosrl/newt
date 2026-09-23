package newt

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fosrl/newt/websocket"
)

type lifecycleKernelDevice struct{ closes atomic.Int32 }

func (*lifecycleKernelDevice) SetAllowedIPs([]netip.Prefix) error { return nil }
func (d *lifecycleKernelDevice) Close() error {
	d.closes.Add(1)
	return nil
}

func waitLifecycle(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for tunnel lifecycle operation")
	}
}

func TestShutdownWaitsForInFlightSetup(t *testing.T) {
	n := &Newt{}
	n.shutdownCtx, n.shutdownCancel = context.WithCancel(context.Background())
	device := &lifecycleKernelDevice{}
	setupEntered := make(chan struct{})
	allowSetup := make(chan struct{})
	setupDone := make(chan struct{})
	handler := n.withMainLifecycle(func(websocket.WSMessage) {
		close(setupEntered)
		<-allowSetup
		// Simulate an OS creation call returning after shutdown was requested.
		n.kernelMain = device
	})
	go func() {
		handler(websocket.WSMessage{})
		close(setupDone)
	}()
	waitLifecycle(t, setupEntered)
	shutdownDone := make(chan struct{})
	go func() {
		n.Close()
		close(shutdownDone)
	}()
	waitLifecycle(t, n.shutdownCtx.Done())
	select {
	case <-shutdownDone:
		t.Fatal("shutdown returned while tunnel setup was still in flight")
	default:
	}
	close(allowSetup)
	waitLifecycle(t, setupDone)
	waitLifecycle(t, shutdownDone)
	if got := device.closes.Load(); got != 1 {
		t.Fatalf("device created during shutdown was closed %d times, want 1", got)
	}
	if n.kernelMain != nil {
		t.Fatal("kernel interface remained attached after shutdown")
	}
}

func TestStoppedNewtRejectsFurtherSetup(t *testing.T) {
	n := &Newt{}
	n.Close()
	n.Start(context.Background())
	var calls int
	n.withMainLifecycle(func(websocket.WSMessage) { calls++ })(websocket.WSMessage{})
	if calls != 0 {
		t.Fatal("message handler ran after shutdown")
	}
	// If this reaches the ordinary connection path, the missing transport and
	// invalid registration would trigger work. A stopped instance must ignore it.
	n.wgData.ServerIP = "sentinel"
	n.handleConnect(context.Background(), websocket.WSMessage{Data: map[string]interface{}{"serverIP": "192.0.2.1"}})
	if n.wgData.ServerIP != "sentinel" {
		t.Fatal("connect handler modified stopped tunnel state")
	}
	if err := n.updateRemoteExitNodeSubnets([]string{"192.0.2.0/24"}); err == nil {
		t.Fatal("subnet update accepted after shutdown")
	}
}

func TestConcurrentShutdownClosesKernelDeviceOnce(t *testing.T) {
	device := &lifecycleKernelDevice{}
	n := &Newt{
		kernelMain:            device,
		pingStopChan:          make(chan struct{}),
		pingWithRetryStopChan: make(chan struct{}),
	}
	var workers sync.WaitGroup
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			n.Close()
		}()
	}
	done := make(chan struct{})
	go func() {
		workers.Wait()
		close(done)
	}()
	waitLifecycle(t, done)
	if got := device.closes.Load(); got != 1 {
		t.Fatalf("concurrent shutdown closed the same kernel device %d times", got)
	}
}

func TestQueuedPingRecoveryDiscardsStoppedTunnel(t *testing.T) {
	for _, stopping := range []bool{false, true} {
		name := "replaced probe"
		if stopping {
			name = "shutdown"
		}
		t.Run(name, func(t *testing.T) {
			client, err := websocket.NewClient("newt", "test", "test", "https://example.invalid", time.Second,
				websocket.WithConfigFile(filepath.Join(t.TempDir(), "missing.json")))
			if err != nil {
				t.Fatal(err)
			}
			healthFile := filepath.Join(t.TempDir(), "health")
			if err := os.WriteFile(healthFile, []byte("ok"), 0o600); err != nil {
				t.Fatal(err)
			}
			n := &Newt{client: client, config: Config{HealthFile: healthFile}, pendingPingChainId: "unchanged"}
			n.wgData.PublicKey = "peer"
			t.Cleanup(n.Close)
			stop := make(chan struct{})
			n.lifecycleMu.Lock()
			done := n.schedulePingRecovery(stop, "peer")
			if stopping {
				n.stopping.Store(true)
			} else {
				close(stop)
			}
			n.lifecycleMu.Unlock()
			waitLifecycle(t, done)
			if n.pendingPingChainId != "unchanged" || n.stopFunc != nil {
				t.Fatal("stale ping recovery changed registration state")
			}
			if _, err := os.Stat(healthFile); err != nil {
				t.Fatalf("stale ping recovery removed health state: %v", err)
			}
		})
	}
}
