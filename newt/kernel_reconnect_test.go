package newt

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestKernelReconnectDelaysFirstRequestAndCancelsInterval(t *testing.T) {
	n := &Newt{pendingPingChainId: "retry"}
	const delay = 40 * time.Millisecond
	started := make(chan time.Time, 1)
	var stops atomic.Int32
	n.lifecycleMu.Lock()
	before := time.Now()
	cancel, done := n.delayedKernelReconnect("retry", delay, func() func() {
		started <- time.Now()
		return func() { stops.Add(1) }
	})
	n.lifecycleMu.Unlock()
	defer cancel()
	waitLifecycle(t, done)
	select {
	case at := <-started:
		if at.Sub(before) < delay {
			t.Fatalf("first reconnect after %s, expected at least %s", at.Sub(before), delay)
		}
	default:
		t.Fatal("retry interval was not started")
	}
	cancel()
	cancel()
	if got := stops.Load(); got != 1 {
		t.Fatalf("interval canceled %d times, want exactly once", got)
	}
}

func TestKernelReconnectPendingDelayIsCancelableWithoutLifecycleLock(t *testing.T) {
	n := &Newt{pendingPingChainId: "retry"}
	var starts atomic.Int32
	n.lifecycleMu.Lock()
	cancel, done := n.delayedKernelReconnect("retry", time.Hour, func() func() {
		starts.Add(1)
		return nil
	})
	// Production cancellation is invoked while the lifecycle lock is held.
	// It must stop the timer immediately without waiting for that same lock.
	cancel()
	cancel()
	waitLifecycle(t, done)
	n.lifecycleMu.Unlock()
	if got := starts.Load(); got != 0 {
		t.Fatalf("canceled timer started %d reconnects", got)
	}
}

func TestKernelReconnectDropsObsoleteRetry(t *testing.T) {
	for _, reason := range []string{"chain replaced", "connected", "stopping", "shutdown canceled"} {
		t.Run(reason, func(t *testing.T) {
			n := &Newt{pendingPingChainId: "retry"}
			n.shutdownCtx, n.shutdownCancel = context.WithCancel(context.Background())
			defer n.shutdownCancel()
			var starts atomic.Int32
			n.lifecycleMu.Lock()
			cancel, done := n.delayedKernelReconnect("retry", time.Millisecond, func() func() {
				starts.Add(1)
				return nil
			})
			defer cancel()
			switch reason {
			case "chain replaced":
				n.pendingPingChainId = "newer-chain"
			case "connected":
				n.connected = true
			case "stopping":
				n.stopping.Store(true)
			case "shutdown canceled":
				n.shutdownCancel()
			}
			n.lifecycleMu.Unlock()
			waitLifecycle(t, done)
			if got := starts.Load(); got != 0 {
				t.Fatalf("%s still started %d reconnects", reason, got)
			}
		})
	}
}
