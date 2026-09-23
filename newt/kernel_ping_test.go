package newt

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCanceledTunnelProbes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	probes := map[string]func() error{
		"kernel":   func() error { _, err := pingKernel(ctx, "newt-main", "192.0.2.1", time.Minute); return err },
		"native":   func() error { _, err := pingNativeContext(ctx, "192.0.2.1", time.Minute); return err },
		"netstack": func() error { _, err := pingContext(ctx, nil, "192.0.2.1", time.Minute); return err },
	}
	for name, probe := range probes {
		t.Run(name, func(t *testing.T) {
			if err := probe(); !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled probe returned %v", err)
			}
		})
	}
}

func TestReliablePingDoesNotRetryCanceledTunnel(t *testing.T) {
	calls := 0
	_, err := reliablePing(func(string, time.Duration) (time.Duration, error) {
		calls++
		return 0, context.Canceled
	}, "192.0.2.1", time.Second, 5)
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("got error %v after %d attempts", err, calls)
	}
}
