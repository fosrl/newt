package newt

import (
	"context"
	"testing"
	"time"

	"github.com/fosrl/newt/internal/telemetry"
	"github.com/fosrl/newt/websocket"
)

func TestRegistrationRetryDelay(t *testing.T) {
	cases := []struct {
		failures int
		want     time.Duration
	}{
		{1, 2 * time.Second},
		{2, 4 * time.Second},
		{3, 8 * time.Second},
		{5, 32 * time.Second},
		{6, 60 * time.Second},
		{100, 60 * time.Second},
	}
	for _, c := range cases {
		if got := registrationRetryDelay(c.failures); got != c.want {
			t.Errorf("registrationRetryDelay(%d) = %v, want %v", c.failures, got, c.want)
		}
	}
}

// A failed endpoint lookup used to return after the TUN and WireGuard device were
// built, without anything asking for registration again (fosrl/newt#442).
func TestHandleConnectRetriesRegistrationWhenEndpointDoesNotResolve(t *testing.T) {
	// handleConnect records the registration result, which needs the instruments.
	if err := telemetry.EnsureInstruments(); err != nil {
		t.Fatalf("telemetry.EnsureInstruments: %v", err)
	}

	n := &Newt{config: Config{MTU: 1280, DNS: "9.9.9.9"}}
	t.Cleanup(func() {
		if n.stopFunc != nil {
			n.stopFunc()
		}
		n.closeWgTunnel()
	})

	n.handleConnect(context.Background(), websocket.WSMessage{
		Type: "newt/wg/connect",
		Data: map[string]interface{}{
			"endpoint":  "gerbil.newt-test.invalid:51820",
			"publicKey": "Wz4zB0mLFbGDuc5MqPkCqQeD1vWvmYx8PG6fK3pS5ws=",
			"serverIP":  "100.89.128.1",
			"tunnelIP":  "100.89.128.4",
		},
	})

	if n.dev != nil || n.tun != nil {
		t.Fatal("a failed endpoint lookup left a WireGuard device behind")
	}
	if n.stopFunc == nil {
		t.Fatal("a failed endpoint lookup did not schedule a registration retry")
	}
	if n.resolveFailures != 1 {
		t.Fatalf("resolveFailures = %d, want 1", n.resolveFailures)
	}
}
