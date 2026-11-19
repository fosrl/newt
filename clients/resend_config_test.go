package clients

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	gws "github.com/gorilla/websocket"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/fosrl/newt/internal/telemetry"
	"github.com/fosrl/newt/websocket"
)

// newConnectedService returns a WireGuardService whose websocket client is
// connected to a fake server. Every newt/wg/get-config chain ID the server
// receives is delivered on the returned channel.
func newConnectedService(t *testing.T) (*WireGuardService, <-chan string) {
	t.Helper()

	if _, err := telemetry.Init(context.Background(), telemetry.Config{ServiceName: "test"}); err != nil {
		t.Fatalf("telemetry.Init: %v", err)
	}

	got := make(chan string, 64)
	connected := make(chan struct{}, 1)
	upgrader := gws.Upgrader{}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/auth/newt/get-token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success":true,"data":{"token":"tok","serverVersion":"1.0.0"}}`))
	})
	mux.HandleFunc("/api/v1/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		connected <- struct{}{}
		for {
			var msg websocket.WSMessage
			if err := conn.ReadJSON(&msg); err != nil {
				return
			}
			if msg.Type != "newt/wg/get-config" {
				continue
			}
			data, _ := msg.Data.(map[string]interface{})
			id, _ := data["chainId"].(string)
			got <- id
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	client, err := websocket.NewClient("newt", "id", "secret", srv.URL, time.Minute,
		websocket.WithBaseURL(srv.URL),
		websocket.WithConfigFile(filepath.Join(t.TempDir(), "config.json")),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	select {
	case <-connected:
	case <-time.After(10 * time.Second):
		t.Fatal("websocket client never connected")
	}

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	s := &WireGuardService{client: client, key: key, interfaceName: "wg-test", Port: 51820}
	return s, got
}

func TestResendPendingConfigReusesChainID(t *testing.T) {
	s, got := newConnectedService(t)

	// Request config, then simulate SendMessageInterval giving up on a
	// half-open socket: the sender is stopped but the chain ID stays pending.
	s.LoadRemoteConfig()
	first := <-got
	s.stopGetConfig()
	s.stopGetConfig = nil
	if first == "" || s.pendingConfigChainId != first {
		t.Fatalf("unexpected pending chain ID %q (sent %q)", s.pendingConfigChainId, first)
	}
	drain(got)

	s.ResendPendingConfig()
	select {
	case id := <-got:
		if id != first {
			t.Fatalf("resent chain ID = %q, want pending %q", id, first)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("pending get-config was not re-sent after reconnect")
	}
	s.stopGetConfig()
}

func TestResendPendingConfigNoopWhenNothingPending(t *testing.T) {
	s, got := newConnectedService(t)

	s.ResendPendingConfig()
	select {
	case id := <-got:
		t.Fatalf("unexpected get-config (chainId=%q) with nothing pending", id)
	case <-time.After(500 * time.Millisecond):
	}
	if s.stopGetConfig != nil {
		t.Fatal("no sender should have been started")
	}
}

func TestResendPendingConfigStopsAfterResponse(t *testing.T) {
	s, got := newConnectedService(t)

	s.LoadRemoteConfig()
	id := <-got
	// handleConfig consumes the pending chain ID (it then fails to build the
	// interface in this bare service, which is fine for this check).
	msg := websocket.WSMessage{Type: "newt/wg/receive-config", Data: map[string]interface{}{"chainId": id}}
	s.handleConfig(msg)
	if s.pendingConfigChainId != "" {
		t.Fatalf("pending chain ID not consumed: %q", s.pendingConfigChainId)
	}
	drain(got)

	s.ResendPendingConfig()
	select {
	case <-got:
		t.Fatal("config re-requested after it was already received")
	case <-time.After(500 * time.Millisecond):
	}
}

func drain(ch <-chan string) {
	for {
		select {
		case <-ch:
		case <-time.After(100 * time.Millisecond):
			return
		}
	}
}
