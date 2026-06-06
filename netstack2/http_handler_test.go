package netstack2

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gorilla/websocket"
)

func TestHTTPHandlerProxiesWebSocketUpgrade(t *testing.T) {
	upgrader := websocket.Upgrader{}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade failed: %v", err)
			return
		}
		defer conn.Close()

		messageType, payload, err := conn.ReadMessage()
		if err != nil {
			t.Errorf("read failed: %v", err)
			return
		}
		if err := conn.WriteMessage(messageType, append([]byte("echo:"), payload...)); err != nil {
			t.Errorf("write failed: %v", err)
		}
	}))
	defer backend.Close()

	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse backend URL: %v", err)
	}
	backendHost, backendPort, err := net.SplitHostPort(backendURL.Host)
	if err != nil {
		t.Fatalf("split backend host: %v", err)
	}
	port, err := net.LookupPort("tcp", backendPort)
	if err != nil {
		t.Fatalf("parse backend port: %v", err)
	}

	handler := NewHTTPHandler(nil, nil)
	rule := &SubnetRule{
		Protocol: "http",
		HTTPTargets: []HTTPTarget{
			{
				DestAddr: backendHost,
				DestPort: uint16(port),
				Scheme:   backendURL.Scheme,
			},
		},
	}

	frontend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), connCtxKey{}, rule)
		handler.handleRequest(w, r.WithContext(ctx))
	}))
	defer frontend.Close()

	frontendURL, err := url.Parse(frontend.URL)
	if err != nil {
		t.Fatalf("parse frontend URL: %v", err)
	}
	wsURL := url.URL{
		Scheme:   "ws",
		Host:     frontendURL.Host,
		Path:     "/socket",
		RawQuery: "token=test",
	}

	conn, _, err := websocket.DefaultDialer.Dial(wsURL.String(), nil)
	if err != nil {
		t.Fatalf("dial websocket through proxy: %v", err)
	}
	defer conn.Close()

	if err := conn.WriteMessage(websocket.TextMessage, []byte("hello")); err != nil {
		t.Fatalf("write websocket message: %v", err)
	}

	messageType, payload, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read websocket message: %v", err)
	}
	if messageType != websocket.TextMessage {
		t.Fatalf("message type = %d, want %d", messageType, websocket.TextMessage)
	}
	if got, want := string(payload), "echo:hello"; got != want {
		t.Fatalf("payload = %q, want %q", got, want)
	}
}
