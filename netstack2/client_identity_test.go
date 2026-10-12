package netstack2

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestHTTPHandlerSetsRemoteHeaders(t *testing.T) {
	received := make(chan http.Header, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Clone()
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
	handler.ReplaceClientIdentities([]ClientIdentity{
		{IP: "100.90.128.5", UserID: "u1", Username: "alice", Email: "alice@example.com", Name: "Alice", Role: "Admin, Member"},
		{IP: "100.90.128.6", Name: "build-server", Role: "CI"},
	})
	rule := &SubnetRule{
		Protocol: "http",
		HTTPTargets: []HTTPTarget{
			{DestAddr: backendHost, DestPort: uint16(port), Scheme: backendURL.Scheme},
		},
	}

	send := func(remoteAddr string) http.Header {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "http://app.internal/", nil)
		req.RemoteAddr = remoteAddr
		// a client must not be able to spoof any of these
		req.Header.Set("Remote-User", "mallory")
		req.Header.Set("Remote-Role", "Admin")
		req = req.WithContext(context.WithValue(req.Context(), connCtxKey{}, rule))
		handler.handleRequest(httptest.NewRecorder(), req)
		return <-received
	}

	user := send("100.90.128.5:51234")
	for name, want := range map[string]string{
		"Remote-User-Id": "u1",
		"Remote-User":    "alice",
		"Remote-Email":   "alice@example.com",
		"Remote-Name":    "Alice",
		"Remote-Role":    "Admin, Member",
	} {
		if got := user.Get(name); got != want {
			t.Errorf("user client: %s = %q, want %q", name, got, want)
		}
	}

	machine := send("100.90.128.6:51234")
	for name, want := range map[string]string{
		"Remote-User-Id": "",
		"Remote-User":    "",
		"Remote-Email":   "",
		"Remote-Name":    "build-server",
		"Remote-Role":    "CI",
	} {
		if got := machine.Get(name); got != want {
			t.Errorf("machine client: %s = %q, want %q", name, got, want)
		}
	}

	unknown := send("100.90.128.7:51234")
	for _, name := range []string{"Remote-User", "Remote-Role"} {
		if got := unknown.Get(name); got != "" {
			t.Errorf("unknown client: %s = %q, want it stripped", name, got)
		}
	}

	// an incremental add overwrites a stale entry for a reused IP
	handler.AddClientIdentities([]ClientIdentity{{IP: "100.90.128.5", Name: "other-machine"}})
	reused := send("100.90.128.5:51234")
	if got := reused.Get("Remote-User"); got != "" {
		t.Errorf("reused IP: Remote-User = %q, want empty", got)
	}
	if got := reused.Get("Remote-Name"); got != "other-machine" {
		t.Errorf("reused IP: Remote-Name = %q, want %q", got, "other-machine")
	}
}
