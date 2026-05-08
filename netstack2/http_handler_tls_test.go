package netstack2

import (
	"crypto/tls"
	"net"
	"testing"
)

// tlsConnStub is a minimal net.Conn that also exposes TLS state, matching
// *tls.Conn's ConnectionState used by net/http.Server.
type tlsConnStub struct {
	net.Conn
	state tls.ConnectionState
}

func (t *tlsConnStub) ConnectionState() tls.ConnectionState {
	return t.state
}

func TestHTTPConnCtxForwardsConnectionState(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	inner := &tlsConnStub{
		Conn:  c1,
		state: tls.ConnectionState{Version: tls.VersionTLS12, HandshakeComplete: true},
	}
	wrapped := &httpConnCtx{Conn: inner, rule: nil}

	got := wrapped.ConnectionState()
	if got.Version != tls.VersionTLS12 || !got.HandshakeComplete {
		t.Fatalf("ConnectionState = %+v, want TLS 1.2 and HandshakeComplete", got)
	}
}

func TestHTTPConnCtxConnectionStatePlainTCP(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	wrapped := &httpConnCtx{Conn: c1, rule: nil}
	got := wrapped.ConnectionState()
	if got.Version != 0 {
		t.Fatalf("expected zero ConnectionState for plain conn, got %+v", got)
	}
	_ = c2
}
