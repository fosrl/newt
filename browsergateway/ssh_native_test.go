//go:build !windows

package browsergateway

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/user"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/fosrl/newt/nativessh"
	"golang.org/x/crypto/ssh"
)

func decodeSessionBatch(t *testing.T, data string) []nativessh.SessionRecord {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zlib.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	jsonData, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	var records []nativessh.SessionRecord
	if err := json.Unmarshal(jsonData, &records); err != nil {
		t.Fatal(err)
	}
	return records
}

// TestNativeSSHBrowserSessionIsLogged signs in to a native browser SSH
// session with a CA-signed certificate and checks the session log carries
// the browser transport, the proxied source address and the auth details.
// Spawning the shell as a user needs root; when it can, the test also checks
// a typed command is recorded.
func TestNativeSSHBrowserSessionIsLogged(t *testing.T) {
	u, err := user.Current()
	if err != nil {
		t.Skipf("no current user: %v", err)
	}

	_, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	caSigner, _ := ssh.NewSignerFromKey(caPriv)
	userPub, userPriv, _ := ed25519.GenerateKey(rand.Reader)
	userSSHPub, _ := ssh.NewPublicKey(userPub)

	cert := &ssh.Certificate{
		Key:             userSSHPub,
		Serial:          1,
		CertType:        ssh.UserCert,
		KeyId:           u.Username + "@my-resource",
		ValidPrincipals: []string{u.Username, "my-resource"},
		ValidBefore:     ssh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatal(err)
	}
	keyBlock, err := ssh.MarshalPrivateKey(userPriv, "")
	if err != nil {
		t.Fatal(err)
	}

	store := nativessh.NewCredentialStore()
	if err := store.SetCAKey(string(ssh.MarshalAuthorizedKey(caSigner.PublicKey()))); err != nil {
		t.Fatal(err)
	}
	store.AddPrincipals(u.Username, "my-resource")

	records := make(chan []nativessh.SessionRecord, 10)
	sessionLog := nativessh.NewSessionLogger(func(data string) error {
		records <- decodeSessionBatch(t, data)
		return nil
	})

	g := New(Config{SSHCredentials: store, SessionLog: sessionLog})
	g.SetTargets([]Target{{ID: 1, Type: "ssh", AuthToken: "tok"}})
	mux := http.NewServeMux()
	g.RegisterHandlers(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/gateway/ssh?" + url.Values{
		"authToken": {"tok"},
		"username":  {u.Username},
	}.Encode()
	ws, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		Subprotocols: []string{"ssh"},
		HTTPHeader:   http.Header{"X-Real-Ip": {"203.0.113.7"}},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	send := func(msg sshClientMsg) {
		b, _ := json.Marshal(msg)
		if err := ws.Write(ctx, websocket.MessageText, b); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	send(sshClientMsg{
		Type:        "auth",
		PrivateKey:  string(pem.EncodeToMemory(keyBlock)),
		Certificate: string(ssh.MarshalAuthorizedKey(cert)),
	})

	// The first frame is either shell output or an error if the shell could
	// not be spawned.
	_, first, err := ws.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var reply sshServerMsg
	_ = json.Unmarshal(first, &reply)
	if reply.Error == "Authentication failed" {
		t.Fatal("certificate authentication failed")
	}
	shellStarted := reply.Type == "data"
	if shellStarted {
		send(sshClientMsg{Type: "data", Data: "echo browser\r"})
		send(sshClientMsg{Type: "data", Data: "exit\r"})
		for {
			if _, _, err := ws.Read(ctx); err != nil {
				break
			}
		}
	}
	_ = ws.CloseNow()

	// Give the handler a moment to notice the disconnect and end the session.
	time.Sleep(200 * time.Millisecond)
	sessionLog.Close()

	var got []nativessh.SessionRecord
	for len(records) > 0 {
		got = append(got, <-records...)
	}
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1: %+v", len(got), got)
	}
	rec := got[0]
	if rec.Transport != nativessh.TransportBrowser || rec.SourceAddr != "203.0.113.7" || rec.Username != u.Username {
		t.Fatalf("bad session info: %+v", rec)
	}
	if rec.AuthMethod != nativessh.AuthMethodCertificate || rec.CertKeyID != cert.KeyId || len(rec.CertPrincipals) != 2 {
		t.Fatalf("bad auth info: %+v", rec)
	}
	if rec.EndedAt == nil {
		t.Fatal("session not ended")
	}
	if shellStarted {
		if len(rec.Commands) == 0 || rec.Commands[0].Command != "echo browser" || rec.Commands[0].Channel != nativessh.ChannelShell {
			t.Fatalf("bad commands: %+v", rec.Commands)
		}
	} else {
		t.Log("shell could not be spawned (needs root); skipped command check")
	}
}
