//go:build !windows

package nativessh

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os/user"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// TestServerRecordsCertSessionAndExec connects with a CA-signed certificate
// and checks the session log carries the auth details and exec command.
func TestServerRecordsCertSessionAndExec(t *testing.T) {
	u, err := user.Current()
	if err != nil {
		t.Skipf("no current user: %v", err)
	}

	_, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	caSigner, _ := ssh.NewSignerFromKey(caPriv)
	userPub, userPriv, _ := ed25519.GenerateKey(rand.Reader)
	userSSHPub, _ := ssh.NewPublicKey(userPub)
	userSigner, _ := ssh.NewSignerFromKey(userPriv)

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
	certSigner, _ := ssh.NewCertSigner(cert, userSigner)

	store := NewCredentialStore()
	if err := store.SetCAKey(string(ssh.MarshalAuthorizedKey(caSigner.PublicKey()))); err != nil {
		t.Fatal(err)
	}
	store.AddPrincipals(u.Username, "my-resource")

	records := make(chan []SessionRecord, 10)
	sessionLog := NewSessionLogger(func(data string) error {
		records <- decodeBatch(t, data)
		return nil
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go NewServer(ServerConfig{Credentials: store, SessionLog: sessionLog}).Serve(ln) //nolint:errcheck

	client, err := ssh.Dial("tcp", ln.Addr().String(), &ssh.ClientConfig{
		User:            u.Username,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	// The command may fail to start without root (setgroups); it is
	// recorded either way.
	_ = sess.Run("echo hello")
	client.Close()

	// Give the server a moment to notice the disconnect and end the session.
	time.Sleep(200 * time.Millisecond)
	sessionLog.Close()

	var got []SessionRecord
	for len(records) > 0 {
		got = append(got, <-records...)
	}
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1: %+v", len(got), got)
	}
	rec := got[0]
	if rec.AuthMethod != AuthMethodCertificate || rec.CertKeyID != cert.KeyId || rec.Username != u.Username {
		t.Fatalf("bad auth info: %+v", rec)
	}
	if len(rec.CertPrincipals) != 2 || rec.CertPrincipals[1] != "my-resource" {
		t.Fatalf("bad principals: %v", rec.CertPrincipals)
	}
	if rec.EndedAt == nil {
		t.Fatal("session not ended")
	}
	if len(rec.Commands) != 1 || rec.Commands[0].Command != "echo hello" || rec.Commands[0].Channel != ChannelExec {
		t.Fatalf("bad commands: %+v", rec.Commands)
	}
}
