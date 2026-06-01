package nativessh

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

// CredentialStore holds in-memory SSH credentials that can be updated at runtime.
// It is safe for concurrent use.
type CredentialStore struct {
	mu         sync.RWMutex
	caKey      ssh.PublicKey
	principals map[string]map[string]struct{} // username -> set of allowed principals
}

// connMetaWithUser wraps ConnMetadata while overriding User() for cert checks.
type connMetaWithUser struct {
	ssh.ConnMetadata
	user string
}

func (m connMetaWithUser) User() string { return m.user }

// NewCredentialStore returns an empty, ready-to-use CredentialStore.
func NewCredentialStore() *CredentialStore {
	return &CredentialStore{
		principals: make(map[string]map[string]struct{}),
	}
}

// SetCAKey parses and stores the CA public key from authorized_keys-format data.
func (s *CredentialStore) SetCAKey(authorizedKeyData string) error {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKeyData))
	if err != nil {
		return fmt.Errorf("parse CA key: %w", err)
	}
	s.mu.Lock()
	s.caKey = key
	s.mu.Unlock()
	return nil
}

// AddPrincipals records username and niceId as allowed principals for username.
// Both values are stored; either can appear in the certificate's ValidPrincipals
// field to satisfy the standard cert-auth principal check.
func (s *CredentialStore) AddPrincipals(username, niceId string) {
	username = strings.TrimSpace(username)
	niceId = strings.TrimSpace(niceId)
	if username == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.principals[username] == nil {
		s.principals[username] = make(map[string]struct{})
	}
	s.principals[username][username] = struct{}{}
	if niceId != "" {
		s.principals[username][niceId] = struct{}{}
	}
}

// get returns the CA key and the principal set for username under a read lock.
func (s *CredentialStore) get(username string) (ssh.PublicKey, map[string]struct{}) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.caKey, s.principals[username]
}

// ServerConfig holds configuration for the native SSH server.
type ServerConfig struct {
	// ListenAddr is the TCP address to listen on. Defaults to ":2222".
	ListenAddr string
	// Credentials provides in-memory CA key and per-user principals.
	// Updates to the store are reflected immediately for new connections.
	// If nil or the store has no CA key set, all connections are rejected.
	Credentials *CredentialStore
}

// Server is a simple SSH server that authenticates clients via SSH certificate
// auth only. Certificates must be signed by the configured CA and the
// connecting username must appear in both the certificate's principal list and
// the local principals file.
type Server struct {
	cfg ServerConfig
}

// NewServer creates a new Server. The ListenAddr defaults to ":2222" when empty.
func NewServer(cfg ServerConfig) *Server {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":2222"
	}
	return &Server{cfg: cfg}
}

// buildSSHConfig builds the ssh.ServerConfig with multi-method authentication:
//  1. Public key: host ~/.ssh/authorized_keys, then CA certificate.
//  2. Password: system PAM stack (Linux only).
func (s *Server) buildSSHConfig() (*ssh.ServerConfig, error) {
	hostSigner, err := generateHostKey()
	if err != nil {
		return nil, fmt.Errorf("host key: %w", err)
	}
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: makePublicKeyCallback(s.cfg.Credentials),
		PasswordCallback:  makePasswordCallback(),
	}
	cfg.AddHostKey(hostSigner)
	return cfg, nil
}

// Serve accepts connections on ln and handles them. It returns when ln is
// closed or a non-temporary Accept error occurs.
func (s *Server) Serve(ln net.Listener) error {
	sshCfg, err := s.buildSSHConfig()
	if err != nil {
		return err
	}
	log.Printf("nativessh: server listening on %s", ln.Addr())
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handleConn(conn, sshCfg)
	}
}

// ListenAndServe starts the SSH server on the host network and blocks until
// the listener is closed.
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.cfg.ListenAddr, err)
	}
	defer ln.Close()
	return s.Serve(ln)
}

func (s *Server) handleConn(conn net.Conn, cfg *ssh.ServerConfig) {
	defer conn.Close()
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		log.Printf("nativessh: handshake failed from %s: %v", conn.RemoteAddr(), err)
		return
	}
	defer sshConn.Close()
	log.Printf("nativessh: connection from %s user=%s", conn.RemoteAddr(), sshConn.User())

	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			_ = newChan.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		ch, requests, err := newChan.Accept()
		if err != nil {
			log.Printf("nativessh: channel accept error: %v", err)
			return
		}
		go s.handleSession(ch, requests, sshConn.User())
	}
}

// handleSession drives a single SSH session channel. It waits for a pty-req
// followed by a shell request and then bridges the PTY to the channel.
func (s *Server) handleSession(ch ssh.Channel, requests <-chan *ssh.Request, username string) {
	defer ch.Close()

	var (
		sess    *PTYSession
		started bool
	)

	for req := range requests {
		switch req.Type {
		case "pty-req":
			var err error
			if sess == nil {
				sess, err = NewPTYSessionAs(username)
				if err != nil {
					log.Printf("nativessh: PTY start error: %v", err)
					if req.WantReply {
						_ = req.Reply(false, nil)
					}
					return
				}
			}
			cols, rows := parsePTYReq(req.Payload)
			_ = sess.Resize(cols, rows)
			if req.WantReply {
				_ = req.Reply(true, nil)
			}

		case "shell":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			if started || sess == nil {
				continue
			}
			started = true
			// PTY output → SSH channel.
			go func() {
				_, _ = io.Copy(ch, sess)
				// Notify the client of the shell's exit status so it can
				// disconnect cleanly instead of requiring a manual disconnect.
				exitCode := sess.ExitCode()
				exitStatusPayload := ssh.Marshal(struct{ Status uint32 }{uint32(exitCode)})
				_, _ = ch.SendRequest("exit-status", false, exitStatusPayload)
				_ = ch.CloseWrite()
				sess.Close() //nolint:errcheck
				// Close the channel so the ssh library closes the requests
				// channel, which unblocks the for-range loop in handleSession
				// and allows the deferred ch.Close() to run. Without this,
				// handleSession blocks forever waiting for requests to drain.
				_ = ch.Close()
			}()
			// SSH channel input → PTY stdin.
			go func() {
				_, _ = io.Copy(sess, ch)
			}()

		case "window-change":
			if sess != nil {
				cols, rows := parseWindowChange(req.Payload)
				_ = sess.Resize(cols, rows)
			}
			if req.WantReply {
				_ = req.Reply(true, nil)
			}

		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}

	if sess != nil && !started {
		sess.Close() //nolint:errcheck
	}
}

// makePublicKeyCallback returns a PublicKeyCallback that tries, in order:
//  1. Host authorized_keys  – matches any key in the OS user's
//     ~/.ssh/authorized_keys file.
//  2. CA certificate        – validates an SSH certificate signed by the
//     configured CA and checks that the user appears in the principals map.
//
// store may be nil or empty; those paths are simply skipped.
func makePublicKeyCallback(store *CredentialStore) func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
	return func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		// 1. Host authorized_keys.
		if CheckAuthorizedKeys(meta.User(), key) {
			log.Printf("nativessh: authorized_keys auth for user %q", meta.User())
			return &ssh.Permissions{}, nil
		}

		// 2. CA certificate.
		if store != nil {
			caKey, userPrincipals := store.get(meta.User())
			if caKey != nil {
				checker := &ssh.CertChecker{
					IsUserAuthority: func(auth ssh.PublicKey) bool {
						return ssh.FingerprintSHA256(auth) == ssh.FingerprintSHA256(caKey)
					},
				}

				if len(userPrincipals) == 0 {
					return nil, fmt.Errorf("user %q not in allowed principals list", meta.User())
				}

				var lastErr error
				for principal := range userPrincipals {
					perms, err := checker.Authenticate(connMetaWithUser{ConnMetadata: meta, user: principal}, key)
					if err == nil {
						log.Printf("nativessh: CA cert auth for user %q principal=%q", meta.User(), principal)
						return perms, nil
					}
					lastErr = err
				}

				if lastErr != nil {
					log.Printf("nativessh: CA cert rejected for user %q: %v", meta.User(), lastErr)
				}
			}
		}

		return nil, fmt.Errorf("public key not authorized for user %q", meta.User())
	}
}

// makePasswordCallback returns a PasswordCallback that validates the supplied
// password via the host OS PAM stack.  On non-Linux platforms this always
// fails (see pam_other.go).
func makePasswordCallback() func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
	return func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		if err := VerifySystemPassword(meta.User(), string(password)); err != nil {
			// Return a generic message to the client; log the real reason.
			log.Printf("nativessh: password auth failed for user %q: %v", meta.User(), err)
			return nil, fmt.Errorf("permission denied")
		}
		log.Printf("nativessh: password auth for user %q", meta.User())
		return &ssh.Permissions{}, nil
	}
}

// generateHostKey generates a fresh ephemeral Ed25519 host key in memory.
// A new key is created on every server start; nothing is written to disk.
func generateHostKey() (ssh.Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate host key: %w", err)
	}
	log.Printf("nativessh: generated ephemeral Ed25519 host key")
	return ssh.NewSignerFromKey(priv)
}

// ptyRequestMsg mirrors the SSH wire format for pty-req (RFC 4254 §6.2).
type ptyRequestMsg struct {
	Term     string
	Columns  uint32
	Rows     uint32
	Width    uint32
	Height   uint32
	Modelist string
}

func parsePTYReq(payload []byte) (cols, rows uint16) {
	var req ptyRequestMsg
	if err := ssh.Unmarshal(payload, &req); err != nil {
		return 80, 24
	}
	return uint16(req.Columns), uint16(req.Rows)
}

// windowChangeMsg mirrors the SSH wire format for window-change (RFC 4254 §6.7).
type windowChangeMsg struct {
	Columns uint32
	Rows    uint32
	Width   uint32
	Height  uint32
}

func parseWindowChange(payload []byte) (cols, rows uint16) {
	var msg windowChangeMsg
	if err := ssh.Unmarshal(payload, &msg); err != nil {
		return 80, 24
	}
	return uint16(msg.Columns), uint16(msg.Rows)
}
