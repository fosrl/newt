package nativessh

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

const (
	// DefaultCAKeyPath is the path to the SSH CA public key used to validate
	// client certificates.
	DefaultCAKeyPath = "/tmp/newt/ssh_ca.pub"
	// DefaultPrincipalsPath is the path to a file listing allowed SSH
	// certificate principals, one per line.
	DefaultPrincipalsPath = "/tmp/newt/ssh_principals"
	// DefaultHostKeyPath is where the server's Ed25519 host key is persisted.
	// A new key is generated and saved here on first run.
	DefaultHostKeyPath = "/tmp/newt/ssh_host_key"
)

// ServerConfig holds configuration for the native SSH server.
type ServerConfig struct {
	// ListenAddr is the TCP address to listen on. Defaults to ":2222".
	ListenAddr string
	// CAKeyPath is the path to the CA public key file (authorized_keys format).
	// Defaults to DefaultCAKeyPath.
	CAKeyPath string
	// PrincipalsPath is the path to a file of allowed principals, one per line.
	// Defaults to DefaultPrincipalsPath.
	PrincipalsPath string
	// HostKeyPath is where the Ed25519 host private key is stored (PEM).
	// Defaults to DefaultHostKeyPath. Generated on first run if absent.
	HostKeyPath string
	// Shell is the shell executable to spawn. Defaults to /bin/sh.
	Shell string
}

// Server is a simple SSH server that authenticates clients via SSH certificate
// auth only. Certificates must be signed by the configured CA and the
// connecting username must appear in both the certificate's principal list and
// the local principals file.
type Server struct {
	cfg ServerConfig
}

// NewServer creates a new Server. Zero-value fields in cfg are replaced with
// defaults.
func NewServer(cfg ServerConfig) *Server {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":2222"
	}
	if cfg.CAKeyPath == "" {
		cfg.CAKeyPath = DefaultCAKeyPath
	}
	if cfg.PrincipalsPath == "" {
		cfg.PrincipalsPath = DefaultPrincipalsPath
	}
	if cfg.HostKeyPath == "" {
		cfg.HostKeyPath = DefaultHostKeyPath
	}
	if cfg.Shell == "" {
		cfg.Shell = "/bin/sh"
	}
	return &Server{cfg: cfg}
}

// ListenAndServe starts the SSH server and blocks until the listener is closed.
func (s *Server) ListenAndServe() error {
	caKey, err := loadCAPublicKey(s.cfg.CAKeyPath)
	if err != nil {
		return fmt.Errorf("load CA public key from %s: %w", s.cfg.CAKeyPath, err)
	}

	principals, err := loadPrincipals(s.cfg.PrincipalsPath)
	if err != nil {
		return fmt.Errorf("load principals from %s: %w", s.cfg.PrincipalsPath, err)
	}

	hostSigner, err := generateOrLoadHostKey(s.cfg.HostKeyPath)
	if err != nil {
		return fmt.Errorf("host key: %w", err)
	}

	sshCfg := &ssh.ServerConfig{
		PublicKeyCallback: makeCertAuthCallback(caKey, principals),
	}
	sshCfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.cfg.ListenAddr, err)
	}
	defer ln.Close()
	log.Printf("nativessh: server listening on %s", s.cfg.ListenAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("accept: %w", err)
		}
		go s.handleConn(conn, sshCfg)
	}
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
		go s.handleSession(ch, requests)
	}
}

// handleSession drives a single SSH session channel. It waits for a pty-req
// followed by a shell request and then bridges the PTY to the channel.
func (s *Server) handleSession(ch ssh.Channel, requests <-chan *ssh.Request) {
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
				sess, err = NewPTYSession(s.cfg.Shell)
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
				_ = ch.CloseWrite()
				sess.Close() //nolint:errcheck
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

// makeCertAuthCallback returns an ssh.PublicKeyCallback that accepts only
// SSH user certificates that are:
//  1. Signed by caKey.
//  2. Listing the connecting username in ValidPrincipals (standard cert auth).
//  3. Whose connecting username is also in the local allowedPrincipals set.
func makeCertAuthCallback(caKey ssh.PublicKey, allowedPrincipals map[string]struct{}) func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
	checker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return ssh.FingerprintSHA256(auth) == ssh.FingerprintSHA256(caKey)
		},
	}
	return func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		perms, err := checker.Authenticate(meta, key)
		if err != nil {
			return nil, err
		}
		if _, ok := allowedPrincipals[meta.User()]; !ok {
			return nil, fmt.Errorf("user %q not in allowed principals list", meta.User())
		}
		return perms, nil
	}
}

// generateOrLoadHostKey loads an Ed25519 host key from path, or generates and
// saves a new one if the file does not exist.
func generateOrLoadHostKey(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		return ssh.ParsePrivateKey(data)
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read host key %s: %w", path, err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate host key: %w", err)
	}
	pemBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, fmt.Errorf("marshal host key: %w", err)
	}
	pemData := pem.EncodeToMemory(pemBlock)
	if writeErr := os.WriteFile(path, pemData, 0600); writeErr != nil {
		log.Printf("nativessh: warning: could not persist host key to %s: %v", path, writeErr)
	}
	log.Printf("nativessh: generated new Ed25519 host key (saved to %s)", path)
	return ssh.NewSignerFromKey(priv)
}

func loadCAPublicKey(path string) (ssh.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func loadPrincipals(path string) (map[string]struct{}, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	principals := make(map[string]struct{})
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			principals[line] = struct{}{}
		}
	}
	return principals, scanner.Err()
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
