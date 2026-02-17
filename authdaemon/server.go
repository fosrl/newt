package authdaemon

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/fosrl/newt/logger"
)

type Config struct {
	// DisableHTTPS: when true, Run() does not start the HTTPS server (for embedded use inside Newt). Call ProcessConnection directly for connection events.
	DisableHTTPS       bool
	Port               int    // Listen port for the HTTPS server. Required when DisableHTTPS is false.
	PresharedKey       string // Required when DisableHTTPS is false; used for HTTP auth (Authorization: Bearer <key> or X-Preshared-Key: <key>).
	CACertPath         string // Where to write the CA cert (e.g. /etc/ssh/ca.pem).
	SSHDConfigPath     string // Path to sshd_config (e.g. /etc/ssh/sshd_config). Defaults to /etc/ssh/sshd_config when CACertPath is set.
	ReloadSSHCommand   string // Command to reload sshd after config change (e.g. "systemctl reload sshd"). Empty = no reload.
	PrincipalsFilePath string // Path to the principals data file (JSON: username -> array of principals). Empty = do not store principals.
}

type Server struct {
	cfg          Config
	addr         string
	presharedKey string
	mux          *http.ServeMux
	tlsCert      tls.Certificate
}

// generateTLSCert creates a self-signed certificate and key in memory (no disk).
func generateTLSCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "127.0.0.1"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshal key: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("x509 key pair: %w", err)
	}
	return cert, nil
}

// authMiddleware wraps next and requires a valid preshared key on every request.
// Accepts Authorization: Bearer <key> or X-Preshared-Key: <key>.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := ""
		if v := r.Header.Get("Authorization"); strings.HasPrefix(v, "Bearer ") {
			key = strings.TrimSpace(strings.TrimPrefix(v, "Bearer "))
		}
		if key == "" {
			key = strings.TrimSpace(r.Header.Get("X-Preshared-Key"))
		}
		if key == "" || subtle.ConstantTimeCompare([]byte(key), []byte(s.presharedKey)) != 1 {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// NewServer builds a new auth-daemon server from cfg. When DisableHTTPS is false, PresharedKey and Port are required.
func NewServer(cfg Config) (*Server, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("auth-daemon is only supported on Linux, not %s", runtime.GOOS)
	}
	if !cfg.DisableHTTPS {
		if cfg.PresharedKey == "" {
			return nil, fmt.Errorf("preshared key is required when HTTPS is enabled")
		}
		if cfg.Port <= 0 {
			return nil, fmt.Errorf("port must be positive when HTTPS is enabled")
		}
	}
	s := &Server{cfg: cfg}
	if !cfg.DisableHTTPS {
		cert, err := generateTLSCert()
		if err != nil {
			return nil, err
		}
		s.addr = fmt.Sprintf(":%d", cfg.Port)
		s.presharedKey = cfg.PresharedKey
		s.mux = http.NewServeMux()
		s.tlsCert = cert
		s.registerRoutes()
	}
	return s, nil
}

// Run starts the HTTPS server (unless DisableHTTPS) and blocks until ctx is cancelled or the server errors.
// When DisableHTTPS is true, Run() blocks on ctx only and does not listen; use ProcessConnection for connection events.
func (s *Server) Run(ctx context.Context) error {
	if s.cfg.DisableHTTPS {
		logger.Info("auth-daemon running (HTTPS disabled)")
		<-ctx.Done()
		s.cleanupPrincipalsFile()
		return nil
	}
	tcfg := &tls.Config{
		Certificates: []tls.Certificate{s.tlsCert},
		MinVersion:   tls.VersionTLS12,
	}
	handler := s.authMiddleware(s.mux)
	srv := &http.Server{
		Addr:              s.addr,
		Handler:           handler,
		TLSConfig:         tcfg,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Warn("auth-daemon shutdown: %v", err)
		}
	}()
	logger.Info("auth-daemon listening on https://127.0.0.1%s", s.addr)
	if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		return err
	}
	s.cleanupPrincipalsFile()
	return nil
}

func (s *Server) cleanupPrincipalsFile() {
	if s.cfg.PrincipalsFilePath != "" {
		if err := os.Remove(s.cfg.PrincipalsFilePath); err != nil && !os.IsNotExist(err) {
			logger.Warn("auth-daemon: remove principals file: %v", err)
		}
	}
}
