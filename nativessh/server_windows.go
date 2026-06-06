//go:build windows

package nativessh

import (
	"errors"
	"log"
	"net"
	"sync"

	"golang.org/x/crypto/ssh"
)

// CredentialStore is a stub on Windows. Native SSH is not supported on Windows.
type CredentialStore struct {
	mu         sync.RWMutex
	principals map[string]map[string]struct{}
}

// NewCredentialStore returns an empty CredentialStore stub.
// Native SSH is not supported on Windows; a warning is logged.
func NewCredentialStore() *CredentialStore {
	log.Println("WARNING: native SSH is not supported on Windows and will be disabled")
	return &CredentialStore{
		principals: make(map[string]map[string]struct{}),
	}
}

// SetCAKey is a no-op stub on Windows.
func (s *CredentialStore) SetCAKey(_ string) error {
	return errors.New("native SSH not supported on Windows")
}

// AddPrincipals is a no-op stub on Windows.
func (s *CredentialStore) AddPrincipals(_, _ string) {}

// get returns nil CA key and empty principals on Windows.
func (s *CredentialStore) get(_ string) (ssh.PublicKey, map[string]struct{}) {
	return nil, nil
}

// ServerConfig holds configuration for the native SSH server (stub on Windows).
type ServerConfig struct {
	ListenAddr  string
	Credentials *CredentialStore
}

// Server is a stub on Windows.
type Server struct{}

// NewServer returns a stub Server and logs a warning.
func NewServer(cfg ServerConfig) *Server {
	return &Server{}
}

// ListenAndServe always returns an error on Windows.
func (s *Server) ListenAndServe() error {
	return errors.New("native SSH not supported on Windows")
}

// Serve always returns an error on Windows.
func (s *Server) Serve(_ net.Listener) error {
	return errors.New("native SSH not supported on Windows")
}
