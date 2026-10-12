package netstack2

import (
	"net/http"
	"net/netip"
	"sync"

	"github.com/fosrl/newt/logger"
)

// Header names match the defaults that Badger sets for resources behind
// Traefik, so downstream services see the same identity headers regardless of
// whether a request came through Pangolin's public proxy or through newt.
const (
	remoteUserIDHeader = "Remote-User-Id"
	remoteUserHeader   = "Remote-User"
	remoteEmailHeader  = "Remote-Email"
	remoteNameHeader   = "Remote-Name"
	remoteRoleHeader   = "Remote-Role"
)

// ClientIdentity describes who is behind a client's tunnel IP. The server
// sends one per client that can reach an HTTP resource; the HTTP handler maps
// a request's source address to it to set the Remote-* headers. Machine
// clients have no user, so only Name and Role are set for them.
type ClientIdentity struct {
	IP       string `json:"ip"`
	UserID   string `json:"userId,omitempty"`
	Username string `json:"username,omitempty"`
	Email    string `json:"email,omitempty"`
	Name     string `json:"name,omitempty"`
	Role     string `json:"role,omitempty"`
}

// clientIdentityStore maps client tunnel IPs to their identity.
type clientIdentityStore struct {
	mu         sync.RWMutex
	identities map[netip.Addr]ClientIdentity
}

func parseIdentityAddr(id ClientIdentity) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(id.IP)
	if err != nil {
		logger.Warn("Ignoring client identity with invalid IP %q: %v", id.IP, err)
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

// replace swaps in the full set of identities, as sent on every full sync.
func (s *clientIdentityStore) replace(ids []ClientIdentity) {
	m := make(map[netip.Addr]ClientIdentity, len(ids))
	for _, id := range ids {
		if addr, ok := parseIdentityAddr(id); ok {
			m[addr] = id
		}
	}
	s.mu.Lock()
	s.identities = m
	s.mu.Unlock()
}

// upsert adds or overwrites the given identities, keeping all others.
func (s *clientIdentityStore) upsert(ids []ClientIdentity) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.identities == nil {
		s.identities = make(map[netip.Addr]ClientIdentity, len(ids))
	}
	for _, id := range ids {
		if addr, ok := parseIdentityAddr(id); ok {
			s.identities[addr] = id
		}
	}
}

// lookup returns the identity for the source address of a request
// ("ip:port", as found in http.Request.RemoteAddr).
func (s *clientIdentityStore) lookup(remoteAddr string) (ClientIdentity, bool) {
	addrPort, err := netip.ParseAddrPort(remoteAddr)
	if err != nil {
		return ClientIdentity{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.identities[addrPort.Addr().Unmap()]
	return id, ok
}

// setRemoteHeaders strips any client-supplied Remote-* headers from out, so a
// client can never spoof them, then sets them from the identity of the client
// the request came from, if known.
func (s *clientIdentityStore) setRemoteHeaders(out http.Header, remoteAddr string) {
	out.Del(remoteUserIDHeader)
	out.Del(remoteUserHeader)
	out.Del(remoteEmailHeader)
	out.Del(remoteNameHeader)
	out.Del(remoteRoleHeader)

	id, ok := s.lookup(remoteAddr)
	if !ok {
		return
	}

	set := func(name, value string) {
		if value != "" {
			out.Set(name, value)
		}
	}
	set(remoteUserIDHeader, id.UserID)
	set(remoteUserHeader, id.Username)
	set(remoteEmailHeader, id.Email)
	set(remoteNameHeader, id.Name)
	set(remoteRoleHeader, id.Role)
}
