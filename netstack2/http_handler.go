/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package netstack2

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"

	"github.com/fosrl/newt/logger"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// ---------------------------------------------------------------------------
// Hardcoded test configuration
// ---------------------------------------------------------------------------

// testHTTPServeHTTPS controls whether the proxy presents HTTP or HTTPS to
// incoming connections. Flip to true and supply valid cert/key paths to test
// TLS termination.
const testHTTPServeHTTPS = false

// testHTTPCertFile / testHTTPKeyFile are paths to a self-signed certificate
// used when testHTTPServeHTTPS == true.
const testHTTPCertFile = "/tmp/test-cert.pem"
const testHTTPKeyFile = "/tmp/test-key.pem"

// testHTTPListenPort is the destination port the handler intercepts from the
// netstack TCP forwarder (e.g. 80 for plain HTTP, 443 for HTTPS termination).
const testHTTPListenPort uint16 = 80

// testHTTPTargets is the hardcoded list of downstream services used for
// testing. DestAddr / DestPort describe where the real HTTP(S) server lives;
// UseHTTPS controls whether the outbound leg uses TLS.
var testHTTPTargets = []HTTPTarget{
	{DestAddr: "127.0.0.1", DestPort: 8080, UseHTTPS: false},
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// HTTPTarget describes a single downstream HTTP or HTTPS service.
type HTTPTarget struct {
	DestAddr string // IP address or hostname of the downstream service
	DestPort uint16 // TCP port of the downstream service
	UseHTTPS bool   // When true the outbound leg uses HTTPS
}

// HTTPHandler intercepts TCP connections from the netstack forwarder and
// services them as HTTP or HTTPS, reverse-proxying each request to one of the
// configured downstream HTTPTarget services.
//
// It is intentionally separate from TCPHandler: there is no overlap between
// raw-TCP connections and HTTP-aware connections on the same destination port.
type HTTPHandler struct {
	stack        *stack.Stack
	proxyHandler *ProxyHandler

	// Configuration (populated from hardcoded test values by NewHTTPHandler).
	targets    []HTTPTarget
	listenPort uint16 // Port this handler claims; used for routing by TCPHandler
	serveHTTPS bool   // Present TLS to the incoming (client) side
	certFile   string // PEM certificate for the incoming TLS listener
	keyFile    string // PEM private key for the incoming TLS listener

	// Runtime state – initialised by Start().
	listener *chanListener
	server   *http.Server
	// One pre-built reverse proxy per target entry.
	proxies []*httputil.ReverseProxy
}

// ---------------------------------------------------------------------------
// chanListener – net.Listener backed by a channel
// ---------------------------------------------------------------------------

// chanListener implements net.Listener by receiving net.Conn values over a
// buffered channel. This lets the netstack TCP forwarder hand off connections
// directly to a running http.Server without any real OS socket.
type chanListener struct {
	connCh chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newChanListener() *chanListener {
	return &chanListener{
		connCh: make(chan net.Conn, 128),
		closed: make(chan struct{}),
	}
}

// Accept blocks until a connection is available or the listener is closed.
func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case conn, ok := <-l.connCh:
		if !ok {
			return nil, net.ErrClosed
		}
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

// Close shuts down the listener; subsequent Accept calls return net.ErrClosed.
func (l *chanListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

// Addr returns a placeholder address (the listener has no real OS socket).
func (l *chanListener) Addr() net.Addr {
	return &net.TCPAddr{}
}

// send delivers conn to the listener. Returns false if the listener is already
// closed, in which case the caller should close conn itself.
func (l *chanListener) send(conn net.Conn) bool {
	select {
	case l.connCh <- conn:
		return true
	case <-l.closed:
		return false
	}
}

// ---------------------------------------------------------------------------
// HTTPHandler constructor and lifecycle
// ---------------------------------------------------------------------------

// NewHTTPHandler creates an HTTPHandler wired to the given stack and
// ProxyHandler, using the hardcoded test configuration defined at the top of
// this file.
func NewHTTPHandler(s *stack.Stack, ph *ProxyHandler) *HTTPHandler {
	return &HTTPHandler{
		stack:        s,
		proxyHandler: ph,
		targets:      testHTTPTargets,
		listenPort:   testHTTPListenPort,
		serveHTTPS:   testHTTPServeHTTPS,
		certFile:     testHTTPCertFile,
		keyFile:      testHTTPKeyFile,
	}
}

// Start builds the per-target reverse proxies and launches the HTTP(S) server
// that will service connections delivered via HandleConn.
func (h *HTTPHandler) Start() error {
	// Build one ReverseProxy per target.
	h.proxies = make([]*httputil.ReverseProxy, 0, len(h.targets))
	for i, t := range h.targets {
		scheme := "http"
		if t.UseHTTPS {
			scheme = "https"
		}
		targetURL := &url.URL{
			Scheme: scheme,
			Host:   fmt.Sprintf("%s:%d", t.DestAddr, t.DestPort),
		}

		proxy := httputil.NewSingleHostReverseProxy(targetURL)

		// For HTTPS downstream, allow self-signed certificates during testing.
		if t.UseHTTPS {
			proxy.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, //nolint:gosec // intentional for test targets
				},
			}
		}

		idx := i // capture for closure
		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			logger.Error("HTTP handler: upstream error (target %d, %s %s): %v",
				idx, r.Method, r.URL.RequestURI(), err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		}

		h.proxies = append(h.proxies, proxy)
	}

	h.listener = newChanListener()

	h.server = &http.Server{
		Handler: http.HandlerFunc(h.handleRequest),
	}

	if h.serveHTTPS {
		cert, err := tls.LoadX509KeyPair(h.certFile, h.keyFile)
		if err != nil {
			return fmt.Errorf("HTTP handler: failed to load TLS keypair (%s, %s): %w",
				h.certFile, h.keyFile, err)
		}
		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
		tlsListener := tls.NewListener(h.listener, tlsCfg)
		go func() {
			if err := h.server.Serve(tlsListener); err != nil && err != http.ErrServerClosed {
				logger.Error("HTTP handler: HTTPS server exited: %v", err)
			}
		}()
		logger.Info("HTTP handler: listening (HTTPS) on port %d, %d downstream target(s)",
			h.listenPort, len(h.targets))
	} else {
		go func() {
			if err := h.server.Serve(h.listener); err != nil && err != http.ErrServerClosed {
				logger.Error("HTTP handler: HTTP server exited: %v", err)
			}
		}()
		logger.Info("HTTP handler: listening (HTTP) on port %d, %d downstream target(s)",
			h.listenPort, len(h.targets))
	}

	return nil
}

// HandleConn accepts a TCP connection from the netstack forwarder and delivers
// it to the running HTTP(S) server. The HTTP handler takes full ownership of
// the connection's lifecycle; the caller must NOT close conn after this call.
func (h *HTTPHandler) HandleConn(conn net.Conn) {
	if !h.listener.send(conn) {
		// Listener already closed – clean up the orphaned connection.
		conn.Close()
	}
}

// HandlesPort reports whether this handler is responsible for connections
// arriving on the given destination port.
func (h *HTTPHandler) HandlesPort(port uint16) bool {
	return port == h.listenPort
}

// Close shuts down the underlying HTTP server and the channel listener.
func (h *HTTPHandler) Close() error {
	if h.server != nil {
		if err := h.server.Close(); err != nil {
			return err
		}
	}
	if h.listener != nil {
		h.listener.Close()
	}
	return nil
}

// ---------------------------------------------------------------------------
// Request routing
// ---------------------------------------------------------------------------

// handleRequest proxies an incoming HTTP request to the appropriate downstream
// target. Currently always routes to the first (and, in the hardcoded test
// setup, only) configured target.
func (h *HTTPHandler) handleRequest(w http.ResponseWriter, r *http.Request) {
	if len(h.proxies) == 0 {
		logger.Error("HTTP handler: no downstream targets configured")
		http.Error(w, "no targets configured", http.StatusBadGateway)
		return
	}

	// TODO: add host/path-based routing when moving beyond hardcoded test config.
	proxy := h.proxies[0]
	target := h.targets[0]

	scheme := "http"
	if target.UseHTTPS {
		scheme = "https"
	}
	logger.Info("HTTP handler: %s %s -> %s://%s:%d",
		r.Method, r.URL.RequestURI(), scheme, target.DestAddr, target.DestPort)

	proxy.ServeHTTP(w, r)
}