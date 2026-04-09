/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package netstack2

import (
	"context"
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
// HTTPTarget
// ---------------------------------------------------------------------------

// HTTPTarget describes a single downstream HTTP or HTTPS service that the
// proxy should forward requests to.
type HTTPTarget struct {
	DestAddr string `json:"destAddr"` // IP address or hostname of the downstream service
	DestPort uint16 `json:"destPort"` // TCP port of the downstream service
	UseHTTPS bool   `json:"useHttps"` // When true the outbound leg uses HTTPS
}

// ---------------------------------------------------------------------------
// HTTPHandler
// ---------------------------------------------------------------------------

// HTTPHandler intercepts TCP connections from the netstack forwarder on ports
// 80 and 443 and services them as HTTP or HTTPS, reverse-proxying each request
// to downstream targets specified by the matching SubnetRule.
//
// HTTP and raw TCP are fully separate: a connection is only routed here when
// its SubnetRule has Protocol set ("http" or "https"). All other connections
// on those ports fall through to the normal raw-TCP path.
//
// Incoming TLS termination (Protocol == "https") is performed per-connection
// using the certificate and key stored in the rule, so different subnet rules
// can present different certificates without sharing any state.
//
// Outbound connections to downstream targets honour HTTPTarget.UseHTTPS
// independently of the incoming protocol.
type HTTPHandler struct {
	stack        *stack.Stack
	proxyHandler *ProxyHandler

	listener *chanListener
	server   *http.Server

	// proxyCache holds pre-built *httputil.ReverseProxy values keyed by the
	// canonical target URL string ("scheme://host:port"). Building a proxy is
	// cheap, but reusing one preserves the underlying http.Transport connection
	// pool, which matters for throughput.
	proxyCache sync.Map // map[string]*httputil.ReverseProxy

	// tlsCache holds pre-parsed *tls.Config values keyed by the concatenation
	// of the PEM certificate and key. Parsing a keypair is relatively expensive
	// and the same cert is likely reused across many connections.
	tlsCache sync.Map // map[string]*tls.Config
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
// closed, in which case the caller is responsible for closing conn.
func (l *chanListener) send(conn net.Conn) bool {
	select {
	case l.connCh <- conn:
		return true
	case <-l.closed:
		return false
	}
}

// ---------------------------------------------------------------------------
// httpConnCtx – conn wrapper that carries a SubnetRule through the listener
// ---------------------------------------------------------------------------

// httpConnCtx wraps a net.Conn so the matching SubnetRule can be passed
// through the chanListener into the http.Server's ConnContext callback,
// making it available to request handlers via the request context.
type httpConnCtx struct {
	net.Conn
	rule *SubnetRule
}

// connCtxKey is the unexported context key used to store a *SubnetRule on the
// per-connection context created by http.Server.ConnContext.
type connCtxKey struct{}

// ---------------------------------------------------------------------------
// Constructor and lifecycle
// ---------------------------------------------------------------------------

// NewHTTPHandler creates an HTTPHandler attached to the given stack and
// ProxyHandler. Call Start to begin serving connections.
func NewHTTPHandler(s *stack.Stack, ph *ProxyHandler) *HTTPHandler {
	return &HTTPHandler{
		stack:        s,
		proxyHandler: ph,
	}
}

// Start launches the internal http.Server that services connections delivered
// via HandleConn. The server runs for the lifetime of the HTTPHandler; call
// Close to stop it.
func (h *HTTPHandler) Start() error {
	h.listener = newChanListener()

	h.server = &http.Server{
		Handler: http.HandlerFunc(h.handleRequest),
		// ConnContext runs once per accepted connection and attaches the
		// SubnetRule carried by httpConnCtx to the connection's context so
		// that handleRequest can retrieve it without any global state.
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if cc, ok := c.(*httpConnCtx); ok {
				return context.WithValue(ctx, connCtxKey{}, cc.rule)
			}
			return ctx
		},
	}

	go func() {
		if err := h.server.Serve(h.listener); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP handler: server exited unexpectedly: %v", err)
		}
	}()

	logger.Info("HTTP handler: ready — routing determined per SubnetRule on ports 80/443")
	return nil
}

// HandleConn accepts a TCP connection from the netstack forwarder together
// with the SubnetRule that matched it. The HTTP handler takes full ownership
// of the connection's lifecycle; the caller must NOT close conn after this call.
//
// When rule.Protocol is "https", TLS termination is performed on conn using
// the certificate and key stored in rule.TLSCert and rule.TLSKey before the
// connection is passed to the HTTP server. The HTTP server itself is always
// plain-HTTP; TLS is fully unwrapped at this layer.
func (h *HTTPHandler) HandleConn(conn net.Conn, rule *SubnetRule) {
	var effectiveConn net.Conn = conn

	if rule.Protocol == "https" {
		tlsCfg, err := h.getTLSConfig(rule)
		if err != nil {
			logger.Error("HTTP handler: cannot build TLS config for connection from %s: %v",
				conn.RemoteAddr(), err)
			conn.Close()
			return
		}
		// tls.Server wraps the raw conn; the TLS handshake is deferred until
		// the first Read, which the http.Server will trigger naturally.
		effectiveConn = tls.Server(conn, tlsCfg)
	}

	wrapped := &httpConnCtx{Conn: effectiveConn, rule: rule}
	if !h.listener.send(wrapped) {
		// Listener is already closed — clean up the orphaned connection.
		effectiveConn.Close()
	}
}

// Close gracefully shuts down the HTTP server and the underlying channel
// listener, causing the goroutine started in Start to exit.
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
// Internal helpers
// ---------------------------------------------------------------------------

// getTLSConfig returns a *tls.Config for the cert/key pair in rule, using a
// cache to avoid re-parsing the same keypair on every connection.
// The cache key is the concatenation of the PEM cert and key strings, so
// different rules that happen to share the same material hit the same entry.
func (h *HTTPHandler) getTLSConfig(rule *SubnetRule) (*tls.Config, error) {
	cacheKey := rule.TLSCert + "|" + rule.TLSKey
	if v, ok := h.tlsCache.Load(cacheKey); ok {
		return v.(*tls.Config), nil
	}

	cert, err := tls.X509KeyPair([]byte(rule.TLSCert), []byte(rule.TLSKey))
	if err != nil {
		return nil, fmt.Errorf("failed to parse TLS keypair: %w", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	// LoadOrStore is safe under concurrent calls: if two goroutines race here
	// both will produce a valid config; the loser's work is discarded.
	actual, _ := h.tlsCache.LoadOrStore(cacheKey, cfg)
	return actual.(*tls.Config), nil
}

// getProxy returns a cached *httputil.ReverseProxy for the given target,
// creating one on first use. Reusing the proxy preserves its http.Transport
// connection pool, avoiding repeated TCP/TLS handshakes to the downstream.
func (h *HTTPHandler) getProxy(target HTTPTarget) *httputil.ReverseProxy {
	scheme := "http"
	if target.UseHTTPS {
		scheme = "https"
	}
	cacheKey := fmt.Sprintf("%s://%s:%d", scheme, target.DestAddr, target.DestPort)

	if v, ok := h.proxyCache.Load(cacheKey); ok {
		return v.(*httputil.ReverseProxy)
	}

	targetURL := &url.URL{
		Scheme: scheme,
		Host:   fmt.Sprintf("%s:%d", target.DestAddr, target.DestPort),
	}
	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	if target.UseHTTPS {
		// Allow self-signed certificates on downstream HTTPS targets.
		proxy.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // downstream self-signed certs are a supported configuration
			},
		}
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		logger.Error("HTTP handler: upstream error (%s %s -> %s): %v",
			r.Method, r.URL.RequestURI(), cacheKey, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}

	actual, _ := h.proxyCache.LoadOrStore(cacheKey, proxy)
	return actual.(*httputil.ReverseProxy)
}

// handleRequest is the http.Handler entry point. It retrieves the SubnetRule
// attached to the connection by ConnContext, selects the first configured
// downstream target, and forwards the request via the cached ReverseProxy.
//
// TODO: add host/path-based routing across multiple HTTPTargets once the
// configuration model evolves beyond a single target per rule.
func (h *HTTPHandler) handleRequest(w http.ResponseWriter, r *http.Request) {
	rule, _ := r.Context().Value(connCtxKey{}).(*SubnetRule)
	if rule == nil || len(rule.HTTPTargets) == 0 {
		logger.Error("HTTP handler: no downstream targets for request %s %s", r.Method, r.URL.RequestURI())
		http.Error(w, "no targets configured", http.StatusBadGateway)
		return
	}

	target := rule.HTTPTargets[0]
	scheme := "http"
	if target.UseHTTPS {
		scheme = "https"
	}
	logger.Info("HTTP handler: %s %s -> %s://%s:%d",
		r.Method, r.URL.RequestURI(), scheme, target.DestAddr, target.DestPort)

	h.getProxy(target).ServeHTTP(w, r)
}
