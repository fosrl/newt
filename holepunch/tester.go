package holepunch

import (
	"crypto/rand"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/fosrl/newt/bind"
	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/util"
)

// TestResult represents the result of a connection test
type TestResult struct {
	// Success indicates whether the test was successful
	Success bool
	// RTT is the round-trip time of the test packet
	RTT time.Duration
	// Endpoint is the endpoint that was tested
	Endpoint string
	// Error contains any error that occurred during the test
	Error error
}

// TestConnectionOptions configures the connection test
type TestConnectionOptions struct {
	// Timeout is how long to wait for a response (default: 5 seconds)
	Timeout time.Duration
	// Retries is the number of times to retry on failure (default: 0)
	Retries int
}

// DefaultTestOptions returns the default test options
func DefaultTestOptions() TestConnectionOptions {
	return TestConnectionOptions{
		Timeout: 5 * time.Second,
		Retries: 0,
	}
}

// cachedAddr holds a cached resolved UDP address
type cachedAddr struct {
	addr      *net.UDPAddr
	resolvedAt time.Time
}

// HolepunchTester monitors holepunch connectivity using magic packets
type HolepunchTester struct {
	sharedBind *bind.SharedBind
	mu         sync.RWMutex
	running    bool
	stopChan   chan struct{}

	// Pending requests waiting for responses (key: echo data as string)
	pendingRequests sync.Map // map[string]*pendingRequest

	// Callback when connection status changes
	callback HolepunchStatusCallback

	// Address cache to avoid repeated DNS/UDP resolution
	addrCache    map[string]*cachedAddr
	addrCacheMu  sync.RWMutex
	addrCacheTTL time.Duration // How long cached addresses are valid
}

// HolepunchStatus represents the status of a holepunch connection
type HolepunchStatus struct {
	Endpoint  string
	Connected bool
	RTT       time.Duration
}

// HolepunchStatusCallback is called when holepunch status changes
type HolepunchStatusCallback func(status HolepunchStatus)

// pendingRequest tracks a pending test request
type pendingRequest struct {
	endpoint  string
	sentAt    time.Time
	replyChan chan time.Duration
}

// NewHolepunchTester creates a new holepunch tester using the given SharedBind
func NewHolepunchTester(sharedBind *bind.SharedBind) *HolepunchTester {
	return &HolepunchTester{
		sharedBind:   sharedBind,
		addrCache:    make(map[string]*cachedAddr),
		addrCacheTTL: 5 * time.Minute, // Cache addresses for 5 minutes
	}
}

// SetCallback sets the callback for connection status changes
func (t *HolepunchTester) SetCallback(callback HolepunchStatusCallback) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.callback = callback
}

// Start begins listening for magic packet responses
func (t *HolepunchTester) Start() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.running {
		return fmt.Errorf("tester already running")
	}

	if t.sharedBind == nil {
		return fmt.Errorf("sharedBind is nil")
	}

	t.running = true
	t.stopChan = make(chan struct{})

	// Register our callback with the SharedBind to receive magic responses
	t.sharedBind.SetMagicResponseCallback(t.handleResponse)

	logger.Debug("HolepunchTester started")
	return nil
}

// Stop stops the tester
func (t *HolepunchTester) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.running {
		return
	}

	t.running = false
	close(t.stopChan)

	// Clear the callback
	if t.sharedBind != nil {
		t.sharedBind.SetMagicResponseCallback(nil)
	}

	// Cancel all pending requests
	t.pendingRequests.Range(func(key, value interface{}) bool {
		if req, ok := value.(*pendingRequest); ok {
			close(req.replyChan)
		}
		t.pendingRequests.Delete(key)
		return true
	})

	// Clear address cache
	t.addrCacheMu.Lock()
	t.addrCache = make(map[string]*cachedAddr)
	t.addrCacheMu.Unlock()

	logger.Debug("HolepunchTester stopped")
}

// resolveEndpoint resolves an endpoint to a UDP address, using cache when possible
func (t *HolepunchTester) resolveEndpoint(endpoint string) (*net.UDPAddr, error) {
	// Check cache first
	t.addrCacheMu.RLock()
	cached, ok := t.addrCache[endpoint]
	ttl := t.addrCacheTTL
	t.addrCacheMu.RUnlock()

	if ok && time.Since(cached.resolvedAt) < ttl {
		return cached.addr, nil
	}

	// Resolve the endpoint
	host, err := util.ResolveDomain(endpoint)
	if err != nil {
		host = endpoint
	}

	_, _, err = net.SplitHostPort(host)
	if err != nil {
		host = net.JoinHostPort(host, "21820")
	}

	remoteAddr, err := net.ResolveUDPAddr("udp", host)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve UDP address %s: %w", host, err)
	}

	// Cache the result
	t.addrCacheMu.Lock()
	t.addrCache[endpoint] = &cachedAddr{
		addr:       remoteAddr,
		resolvedAt: time.Now(),
	}
	t.addrCacheMu.Unlock()

	return remoteAddr, nil
}

// InvalidateCache removes a specific endpoint from the address cache
func (t *HolepunchTester) InvalidateCache(endpoint string) {
	t.addrCacheMu.Lock()
	delete(t.addrCache, endpoint)
	t.addrCacheMu.Unlock()
}

// ClearCache clears all cached addresses
func (t *HolepunchTester) ClearCache() {
	t.addrCacheMu.Lock()
	t.addrCache = make(map[string]*cachedAddr)
	t.addrCacheMu.Unlock()
}

// handleResponse is called by SharedBind when a magic response is received
func (t *HolepunchTester) handleResponse(addr netip.AddrPort, echoData []byte) {
	// logger.Debug("Received magic response from %s", addr.String())
	key := string(echoData)

	value, ok := t.pendingRequests.LoadAndDelete(key)
	if !ok {
		// No matching request found
		logger.Debug("No pending request found for magic response from %s", addr.String())
		return
	}

	req := value.(*pendingRequest)
	rtt := time.Since(req.sentAt)
	// logger.Debug("Magic response matched pending request for %s (RTT: %v)", req.endpoint, rtt)

	// Send RTT to the waiting goroutine (non-blocking)
	select {
	case req.replyChan <- rtt:
	default:
	}
}

// TestEndpoint sends a magic test packet to the endpoint and waits for a response.
// This uses the SharedBind so packets come from the same source port as WireGuard.
func (t *HolepunchTester) TestEndpoint(endpoint string, timeout time.Duration) TestResult {
	result := TestResult{
		Endpoint: endpoint,
	}

	t.mu.RLock()
	running := t.running
	sharedBind := t.sharedBind
	t.mu.RUnlock()

	if !running {
		result.Error = fmt.Errorf("tester not running")
		return result
	}

	if sharedBind == nil || sharedBind.IsClosed() {
		result.Error = fmt.Errorf("sharedBind is nil or closed")
		return result
	}

	// Resolve the endpoint (using cache)
	remoteAddr, err := t.resolveEndpoint(endpoint)
	if err != nil {
		result.Error = err
		return result
	}

	// Generate random data for the test packet
	randomData := make([]byte, bind.MagicPacketDataLen)
	if _, err := rand.Read(randomData); err != nil {
		result.Error = fmt.Errorf("failed to generate random data: %w", err)
		return result
	}

	// Create a pending request
	req := &pendingRequest{
		endpoint:  endpoint,
		sentAt:    time.Now(),
		replyChan: make(chan time.Duration, 1),
	}

	key := string(randomData)
	t.pendingRequests.Store(key, req)

	// Build the test request packet
	request := make([]byte, bind.MagicTestRequestLen)
	copy(request, bind.MagicTestRequest)
	copy(request[len(bind.MagicTestRequest):], randomData)

	// Send the test packet
	_, err = sharedBind.WriteToUDP(request, remoteAddr)
	if err != nil {
		t.pendingRequests.Delete(key)
		result.Error = fmt.Errorf("failed to send test packet: %w", err)
		return result
	}

	// Wait for response with timeout
	select {
	case rtt, ok := <-req.replyChan:
		if ok {
			result.Success = true
			result.RTT = rtt
		} else {
			result.Error = fmt.Errorf("request cancelled")
		}
	case <-time.After(timeout):
		t.pendingRequests.Delete(key)
		result.Error = fmt.Errorf("timeout waiting for response")
	}

	return result
}

// TestConnectionWithBind sends a magic test packet using an existing SharedBind.
// This is useful when you want to test the connection through the same socket
// that WireGuard is using, which tests the actual hole-punched path.
func TestConnectionWithBind(sharedBind *bind.SharedBind, endpoint string, opts *TestConnectionOptions) TestResult {
	if opts == nil {
		defaultOpts := DefaultTestOptions()
		opts = &defaultOpts
	}

	result := TestResult{
		Endpoint: endpoint,
	}

	if sharedBind == nil {
		result.Error = fmt.Errorf("sharedBind is nil")
		return result
	}

	if sharedBind.IsClosed() {
		result.Error = fmt.Errorf("sharedBind is closed")
		return result
	}

	// Resolve the endpoint
	host, err := util.ResolveDomain(endpoint)
	if err != nil {
		host = endpoint
	}

	_, _, err = net.SplitHostPort(host)
	if err != nil {
		host = net.JoinHostPort(host, "21820")
	}

	remoteAddr, err := net.ResolveUDPAddr("udp", host)
	if err != nil {
		result.Error = fmt.Errorf("failed to resolve UDP address %s: %w", host, err)
		return result
	}

	// Generate random data for the test packet
	randomData := make([]byte, bind.MagicPacketDataLen)
	if _, err := rand.Read(randomData); err != nil {
		result.Error = fmt.Errorf("failed to generate random data: %w", err)
		return result
	}

	// Build the test request packet
	request := make([]byte, bind.MagicTestRequestLen)
	copy(request, bind.MagicTestRequest)
	copy(request[len(bind.MagicTestRequest):], randomData)

	// Get the underlying UDP connection to set read deadline and read response
	udpConn := sharedBind.GetUDPConn()
	if udpConn == nil {
		result.Error = fmt.Errorf("could not get UDP connection from SharedBind")
		return result
	}

	attempts := opts.Retries + 1
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			logger.Debug("Retrying connection test to %s (attempt %d/%d)", endpoint, attempt+1, attempts)
		}

		// Note: We can't easily set a read deadline on the shared connection
		// without affecting WireGuard, so we use a goroutine with timeout instead
		startTime := time.Now()

		// Send the test packet through the shared bind
		_, err = sharedBind.WriteToUDP(request, remoteAddr)
		if err != nil {
			result.Error = fmt.Errorf("failed to send test packet: %w", err)
			if attempt < attempts-1 {
				continue
			}
			return result
		}

		// For shared bind test, we send the packet but can't easily wait for
		// response without interfering with WireGuard's receive loop.
		// The response will be handled by SharedBind automatically.
		// We consider the test successful if the send succeeded.
		// For a full round-trip test, use TestConnection() with a separate socket.

		result.RTT = time.Since(startTime)
		result.Success = true
		result.Error = nil
		logger.Debug("Test packet sent to %s via SharedBind", endpoint)
		return result
	}

	return result
}
