package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/fosrl/newt/logger"
	"github.com/miekg/dns"
)

// DNSAuthorityConfig holds configuration for a DNS authority zone
type DNSAuthorityConfig struct {
	Enabled       bool                   `json:"enabled"`
	Domain        string                 `json:"domain"`        // e.g., "hub.docker.visnovsky.us"
	TTL           uint32                 `json:"ttl"`           // TTL for DNS responses
	RoutingPolicy string                 `json:"routingPolicy"` // "failover", "roundrobin", "priority", "intelligent"
	StickySession bool                   `json:"stickySession,omitempty"`
	ServingSiteID int                    `json:"servingSiteId,omitempty"`
	Targets       []DNSAuthorityTarget   `json:"targets"`
}

func authoritativeBaseDomain(domain string) string {
	trimmed := strings.TrimSuffix(domain, ".")
	trimmed = strings.TrimPrefix(trimmed, "*.")
	return dns.Fqdn(trimmed)
}

// DNSAuthorityTarget represents a target IP with health status
type DNSAuthorityTarget struct {
	IP               string `json:"ip"`                         // Public IP to respond with
	Priority         int    `json:"priority"`                   // Lower = higher priority for failover
	Healthy          bool   `json:"healthy"`                    // Health status from Pangolin
	SiteID           int    `json:"siteId"`                     // Site ID for reference
	SiteName         string `json:"siteName"`                   // Human-readable name
	BackendLatencyMs int64  `json:"backendLatencyMs,omitempty"` // Existing target healthcheck latency from site to backend
}

// DNSAuthorityServer serves authoritative DNS responses on port 53
type DNSAuthorityServer struct {
	mu                       sync.RWMutex
	zones                    map[string]*DNSAuthorityConfig // domain -> config
	server                   *dns.Server
	tcpServer                *dns.Server
	ctx                      context.Context
	cancel                   context.CancelFunc
	running                  bool
	bindAddr                 string
	rrIndex                  map[string]int // For round-robin: domain -> current index
	latencyCache             map[string]map[string]latencySample // domain -> target IP -> sample
	latencyRefreshing        map[string]bool                     // domain -> refresh in progress
	stickyAffinities         map[string]map[string]stickyAffinity // queried domain -> client IP -> sticky target
	stickyAffinityTTL        time.Duration
	intelligentProbeInterval time.Duration
	intelligentProbeTimeout  time.Duration
}

type latencySample struct {
	latency    time.Duration
	measuredAt time.Time
}

type stickyAffinity struct {
	targetIP      string
	establishedAt time.Time
}

// NewDNSAuthorityServer creates a new DNS authority server
func NewDNSAuthorityServer(bindAddr string) *DNSAuthorityServer {
	ctx, cancel := context.WithCancel(context.Background())

	if bindAddr == "" {
		bindAddr = "0.0.0.0"
	}

	return &DNSAuthorityServer{
		zones:                    make(map[string]*DNSAuthorityConfig),
		ctx:                      ctx,
		cancel:                   cancel,
		bindAddr:                 bindAddr,
		rrIndex:                  make(map[string]int),
		latencyCache:             make(map[string]map[string]latencySample),
		latencyRefreshing:        make(map[string]bool),
		stickyAffinities:         make(map[string]map[string]stickyAffinity),
		stickyAffinityTTL:        24 * time.Hour,
		intelligentProbeInterval: 15 * time.Second,
		intelligentProbeTimeout:  500 * time.Millisecond,
	}
}

// UpdateZone updates or adds a zone configuration
func (s *DNSAuthorityServer) UpdateZone(config *DNSAuthorityConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Normalize domain to FQDN format (trailing dot)
	domain := config.Domain
	if len(domain) > 0 && domain[len(domain)-1] != '.' {
		domain = domain + "."
	}

	// Set defaults
	if config.TTL == 0 {
		config.TTL = 60
	}
	if config.RoutingPolicy == "" {
		config.RoutingPolicy = "failover"
	}

	s.zones[domain] = config
	if _, ok := s.latencyCache[domain]; !ok {
		s.latencyCache[domain] = make(map[string]latencySample)
	}
	logger.Info("DNS Authority: Updated zone %s with %d targets (policy: %s)", domain, len(config.Targets), config.RoutingPolicy)
}

// RemoveZone removes a zone configuration
func (s *DNSAuthorityServer) RemoveZone(domain string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(domain) > 0 && domain[len(domain)-1] != '.' {
		domain = domain + "."
	}

	delete(s.zones, domain)
	delete(s.rrIndex, domain)
	delete(s.latencyCache, domain)
	delete(s.latencyRefreshing, domain)
	delete(s.stickyAffinities, normalizeDomainKey(domain))
	logger.Info("DNS Authority: Removed zone %s", domain)
}

// UpdateTargetHealth updates the health status of a target
func (s *DNSAuthorityServer) UpdateTargetHealth(domain string, siteID int, healthy bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(domain) > 0 && domain[len(domain)-1] != '.' {
		domain = domain + "."
	}

	zone, exists := s.zones[domain]
	if !exists {
		return
	}

	for i := range zone.Targets {
		if zone.Targets[i].SiteID == siteID {
			zone.Targets[i].Healthy = healthy
			logger.Debug("DNS Authority: Updated health for %s site %d to %v", domain, siteID, healthy)
			break
		}
	}
}

// Start starts the DNS authority server on port 53.
//
// CAVEAT: Port 53 is a privileged port on most systems. This method performs
// a pre-flight bind check before attempting to start. Common reasons for
// failure include:
//   - systemd-resolved (Linux) already listening on 127.0.0.53:53
//   - Another DNS server (dnsmasq, unbound) occupying port 53
//   - Insufficient privileges (non-root on Linux, no admin on Windows)
//   - macOS mDNSResponder listening on port 53
func (s *DNSAuthorityServer) Start() error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()

	addr := fmt.Sprintf("%s:53", s.bindAddr)

	// Pre-flight: check if port 53 is bindable before committing to start
	if err := s.checkPort53Available(addr); err != nil {
		logger.Warn("DNS Authority: Port 53 pre-flight check failed on %s: %v", addr, err)
		logger.Warn("DNS Authority: Common causes:")
		logger.Warn("  - systemd-resolved is listening on 127.0.0.53:53 (try: sudo systemctl disable --now systemd-resolved)")
		logger.Warn("  - Another DNS server (dnsmasq, unbound, pihole) is using port 53")
		logger.Warn("  - Insufficient privileges (port 53 requires root/admin)")
		logger.Warn("  - macOS mDNSResponder is occupying port 53")
		logger.Warn("DNS Authority: The server will NOT start. DNS authority zones are configured but inactive.")
		return fmt.Errorf("port 53 is not available on %s: %w", s.bindAddr, err)
	}

	logger.Info("DNS Authority: Port 53 pre-flight check passed on %s", addr)

	// Create DNS handler
	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handleDNSQuery)

	// Create UDP server
	s.server = &dns.Server{
		Addr:    addr,
		Net:     "udp",
		Handler: mux,
	}

	// Create TCP server (some clients prefer TCP)
	s.tcpServer = &dns.Server{
		Addr:    addr,
		Net:     "tcp",
		Handler: mux,
	}

	// Start UDP server
	go func() {
		logger.Info("DNS Authority: Starting UDP server on %s", addr)
		if err := s.server.ListenAndServe(); err != nil {
			if s.ctx.Err() == nil {
				logger.Error("DNS Authority: UDP server error: %v", err)
			}
		}
	}()

	// Start TCP server
	go func() {
		logger.Info("DNS Authority: Starting TCP server on %s", addr)
		if err := s.tcpServer.ListenAndServe(); err != nil {
			if s.ctx.Err() == nil {
				logger.Error("DNS Authority: TCP server error: %v", err)
			}
		}
	}()

	// Give servers time to start and check for bind errors
	time.Sleep(100 * time.Millisecond)

	s.mu.Lock()
	s.running = true
	s.mu.Unlock()

	s.startIntelligentRefreshLoop()

	logger.Info("DNS Authority: Server started successfully on %s", addr)
	return nil
}

// Stop stops the DNS authority server
func (s *DNSAuthorityServer) Stop() error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = false
	s.mu.Unlock()

	s.cancel()

	if s.server != nil {
		if err := s.server.Shutdown(); err != nil {
			logger.Error("DNS Authority: Error shutting down UDP server: %v", err)
		}
	}

	if s.tcpServer != nil {
		if err := s.tcpServer.Shutdown(); err != nil {
			logger.Error("DNS Authority: Error shutting down TCP server: %v", err)
		}
	}

	logger.Info("DNS Authority: Server stopped")
	return nil
}

// handleDNSQuery handles incoming DNS queries
func (s *DNSAuthorityServer) handleDNSQuery(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	if len(r.Question) == 0 {
		w.WriteMsg(m)
		return
	}

	q := r.Question[0]
	logger.Debug("DNS Authority: Query for %s (type %s) from %s", q.Name, dns.TypeToString[q.Qtype], w.RemoteAddr())

	s.mu.RLock()
	zone, exactMatch := s.zones[q.Name]

	// If no exact match, try to find a wildcard match
	if !exactMatch {
		zone = s.findWildcardMatch(q.Name)
	}
	s.mu.RUnlock()

	if zone == nil || !zone.Enabled {
		// Not authoritative for this domain - return NXDOMAIN or REFUSED
		m.Rcode = dns.RcodeRefused
		w.WriteMsg(m)
		return
	}

	switch q.Qtype {
	case dns.TypeA:
		s.handleARecord(m, q, zone, clientIPFromRemoteAddr(w.RemoteAddr()))
	case dns.TypeAAAA:
		// Return empty response for AAAA (no IPv6 support yet)
		// This prevents browsers from waiting for AAAA timeout
		m.Rcode = dns.RcodeSuccess
	case dns.TypeNS:
		s.handleNSRecord(m, q, zone)
	case dns.TypeSOA:
		s.handleSOARecord(m, q, zone)
	default:
		// Return empty response for unsupported types
		m.Rcode = dns.RcodeSuccess
	}

	w.WriteMsg(m)
}

// findWildcardMatch finds a zone that matches via wildcard
func (s *DNSAuthorityServer) findWildcardMatch(name string) *DNSAuthorityConfig {
	// Try progressively shorter domain prefixes
	// e.g., for "foo.bar.example.com." try "*.bar.example.com." etc.
	labels := dns.SplitDomainName(name)
	for i := 1; i < len(labels); i++ {
		wildcard := "*." + dns.Fqdn(labels[i])
		for j := i + 1; j < len(labels); j++ {
			wildcard = wildcard[:len(wildcard)-1] + "." + labels[j] + "."
		}
		if zone, ok := s.zones[wildcard]; ok {
			return zone
		}
	}
	return nil
}

// handleARecord responds with A records based on health and routing policy
func (s *DNSAuthorityServer) handleARecord(m *dns.Msg, q dns.Question, zone *DNSAuthorityConfig, clientIP string) {
	ips := s.selectTargetIPs(zone, q.Name, clientIP)

	for _, ip := range ips {
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil || parsedIP.To4() == nil {
			continue
		}

		rr := &dns.A{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    zone.TTL,
			},
			A: parsedIP.To4(),
		}
		m.Answer = append(m.Answer, rr)
	}

	if len(m.Answer) == 0 {
		logger.Warn("DNS Authority: No healthy targets for %s", q.Name)
	}
}

// handleNSRecord responds with NS records for all healthy targets and includes
// glue A-records in the Additional section so resolvers can reach each nameserver.
func (s *DNSAuthorityServer) handleNSRecord(m *dns.Msg, q dns.Question, zone *DNSAuthorityConfig) {
	baseDomain := authoritativeBaseDomain(zone.Domain)
	nsIndex := 1
	for _, target := range zone.Targets {
		if target.Healthy || len(zone.Targets) == 1 {
			nsName := dns.Fqdn(fmt.Sprintf("ns%d.%s", nsIndex, baseDomain))
			rr := &dns.NS{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeNS,
					Class:  dns.ClassINET,
					Ttl:    zone.TTL,
				},
				Ns: nsName,
			}
			m.Answer = append(m.Answer, rr)

			// Add glue A-record in Additional section
			parsedIP := net.ParseIP(target.IP)
			if parsedIP != nil && parsedIP.To4() != nil {
				glue := &dns.A{
					Hdr: dns.RR_Header{
						Name:   nsName,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    zone.TTL,
					},
					A: parsedIP.To4(),
				}
				m.Extra = append(m.Extra, glue)
			}

			nsIndex++
		}
	}
}

// handleSOARecord responds with SOA record
func (s *DNSAuthorityServer) handleSOARecord(m *dns.Msg, q dns.Question, zone *DNSAuthorityConfig) {
	baseDomain := authoritativeBaseDomain(zone.Domain)
	soa := &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    zone.TTL,
		},
		Ns:      dns.Fqdn(fmt.Sprintf("ns1.%s", baseDomain)),
		Mbox:    dns.Fqdn(fmt.Sprintf("hostmaster.%s", baseDomain)),
		Serial:  uint32(time.Now().Unix()),
		Refresh: 86400,
		Retry:   7200,
		Expire:  3600000,
		Minttl:  zone.TTL,
	}
	m.Answer = append(m.Answer, soa)
}

// selectTargetIPs selects IPs based on routing policy and health status
func (s *DNSAuthorityServer) selectTargetIPs(zone *DNSAuthorityConfig, queriedDomain string, clientIP string) []string {
	var ips []string

	// Get healthy targets
	var healthyTargets []DNSAuthorityTarget
	var allTargets []DNSAuthorityTarget

	for _, t := range zone.Targets {
		allTargets = append(allTargets, t)
		if t.Healthy {
			healthyTargets = append(healthyTargets, t)
		}
	}

	// If no healthy targets, fall back to all targets (best effort)
	targets := healthyTargets
	if len(targets) == 0 {
		targets = allTargets
		logger.Warn("DNS Authority: No healthy targets for %s, using all targets", zone.Domain)
	}

	if len(targets) == 0 {
		return ips
	}

	var stickyTarget *DNSAuthorityTarget
	if zone.StickySession && clientIP != "" {
		if target, ok := s.getStickyTarget(queriedDomain, clientIP, targets); ok {
			stickyTarget = &target
		}
	}

	switch zone.RoutingPolicy {
	case "failover":
		if stickyTarget != nil {
			ips = append(ips, stickyTarget.IP)
		} else {
			ips = append(ips, selectLowestPriorityTarget(targets).IP)
		}

	case "roundrobin":
		if stickyTarget != nil {
			ips = append(ips, stickyTarget.IP)
		} else {
			// Rotate through all healthy targets
			s.mu.Lock()
			idx := s.rrIndex[zone.Domain]
			s.rrIndex[zone.Domain] = (idx + 1) % len(targets)
			s.mu.Unlock()
			ips = append(ips, targets[idx%len(targets)].IP)
		}

	case "priority":
		// Return all healthy targets (client can choose)
		if stickyTarget != nil {
			ips = append(ips, stickyTarget.IP)
		}
		for _, t := range targets {
			if stickyTarget != nil && t.IP == stickyTarget.IP {
				continue
			}
			ips = append(ips, t.IP)
		}

	case "intelligent":
		if stickyTarget != nil {
			ips = append(ips, stickyTarget.IP)
		} else {
			best := s.selectIntelligentTarget(zone, targets)
			ips = append(ips, best.IP)
		}

	default:
		// Default to failover behavior
		if stickyTarget != nil {
			ips = append(ips, stickyTarget.IP)
		} else {
			ips = append(ips, selectLowestPriorityTarget(targets).IP)
		}
	}

	return ips
}

// RecordSessionEstablished records that a client has established a session on
// this Newt for the given domain. Sticky DNS responses will prioritize this
// site's public IP for subsequent queries from that client.
func (s *DNSAuthorityServer) RecordSessionEstablished(domain string, clientIP string) {
	if clientIP == "" || domain == "" {
		return
	}

	domainKey := normalizeDomainKey(domain)

	s.mu.RLock()
	var zone *DNSAuthorityConfig
	if z, ok := s.zones[domainKey]; ok {
		zone = z
	} else {
		zone = s.findWildcardMatch(domainKey)
	}

	if zone == nil || !zone.Enabled || !zone.StickySession || zone.ServingSiteID == 0 {
		s.mu.RUnlock()
		return
	}

	targetIP := ""
	for _, target := range zone.Targets {
		if target.SiteID == zone.ServingSiteID {
			targetIP = target.IP
			break
		}
	}
	s.mu.RUnlock()

	if targetIP == "" {
		return
	}

	s.setStickyTarget(domainKey, clientIP, targetIP)
}

func (s *DNSAuthorityServer) getStickyTarget(queriedDomain string, clientIP string, targets []DNSAuthorityTarget) (DNSAuthorityTarget, bool) {
	domainKey := normalizeDomainKey(queriedDomain)
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	byClient := s.stickyAffinities[domainKey]
	if byClient == nil {
		return DNSAuthorityTarget{}, false
	}

	affinity, ok := byClient[clientIP]
	if !ok {
		return DNSAuthorityTarget{}, false
	}

	if now.Sub(affinity.establishedAt) > s.stickyAffinityTTL {
		delete(byClient, clientIP)
		if len(byClient) == 0 {
			delete(s.stickyAffinities, domainKey)
		}
		return DNSAuthorityTarget{}, false
	}

	for _, t := range targets {
		if t.IP == affinity.targetIP {
			return t, true
		}
	}

	delete(byClient, clientIP)
	if len(byClient) == 0 {
		delete(s.stickyAffinities, domainKey)
	}

	return DNSAuthorityTarget{}, false
}

func (s *DNSAuthorityServer) setStickyTarget(queriedDomain string, clientIP string, targetIP string) {
	domainKey := normalizeDomainKey(queriedDomain)
	s.mu.Lock()
	defer s.mu.Unlock()

	byClient := s.stickyAffinities[domainKey]
	if byClient == nil {
		byClient = make(map[string]stickyAffinity)
		s.stickyAffinities[domainKey] = byClient
	}

	byClient[clientIP] = stickyAffinity{targetIP: targetIP, establishedAt: time.Now()}
}

func clientIPFromRemoteAddr(addr net.Addr) string {
	if addr == nil {
		return ""
	}

	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		return udpAddr.IP.String()
	}
	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		return tcpAddr.IP.String()
	}

	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

func normalizeDomainKey(domain string) string {
	trimmed := strings.TrimSpace(domain)
	if trimmed == "" {
		return ""
	}
	return strings.ToLower(dns.Fqdn(trimmed))
}

func selectLowestPriorityTarget(targets []DNSAuthorityTarget) DNSAuthorityTarget {
	best := targets[0]
	for _, t := range targets[1:] {
		if t.Priority < best.Priority {
			best = t
		}
	}
	return best
}

func (s *DNSAuthorityServer) selectIntelligentTarget(zone *DNSAuthorityConfig, targets []DNSAuthorityTarget) DNSAuthorityTarget {
	now := time.Now()
	refreshNeeded := false

	s.mu.RLock()
	zoneCache := s.latencyCache[zone.Domain]
	bestScore := int64(0)
	var bestTarget *DNSAuthorityTarget
	for i := range targets {
		t := &targets[i]
		sample, ok := zoneCache[t.IP]
		if !ok || now.Sub(sample.measuredAt) > s.intelligentProbeInterval {
			refreshNeeded = true
			continue
		}
		frontendLatencyMs := sample.latency.Milliseconds()
		if frontendLatencyMs <= 0 {
			frontendLatencyMs = 1
		}

		backendLatencyMs := t.BackendLatencyMs
		if backendLatencyMs <= 0 {
			backendLatencyMs = frontendLatencyMs
		}

		// Weight edge reachability higher than backend health latency so DNS answers
		// prefer the site clients can connect to fastest, while still accounting for
		// backend responsiveness when edge latencies are close.
		score := (frontendLatencyMs * 70) + (backendLatencyMs * 30)
		if bestTarget == nil || score < bestScore || (score == bestScore && t.Priority < bestTarget.Priority) {
			bestTarget = t
			bestScore = score
		}
	}
	s.mu.RUnlock()

	if refreshNeeded {
		s.scheduleLatencyRefresh(zone.Domain, targets)
	}

	if bestTarget != nil {
		return *bestTarget
	}

	// If no fresh latency is available yet, preserve HA semantics via failover.
	return selectLowestPriorityTarget(targets)
}

func (s *DNSAuthorityServer) scheduleLatencyRefresh(domain string, targets []DNSAuthorityTarget) {
	s.mu.Lock()
	if s.latencyRefreshing[domain] {
		s.mu.Unlock()
		return
	}
	s.latencyRefreshing[domain] = true
	timeout := s.intelligentProbeTimeout
	s.mu.Unlock()

	go func() {
		results := make(map[string]latencySample)
		for _, t := range targets {
			if latency, ok := probeTargetLatency(t.IP, timeout); ok {
				results[t.IP] = latencySample{latency: latency, measuredAt: time.Now()}
			}
		}

		s.mu.Lock()
		cache := s.latencyCache[domain]
		if cache == nil {
			cache = make(map[string]latencySample)
			s.latencyCache[domain] = cache
		}
		for ip, sample := range results {
			cache[ip] = sample
		}
		s.latencyRefreshing[domain] = false
		s.mu.Unlock()
	}()
}

func (s *DNSAuthorityServer) startIntelligentRefreshLoop() {
	go func() {
		ticker := time.NewTicker(s.intelligentProbeInterval)
		defer ticker.Stop()

		// Prime the latency cache shortly after start so intelligent routing
		// can use measured data without waiting for a query-triggered refresh.
		s.refreshIntelligentZones()

		for {
			select {
			case <-s.ctx.Done():
				return
			case <-ticker.C:
				s.refreshIntelligentZones()
			}
		}
	}()
}

type intelligentRefreshJob struct {
	domain  string
	targets []DNSAuthorityTarget
}

func (s *DNSAuthorityServer) refreshIntelligentZones() {
	jobs := make([]intelligentRefreshJob, 0)

	s.mu.RLock()
	for domain, zone := range s.zones {
		if zone == nil || !zone.Enabled || zone.RoutingPolicy != "intelligent" {
			continue
		}

		healthyTargets := make([]DNSAuthorityTarget, 0, len(zone.Targets))
		allTargets := make([]DNSAuthorityTarget, 0, len(zone.Targets))
		for _, target := range zone.Targets {
			allTargets = append(allTargets, target)
			if target.Healthy {
				healthyTargets = append(healthyTargets, target)
			}
		}

		targets := healthyTargets
		if len(targets) == 0 {
			targets = allTargets
		}

		if len(targets) == 0 {
			continue
		}

		jobs = append(jobs, intelligentRefreshJob{domain: domain, targets: targets})
	}
	s.mu.RUnlock()

	for _, job := range jobs {
		s.scheduleLatencyRefresh(job.domain, job.targets)
	}
}

func probeTargetLatency(ip string, timeout time.Duration) (time.Duration, bool) {
	ports := []string{"443", "80"}
	for _, port := range ports {
		addr := net.JoinHostPort(ip, port)
		start := time.Now()
		conn, err := net.DialTimeout("tcp", addr, timeout)
		if err != nil {
			continue
		}
		_ = conn.Close()
		return time.Since(start), true
	}
	return 0, false
}

// IsRunning returns whether the server is running
func (s *DNSAuthorityServer) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

// GetZones returns a copy of all configured zones
func (s *DNSAuthorityServer) GetZones() map[string]*DNSAuthorityConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()

	zones := make(map[string]*DNSAuthorityConfig)
	for k, v := range s.zones {
		zones[k] = v
	}
	return zones
}

// checkPort53Available performs a pre-flight check to determine whether port 53
// can be bound (both UDP and TCP). The test listeners are closed immediately
// after a successful bind. This catches common conflicts early with a clear
// error message instead of a silent goroutine failure.
func (s *DNSAuthorityServer) checkPort53Available(addr string) error {
	// Check UDP
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("invalid address %s: %w", addr, err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("cannot bind UDP %s: %w", addr, err)
	}
	udpConn.Close()

	// Check TCP
	tcpListener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("cannot bind TCP %s: %w", addr, err)
	}
	tcpListener.Close()

	return nil
}

// SelfTest performs a DNS query to itself to verify the server is responding
func (s *DNSAuthorityServer) SelfTest() error {
	addr := fmt.Sprintf("%s:53", s.bindAddr)

	c := new(dns.Client)
	c.Timeout = 1 * time.Second

	m := new(dns.Msg)
	// We use a dummy query; even a NXDOMAIN response confirms the server is alive
	m.SetQuestion("healthcheck.newt.", dns.TypeA)

	// In some environments, binding to 0.0.0.0 then querying 127.0.0.1:53 works.
	// We'll try the bind address first, then localhost as fallback.
	testAddrs := []string{addr}
	if s.bindAddr == "0.0.0.0" {
		testAddrs = append(testAddrs, "127.0.0.1:53")
	}

	var lastErr error
	for _, testAddr := range testAddrs {
		_, _, err := c.Exchange(m, testAddr)
		if err == nil {
			return nil
		}
		lastErr = err
	}

	return fmt.Errorf("self-test failed: %w", lastErr)
}
