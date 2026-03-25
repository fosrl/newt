package netstack2

import (
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/fosrl/newt/logger"
)

const (
	// flushInterval is how often the access logger flushes completed sessions to the server
	flushInterval = 60 * time.Second

	// maxBufferedSessions is the max number of completed sessions to buffer before forcing a flush
	maxBufferedSessions = 100

	// sessionGapThreshold is the maximum gap between the end of one connection
	// and the start of the next for them to be considered part of the same session.
	// If the gap exceeds this, a new consolidated session is created.
	sessionGapThreshold = 5 * time.Second

	// minConnectionsToConsolidate is the minimum number of connections in a group
	// before we bother consolidating. Groups smaller than this are sent as-is.
	minConnectionsToConsolidate = 2
)

// SendFunc is a callback that sends compressed access log data to the server.
// The data is a base64-encoded zlib-compressed JSON array of AccessSession objects.
type SendFunc func(data string) error

// AccessSession represents a tracked access session through the proxy
type AccessSession struct {
	SessionID       string    `json:"sessionId"`
	ResourceID      int       `json:"resourceId"`
	SourceAddr      string    `json:"sourceAddr"`
	DestAddr        string    `json:"destAddr"`
	Protocol        string    `json:"protocol"`
	StartedAt       time.Time `json:"startedAt"`
	EndedAt         time.Time `json:"endedAt,omitempty"`
	BytesTx         int64     `json:"bytesTx"`
	BytesRx         int64     `json:"bytesRx"`
	ConnectionCount int       `json:"connectionCount,omitempty"` // number of raw connections merged into this session (0 or 1 = single)
}

// udpSessionKey identifies a unique UDP "session" by src -> dst
type udpSessionKey struct {
	srcAddr  string
	dstAddr  string
	protocol string
}

// consolidationKey groups connections that may be part of the same logical session.
// Source port is intentionally excluded so that many ephemeral-port connections
// from the same source IP to the same destination are grouped together.
type consolidationKey struct {
	sourceIP   string // IP only, no port
	destAddr   string // full host:port of the destination
	protocol   string
	resourceID int
}

// AccessLogger tracks access sessions for resources and periodically
// flushes completed sessions to the server via a configurable SendFunc.
type AccessLogger struct {
	mu                sync.Mutex
	sessions          map[string]*AccessSession       // active sessions: sessionID -> session
	udpSessions       map[udpSessionKey]*AccessSession // active UDP sessions for dedup
	completedSessions []*AccessSession                 // completed sessions waiting to be flushed
	udpTimeout        time.Duration
	sendFn            SendFunc
	stopCh            chan struct{}
	flushDone         chan struct{} // closed after the flush goroutine exits
}

// NewAccessLogger creates a new access logger.
// udpTimeout controls how long a UDP session is kept alive without traffic before being ended.
func NewAccessLogger(udpTimeout time.Duration) *AccessLogger {
	al := &AccessLogger{
		sessions:          make(map[string]*AccessSession),
		udpSessions:       make(map[udpSessionKey]*AccessSession),
		completedSessions: make([]*AccessSession, 0),
		udpTimeout:        udpTimeout,
		stopCh:            make(chan struct{}),
		flushDone:         make(chan struct{}),
	}
	go al.backgroundLoop()
	return al
}

// SetSendFunc sets the callback used to send compressed access log batches
// to the server. This can be called after construction once the websocket
// client is available.
func (al *AccessLogger) SetSendFunc(fn SendFunc) {
	al.mu.Lock()
	defer al.mu.Unlock()
	al.sendFn = fn
}

// generateSessionID creates a random session identifier
func generateSessionID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// StartTCPSession logs the start of a TCP session and returns a session ID.
func (al *AccessLogger) StartTCPSession(resourceID int, srcAddr, dstAddr string) string {
	sessionID := generateSessionID()
	now := time.Now()

	session := &AccessSession{
		SessionID:  sessionID,
		ResourceID: resourceID,
		SourceAddr: srcAddr,
		DestAddr:   dstAddr,
		Protocol:   "tcp",
		StartedAt:  now,
	}

	al.mu.Lock()
	al.sessions[sessionID] = session
	al.mu.Unlock()

	logger.Info("ACCESS START session=%s resource=%d proto=tcp src=%s dst=%s time=%s",
		sessionID, resourceID, srcAddr, dstAddr, now.Format(time.RFC3339))

	return sessionID
}

// EndTCPSession logs the end of a TCP session and queues it for sending.
func (al *AccessLogger) EndTCPSession(sessionID string) {
	now := time.Now()

	al.mu.Lock()
	session, ok := al.sessions[sessionID]
	if ok {
		session.EndedAt = now
		delete(al.sessions, sessionID)
		al.completedSessions = append(al.completedSessions, session)
	}
	shouldFlush := len(al.completedSessions) >= maxBufferedSessions
	al.mu.Unlock()

	if ok {
		duration := now.Sub(session.StartedAt)
		logger.Info("ACCESS END session=%s resource=%d proto=tcp src=%s dst=%s started=%s ended=%s duration=%s",
			sessionID, session.ResourceID, session.SourceAddr, session.DestAddr,
			session.StartedAt.Format(time.RFC3339), now.Format(time.RFC3339), duration)
	}

	if shouldFlush {
		al.flush()
	}
}

// TrackUDPSession starts or returns an existing UDP session. Returns the session ID.
func (al *AccessLogger) TrackUDPSession(resourceID int, srcAddr, dstAddr string) string {
	key := udpSessionKey{
		srcAddr:  srcAddr,
		dstAddr:  dstAddr,
		protocol: "udp",
	}

	al.mu.Lock()
	defer al.mu.Unlock()

	if existing, ok := al.udpSessions[key]; ok {
		return existing.SessionID
	}

	sessionID := generateSessionID()
	now := time.Now()

	session := &AccessSession{
		SessionID:  sessionID,
		ResourceID: resourceID,
		SourceAddr: srcAddr,
		DestAddr:   dstAddr,
		Protocol:   "udp",
		StartedAt:  now,
	}

	al.sessions[sessionID] = session
	al.udpSessions[key] = session

	logger.Info("ACCESS START session=%s resource=%d proto=udp src=%s dst=%s time=%s",
		sessionID, resourceID, srcAddr, dstAddr, now.Format(time.RFC3339))

	return sessionID
}

// EndUDPSession ends a UDP session and queues it for sending.
func (al *AccessLogger) EndUDPSession(sessionID string) {
	now := time.Now()

	al.mu.Lock()
	session, ok := al.sessions[sessionID]
	if ok {
		session.EndedAt = now
		delete(al.sessions, sessionID)
		key := udpSessionKey{
			srcAddr:  session.SourceAddr,
			dstAddr:  session.DestAddr,
			protocol: "udp",
		}
		delete(al.udpSessions, key)
		al.completedSessions = append(al.completedSessions, session)
	}
	shouldFlush := len(al.completedSessions) >= maxBufferedSessions
	al.mu.Unlock()

	if ok {
		duration := now.Sub(session.StartedAt)
		logger.Info("ACCESS END session=%s resource=%d proto=udp src=%s dst=%s started=%s ended=%s duration=%s",
			sessionID, session.ResourceID, session.SourceAddr, session.DestAddr,
			session.StartedAt.Format(time.RFC3339), now.Format(time.RFC3339), duration)
	}

	if shouldFlush {
		al.flush()
	}
}

// backgroundLoop handles periodic flushing and stale session reaping.
func (al *AccessLogger) backgroundLoop() {
	defer close(al.flushDone)

	flushTicker := time.NewTicker(flushInterval)
	defer flushTicker.Stop()

	reapTicker := time.NewTicker(30 * time.Second)
	defer reapTicker.Stop()

	for {
		select {
		case <-al.stopCh:
			return
		case <-flushTicker.C:
			al.flush()
		case <-reapTicker.C:
			al.reapStaleSessions()
		}
	}
}

// reapStaleSessions cleans up UDP sessions that were not properly ended.
func (al *AccessLogger) reapStaleSessions() {
	al.mu.Lock()
	defer al.mu.Unlock()

	staleThreshold := time.Now().Add(-5 * time.Minute)

	for key, session := range al.udpSessions {
		if session.StartedAt.Before(staleThreshold) && session.EndedAt.IsZero() {
			now := time.Now()
			session.EndedAt = now
			duration := now.Sub(session.StartedAt)
			logger.Info("ACCESS END (reaped) session=%s resource=%d proto=udp src=%s dst=%s started=%s ended=%s duration=%s",
				session.SessionID, session.ResourceID, session.SourceAddr, session.DestAddr,
				session.StartedAt.Format(time.RFC3339), now.Format(time.RFC3339), duration)
			al.completedSessions = append(al.completedSessions, session)
			delete(al.sessions, session.SessionID)
			delete(al.udpSessions, key)
		}
	}
}

// extractIP strips the port from an address string and returns just the IP.
// If the address has no port component it is returned as-is.
func extractIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// Might already be a bare IP
		return addr
	}
	return host
}

// consolidateSessions takes a slice of completed sessions and merges bursts of
// short-lived connections from the same source IP to the same destination into
// single higher-level session entries.
//
// The algorithm:
//  1. Group sessions by (sourceIP, destAddr, protocol, resourceID).
//  2. Within each group, sort by StartedAt.
//  3. Walk through the sorted list and merge consecutive sessions whose gap
//     (previous EndedAt → next StartedAt) is ≤ sessionGapThreshold.
//  4. For merged sessions the earliest StartedAt and latest EndedAt are kept,
//     bytes are summed, and ConnectionCount records how many raw connections
//     were folded in. If the merged connections used more than one source port,
//     SourceAddr is set to just the IP (port omitted).
//  5. Groups with fewer than minConnectionsToConsolidate members are passed
//     through unmodified.
func consolidateSessions(sessions []*AccessSession) []*AccessSession {
	if len(sessions) <= 1 {
		return sessions
	}

	// Group sessions by consolidation key
	groups := make(map[consolidationKey][]*AccessSession)
	for _, s := range sessions {
		key := consolidationKey{
			sourceIP:   extractIP(s.SourceAddr),
			destAddr:   s.DestAddr,
			protocol:   s.Protocol,
			resourceID: s.ResourceID,
		}
		groups[key] = append(groups[key], s)
	}

	result := make([]*AccessSession, 0, len(sessions))

	for key, group := range groups {
		// Small groups don't need consolidation
		if len(group) < minConnectionsToConsolidate {
			result = append(result, group...)
			continue
		}

		// Sort the group by start time so we can detect gaps
		sort.Slice(group, func(i, j int) bool {
			return group[i].StartedAt.Before(group[j].StartedAt)
		})

		// Walk through and merge runs that are within the gap threshold
		var merged []*AccessSession
		cur := cloneSession(group[0])
		cur.ConnectionCount = 1
		sourcePorts := make(map[string]struct{})
		sourcePorts[cur.SourceAddr] = struct{}{}

		for i := 1; i < len(group); i++ {
			s := group[i]

			// Determine the gap: from the latest end time we've seen so far to the
			// start of the next connection.
			gapRef := cur.EndedAt
			if gapRef.IsZero() {
				gapRef = cur.StartedAt
			}
			gap := s.StartedAt.Sub(gapRef)

			if gap <= sessionGapThreshold {
				// Merge into the current consolidated session
				cur.ConnectionCount++
				cur.BytesTx += s.BytesTx
				cur.BytesRx += s.BytesRx
				sourcePorts[s.SourceAddr] = struct{}{}

				// Extend EndedAt to the latest time
				endTime := s.EndedAt
				if endTime.IsZero() {
					endTime = s.StartedAt
				}
				if endTime.After(cur.EndedAt) {
					cur.EndedAt = endTime
				}
			} else {
				// Gap exceeded — finalize the current session and start a new one
				finalizeMergedSourceAddr(cur, key.sourceIP, sourcePorts)
				merged = append(merged, cur)

				cur = cloneSession(s)
				cur.ConnectionCount = 1
				sourcePorts = make(map[string]struct{})
				sourcePorts[s.SourceAddr] = struct{}{}
			}
		}

		// Finalize the last accumulated session
		finalizeMergedSourceAddr(cur, key.sourceIP, sourcePorts)
		merged = append(merged, cur)

		result = append(result, merged...)
	}

	return result
}

// cloneSession creates a shallow copy of an AccessSession.
func cloneSession(s *AccessSession) *AccessSession {
	cp := *s
	return &cp
}

// finalizeMergedSourceAddr sets the SourceAddr on a consolidated session.
// If multiple distinct source addresses (ports) were seen, the port is
// stripped and only the IP is kept so the log isn't misleading.
func finalizeMergedSourceAddr(s *AccessSession, sourceIP string, ports map[string]struct{}) {
	if len(ports) > 1 {
		// Multiple source ports — just report the IP
		s.SourceAddr = sourceIP
	}
	// Otherwise keep the original SourceAddr which already has ip:port
}

// flush drains the completed sessions buffer, consolidates bursts of
// short-lived connections, compresses with zlib, and sends via the SendFunc.
func (al *AccessLogger) flush() {
	al.mu.Lock()
	if len(al.completedSessions) == 0 {
		al.mu.Unlock()
		return
	}
	batch := al.completedSessions
	al.completedSessions = make([]*AccessSession, 0)
	sendFn := al.sendFn
	al.mu.Unlock()

	if sendFn == nil {
		logger.Debug("Access logger: no send function configured, discarding %d sessions", len(batch))
		return
	}

	// Consolidate bursts of short-lived connections into higher-level sessions
	originalCount := len(batch)
	batch = consolidateSessions(batch)
	if len(batch) != originalCount {
		logger.Info("Access logger: consolidated %d raw connections into %d sessions", originalCount, len(batch))
	}

	compressed, err := compressSessions(batch)
	if err != nil {
		logger.Error("Access logger: failed to compress %d sessions: %v", len(batch), err)
		return
	}

	if err := sendFn(compressed); err != nil {
		logger.Error("Access logger: failed to send %d sessions: %v", len(batch), err)
		// Re-queue the batch so we don't lose data
		al.mu.Lock()
		al.completedSessions = append(batch, al.completedSessions...)
		// Cap re-queued data to prevent unbounded growth if server is unreachable
		if len(al.completedSessions) > maxBufferedSessions*5 {
			dropped := len(al.completedSessions) - maxBufferedSessions*5
			al.completedSessions = al.completedSessions[:maxBufferedSessions*5]
			logger.Warn("Access logger: buffer overflow, dropped %d oldest sessions", dropped)
		}
		al.mu.Unlock()
		return
	}

	logger.Info("Access logger: sent %d sessions to server", len(batch))
}

// compressSessions JSON-encodes the sessions, compresses with zlib, and returns
// a base64-encoded string suitable for embedding in a JSON message.
func compressSessions(sessions []*AccessSession) (string, error) {
	jsonData, err := json.Marshal(sessions)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	w, err := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	if err != nil {
		return "", err
	}
	if _, err := w.Write(jsonData); err != nil {
		w.Close()
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// Close shuts down the background loop, ends all active sessions,
// and performs one final flush to send everything to the server.
func (al *AccessLogger) Close() {
	// Signal the background loop to stop
	select {
	case <-al.stopCh:
		// Already closed
		return
	default:
		close(al.stopCh)
	}

	// Wait for the background loop to exit so we don't race on flush
	<-al.flushDone

	al.mu.Lock()
	now := time.Now()

	// End all active sessions and move them to the completed buffer
	for _, session := range al.sessions {
		if session.EndedAt.IsZero() {
			session.EndedAt = now
			duration := now.Sub(session.StartedAt)
			logger.Info("ACCESS END (shutdown) session=%s resource=%d proto=%s src=%s dst=%s started=%s ended=%s duration=%s",
				session.SessionID, session.ResourceID, session.Protocol, session.SourceAddr, session.DestAddr,
				session.StartedAt.Format(time.RFC3339), now.Format(time.RFC3339), duration)
			al.completedSessions = append(al.completedSessions, session)
		}
	}

	al.sessions = make(map[string]*AccessSession)
	al.udpSessions = make(map[udpSessionKey]*AccessSession)
	al.mu.Unlock()

	// Final flush to send all remaining sessions to the server
	al.flush()
}