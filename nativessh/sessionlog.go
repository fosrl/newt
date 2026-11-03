package nativessh

import (
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/fosrl/newt/logger"
)

const (
	// sessionLogFlushInterval is how often buffered SSH session activity is
	// sent to the server.
	sessionLogFlushInterval = 60 * time.Second

	// maxPendingCommands is the number of buffered commands that forces an
	// early flush.
	maxPendingCommands = 500

	// maxRetryRecords caps how many unsent session records are kept around
	// while the server is unreachable.
	maxRetryRecords = 1000

	// maxCommandBytes caps the length of a single recorded command.
	maxCommandBytes = 4096
)

// Channel types recorded alongside each command.
const (
	ChannelShell = "shell"
	ChannelExec  = "exec"
)

// Transports a session can arrive over.
const (
	// TransportSSH is a connection to the native SSH server.
	TransportSSH = "ssh"
	// TransportBrowser is a browser terminal served by the browser gateway.
	TransportBrowser = "browser"
)

// Authentication methods reported in session logs.
const (
	AuthMethodPublicKey   = "publickey"
	AuthMethodCertificate = "certificate"
	AuthMethodPassword    = "password"
)

// AuthResult records how a user authenticated, for session logging.
type AuthResult struct {
	Method         string
	KeyFingerprint string
	CertKeyID      string
	CertPrincipals []string
}

// SendFunc is a callback that sends compressed SSH session log data to the
// server. The data is a base64-encoded zlib-compressed JSON array of
// SessionRecord objects.
type SendFunc func(data string) error

// CommandRecord is a single command run during an SSH session.
type CommandRecord struct {
	Command   string    `json:"command"`
	Channel   string    `json:"channel"`
	Timestamp time.Time `json:"timestamp"`
	// Inexact is set for interactive lines that were edited with history
	// recall or tab completion, so the reconstructed text may not match
	// what the shell actually ran.
	Inexact bool `json:"inexact,omitempty"`
}

// SessionInfo describes an authenticated SSH connection.
type SessionInfo struct {
	SourceAddr string
	DestAddr   string
	Username   string
	Transport  string
	Auth       AuthResult
}

// SessionRecord is the wire format for one SSH session. A long-running
// session is sent once per flush with only the commands recorded since the
// previous flush; the server merges records by SessionID.
type SessionRecord struct {
	SessionID      string          `json:"sessionId"`
	SourceAddr     string          `json:"sourceAddr"`
	DestAddr       string          `json:"destAddr"`
	Username       string          `json:"username"`
	Transport      string          `json:"transport"`
	AuthMethod     string          `json:"authMethod"`
	KeyFingerprint string          `json:"keyFingerprint,omitempty"`
	CertKeyID      string          `json:"certKeyId,omitempty"`
	CertPrincipals []string        `json:"certPrincipals,omitempty"`
	StartedAt      time.Time       `json:"startedAt"`
	EndedAt        *time.Time      `json:"endedAt,omitempty"`
	Commands       []CommandRecord `json:"commands"`
}

type trackedSession struct {
	record  SessionRecord // metadata only; Commands is always empty
	pending []CommandRecord
	ended   bool
	sent    bool // the session has been reported to the server at least once
}

// SessionLogger tracks SSH sessions and the commands run in them, and
// periodically flushes them to the server via a configurable SendFunc.
type SessionLogger struct {
	mu           sync.Mutex
	sessions     map[string]*trackedSession
	retry        []SessionRecord // records from failed sends, oldest first
	pendingCount int
	sendFn       SendFunc
	closed       bool
	flushMu      sync.Mutex // serialises flushes so batches are sent in order
	stopCh       chan struct{}
	flushDone    chan struct{}
}

// NewSessionLogger creates a SessionLogger that sends batches with sendFn.
func NewSessionLogger(sendFn SendFunc) *SessionLogger {
	l := &SessionLogger{
		sessions:  make(map[string]*trackedSession),
		sendFn:    sendFn,
		stopCh:    make(chan struct{}),
		flushDone: make(chan struct{}),
	}
	go l.backgroundLoop()
	return l
}

// Session is a handle for recording activity on one SSH connection. A nil
// *Session is valid and records nothing.
type Session struct {
	l  *SessionLogger
	id string
}

func generateSSHSessionID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// StartSession begins tracking a new SSH session. It is safe to call on a
// nil *SessionLogger, in which case it returns a nil *Session.
func (l *SessionLogger) StartSession(info SessionInfo) *Session {
	if l == nil {
		return nil
	}
	id := generateSSHSessionID()
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.sessions[id] = &trackedSession{
		record: SessionRecord{
			SessionID:      id,
			SourceAddr:     info.SourceAddr,
			DestAddr:       info.DestAddr,
			Username:       info.Username,
			Transport:      info.Transport,
			AuthMethod:     info.Auth.Method,
			KeyFingerprint: info.Auth.KeyFingerprint,
			CertKeyID:      info.Auth.CertKeyID,
			CertPrincipals: info.Auth.CertPrincipals,
			StartedAt:      now,
		},
	}

	logger.Info("SSH SESSION START session=%s user=%s src=%s transport=%s auth=%s time=%s",
		id, info.Username, info.SourceAddr, info.Transport, info.Auth.Method, now.Format(time.RFC3339))

	return &Session{l: l, id: id}
}

// RecordCommand queues a command for the session.
func (s *Session) RecordCommand(channel, command string, inexact bool) {
	if s == nil {
		return
	}
	command = truncateCommand(strings.TrimSpace(command))
	if command == "" && !inexact {
		return
	}

	l := s.l
	l.mu.Lock()
	ts, ok := l.sessions[s.id]
	if !ok || ts.ended || l.closed {
		l.mu.Unlock()
		return
	}
	ts.pending = append(ts.pending, CommandRecord{
		Command:   command,
		Channel:   channel,
		Timestamp: time.Now(),
		Inexact:   inexact,
	})
	l.pendingCount++
	shouldFlush := l.pendingCount >= maxPendingCommands
	l.mu.Unlock()

	logger.Debug("SSH COMMAND session=%s channel=%s", s.id, channel)

	if shouldFlush {
		// Don't block the session's I/O on the network send.
		go l.flush()
	}
}

// ShellRecorder returns writers that capture the commands typed into an
// interactive shell on a PTY. Feed the client's input to input and the PTY's
// output to output (e.g. with io.TeeReader and io.MultiWriter); neither ever
// returns an error. hidden reports when the terminal is reading a password,
// typically PTYSession.InputHidden.
func (s *Session) ShellRecorder(hidden func() bool) (input, output io.Writer) {
	if s == nil {
		return io.Discard, io.Discard
	}
	rec := newLineRecorder(func(line string, inexact bool) {
		s.RecordCommand(ChannelShell, line, inexact)
	}, hidden)
	return rec, outputObserver{rec}
}

// End marks the session as finished. It is safe to call more than once.
func (s *Session) End() {
	if s == nil {
		return
	}
	now := time.Now()

	s.l.mu.Lock()
	ts, ok := s.l.sessions[s.id]
	if ok && !ts.ended {
		ts.ended = true
		ts.record.EndedAt = &now
	} else {
		ok = false
	}
	s.l.mu.Unlock()

	if ok {
		logger.Info("SSH SESSION END session=%s user=%s src=%s duration=%s",
			s.id, ts.record.Username, ts.record.SourceAddr, now.Sub(ts.record.StartedAt))
	}
}

// truncateCommand caps command at maxCommandBytes without splitting a UTF-8
// sequence, and replaces any invalid UTF-8 so the JSON stays well-formed.
func truncateCommand(command string) string {
	command = strings.ToValidUTF8(command, "�")
	if len(command) <= maxCommandBytes {
		return command
	}
	cut := maxCommandBytes
	for cut > 0 && !utf8.RuneStart(command[cut]) {
		cut--
	}
	return command[:cut]
}

func (l *SessionLogger) backgroundLoop() {
	defer close(l.flushDone)

	ticker := time.NewTicker(sessionLogFlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-l.stopCh:
			return
		case <-ticker.C:
			l.flush()
		}
	}
}

// flush sends every session with unsent activity (new commands, a new
// session that hasn't been reported yet, or a session that has ended).
// Ended sessions are dropped from tracking once collected. If the send
// fails the records are kept and retried on the next flush.
func (l *SessionLogger) flush() {
	l.flushMu.Lock()
	defer l.flushMu.Unlock()

	l.mu.Lock()
	batch := l.retry
	l.retry = nil
	for id, ts := range l.sessions {
		if len(ts.pending) == 0 && ts.sent && !ts.ended {
			continue
		}
		rec := ts.record
		rec.Commands = ts.pending
		if rec.Commands == nil {
			rec.Commands = []CommandRecord{}
		}
		batch = append(batch, rec)
		ts.pending = nil
		ts.sent = true
		if ts.ended {
			delete(l.sessions, id)
		}
	}
	l.pendingCount = 0
	sendFn := l.sendFn
	l.mu.Unlock()

	if len(batch) == 0 {
		return
	}

	if sendFn == nil {
		logger.Debug("SSH session logger: no send function configured, discarding %d sessions", len(batch))
		return
	}

	compressed, err := compressRecords(batch)
	if err != nil {
		logger.Error("SSH session logger: failed to compress %d sessions: %v", len(batch), err)
		return
	}

	if err := sendFn(compressed); err != nil {
		logger.Error("SSH session logger: failed to send %d sessions: %v", len(batch), err)
		l.mu.Lock()
		l.retry = append(batch, l.retry...)
		if len(l.retry) > maxRetryRecords {
			dropped := len(l.retry) - maxRetryRecords
			l.retry = l.retry[dropped:]
			logger.Warn("SSH session logger: buffer overflow, dropped %d oldest session records", dropped)
		}
		l.mu.Unlock()
		return
	}

	logger.Debug("SSH session logger: sent %d session records to server", len(batch))
}

// compressRecords JSON-encodes the records, compresses with zlib, and
// returns a base64-encoded string suitable for embedding in a JSON message.
func compressRecords(records []SessionRecord) (string, error) {
	jsonData, err := json.Marshal(records)
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

// Close stops the background loop, ends all active sessions, and performs
// a final flush so nothing is lost when newt exits.
func (l *SessionLogger) Close() {
	if l == nil {
		return
	}
	select {
	case <-l.stopCh:
		return
	default:
		close(l.stopCh)
	}
	<-l.flushDone

	now := time.Now()
	l.mu.Lock()
	l.closed = true
	for _, ts := range l.sessions {
		if !ts.ended {
			ts.ended = true
			ended := now
			ts.record.EndedAt = &ended
			logger.Info("SSH SESSION END (shutdown) session=%s user=%s src=%s duration=%s",
				ts.record.SessionID, ts.record.Username, ts.record.SourceAddr, now.Sub(ts.record.StartedAt))
		}
	}
	l.mu.Unlock()

	l.flush()
}
