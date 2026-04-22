package netstack2

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"sync"
	"time"

	"github.com/fosrl/newt/logger"
)

// HTTPRequestLog represents a single HTTP/HTTPS request proxied through the handler.
type HTTPRequestLog struct {
	RequestID  string    `json:"requestId"`
	ResourceID int       `json:"resourceId"`
	Timestamp  time.Time `json:"timestamp"`
	Method     string    `json:"method"`
	Scheme     string    `json:"scheme"`
	Host       string    `json:"host"`
	Path       string    `json:"path"`
	RawQuery   string    `json:"rawQuery,omitempty"`
	UserAgent  string    `json:"userAgent,omitempty"`
	SourceAddr string    `json:"sourceAddr"`
	TLS        bool      `json:"tls"`
}

// HTTPRequestLogger buffers HTTP request logs and periodically flushes them
// to the server via a configurable SendFunc.
type HTTPRequestLogger struct {
	mu        sync.Mutex
	pending   []HTTPRequestLog
	sendFn    SendFunc
	stopCh    chan struct{}
	flushDone chan struct{}
}

// NewHTTPRequestLogger creates a new HTTPRequestLogger and starts its background flush loop.
func NewHTTPRequestLogger() *HTTPRequestLogger {
	rl := &HTTPRequestLogger{
		pending:   make([]HTTPRequestLog, 0),
		stopCh:    make(chan struct{}),
		flushDone: make(chan struct{}),
	}
	go rl.backgroundLoop()
	return rl
}

// SetSendFunc sets the callback used to send compressed HTTP request log batches
// to the server. This can be called after construction once the websocket
// client is available.
func (rl *HTTPRequestLogger) SetSendFunc(fn SendFunc) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.sendFn = fn
}

// LogRequest adds an HTTP request log entry to the buffer. If the buffer
// reaches maxBufferedSessions entries a flush is triggered immediately.
func (rl *HTTPRequestLogger) LogRequest(log HTTPRequestLog) {
	if log.RequestID == "" {
		log.RequestID = generateSessionID()
	}

	rl.mu.Lock()
	rl.pending = append(rl.pending, log)
	shouldFlush := len(rl.pending) >= maxBufferedSessions
	rl.mu.Unlock()

	if shouldFlush {
		rl.flush()
	}
}

// backgroundLoop handles periodic flushing of buffered request logs.
func (rl *HTTPRequestLogger) backgroundLoop() {
	defer close(rl.flushDone)

	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-rl.stopCh:
			return
		case <-ticker.C:
			rl.flush()
		}
	}
}

// flush drains the pending buffer, compresses with zlib, and sends via the SendFunc.
// On send failure the batch is re-queued, capped at maxBufferedSessions*5 entries
// to prevent unbounded memory growth when the server is unreachable.
func (rl *HTTPRequestLogger) flush() {
	rl.mu.Lock()
	if len(rl.pending) == 0 {
		rl.mu.Unlock()
		return
	}
	batch := rl.pending
	rl.pending = make([]HTTPRequestLog, 0)
	sendFn := rl.sendFn
	rl.mu.Unlock()

	if sendFn == nil {
		logger.Debug("HTTP request logger: no send function configured, discarding %d requests", len(batch))
		return
	}

	compressed, err := compressRequestLogs(batch)
	if err != nil {
		logger.Error("HTTP request logger: failed to compress %d requests: %v", len(batch), err)
		return
	}

	if err := sendFn(compressed); err != nil {
		logger.Error("HTTP request logger: failed to send %d requests: %v", len(batch), err)
		// Re-queue the batch so we don't lose data
		rl.mu.Lock()
		rl.pending = append(batch, rl.pending...)
		// Cap re-queued data to prevent unbounded growth if server is unreachable
		if len(rl.pending) > maxBufferedSessions*5 {
			dropped := len(rl.pending) - maxBufferedSessions*5
			rl.pending = rl.pending[:maxBufferedSessions*5]
			logger.Warn("HTTP request logger: buffer overflow, dropped %d oldest requests", dropped)
		}
		rl.mu.Unlock()
		return
	}

	logger.Info("HTTP request logger: sent %d requests to server", len(batch))
}

// compressRequestLogs JSON-encodes the request logs, compresses with zlib, and
// returns a base64-encoded string suitable for embedding in a JSON message.
func compressRequestLogs(logs []HTTPRequestLog) (string, error) {
	jsonData, err := json.Marshal(logs)
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

// Close shuts down the background loop and performs one final flush to send
// any remaining buffered requests to the server.
func (rl *HTTPRequestLogger) Close() {
	select {
	case <-rl.stopCh:
		// Already closed
		return
	default:
		close(rl.stopCh)
	}

	// Wait for the background loop to exit so we don't race on flush
	<-rl.flushDone

	rl.flush()
}