package healthcheck

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/fosrl/newt/logger"
)

// Health represents the health status of a target
type Health int

const (
	StatusUnknown Health = iota
	StatusHealthy
	StatusUnhealthy
)

func (s Health) String() string {
	switch s {
	case StatusHealthy:
		return "healthy"
	case StatusUnhealthy:
		return "unhealthy"
	default:
		return "unknown"
	}
}

// Config holds the health check configuration for a target
type Config struct {
	ID                int               `json:"id"`
	Enabled           bool              `json:"hcEnabled"`
	Path              string            `json:"hcPath"`
	Scheme            string            `json:"hcScheme"`
	Mode              string            `json:"hcMode"`
	Hostname          string            `json:"hcHostname"`
	Port              int               `json:"hcPort"`
	Interval          int               `json:"hcInterval"`          // in seconds
	UnhealthyInterval int               `json:"hcUnhealthyInterval"` // in seconds
	Timeout           int               `json:"hcTimeout"`           // in seconds
	Headers           map[string]string `json:"hcHeaders"`
	Method            string            `json:"hcMethod"`
	Status            int               `json:"hcStatus"` // HTTP status code
	TLSServerName     string            `json:"hcTlsServerName"`
}

// Target represents a health check target with its current status
type Target struct {
	Config     Config    `json:"config"`
	Status     Health    `json:"status"`
	LastCheck  time.Time `json:"lastCheck"`
	LastError  string    `json:"lastError,omitempty"`
	LastLatencyMs int64  `json:"latencyMs,omitempty"`
	CheckCount int       `json:"checkCount"`
	timer      *time.Timer
	ctx        context.Context
	cancel     context.CancelFunc
	client     *http.Client
}

// StatusChangeCallback is called when any target's status changes
type StatusChangeCallback func(targets map[int]*Target)

// Monitor manages health check targets and their monitoring
type Monitor struct {
	targets     map[int]*Target
	mutex       sync.RWMutex
	callback    StatusChangeCallback
	enforceCert bool
}

// NewMonitor creates a new health check monitor
func NewMonitor(callback StatusChangeCallback, enforceCert bool) *Monitor {
	logger.Debug("Creating new health check monitor with certificate enforcement: %t", enforceCert)

	return &Monitor{
		targets:     make(map[int]*Target),
		callback:    callback,
		enforceCert: enforceCert,
	}
}

// parseHeaders parses the headers string into a map
func parseHeaders(headersStr string) map[string]string {
	headers := make(map[string]string)
	if headersStr == "" {
		return headers
	}

	// Try to parse as JSON first
	if err := json.Unmarshal([]byte(headersStr), &headers); err == nil {
		return headers
	}

	// Fallback to simple key:value parsing
	pairs := strings.Split(headersStr, ",")
	for _, pair := range pairs {
		kv := strings.SplitN(strings.TrimSpace(pair), ":", 2)
		if len(kv) == 2 {
			headers[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}
	return headers
}

// AddTarget adds a new health check target
func (m *Monitor) AddTarget(config Config) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	logger.Info("Adding health check target: ID=%d, hostname=%s, port=%d, enabled=%t",
		config.ID, config.Hostname, config.Port, config.Enabled)

	return m.addTargetUnsafe(config)
}

// AddTargets adds multiple health check targets in bulk
func (m *Monitor) AddTargets(configs []Config) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	logger.Debug("Adding %d health check targets in bulk", len(configs))

	for _, config := range configs {
		if err := m.addTargetUnsafe(config); err != nil {
			logger.Error("Failed to add target %d: %v", config.ID, err)
			return fmt.Errorf("failed to add target %d: %v", config.ID, err)
		}
		logger.Debug("Successfully added target: ID=%d, hostname=%s", config.ID, config.Hostname)
	}

	// Don't notify callback immediately - let the initial health checks complete first
	// The callback will be triggered when the first health check results are available

	logger.Debug("Successfully added all %d health check targets", len(configs))
	return nil
}

// addTargetUnsafe adds a target without acquiring the mutex (internal method)
func (m *Monitor) addTargetUnsafe(config Config) error {
	// Set defaults
	if config.Scheme == "" {
		config.Scheme = "http"
	}
	if config.Mode == "" {
		config.Mode = "http"
	}
	if config.Method == "" {
		config.Method = "GET"
	}
	if config.Interval == 0 {
		config.Interval = 30
	}
	if config.UnhealthyInterval == 0 {
		config.UnhealthyInterval = 30
	}
	if config.Timeout == 0 {
		config.Timeout = 5
	}

	logger.Debug("Target %d configuration: scheme=%s, method=%s, interval=%ds, timeout=%ds",
		config.ID, config.Scheme, config.Method, config.Interval, config.Timeout)

	// Parse headers if provided as string
	if len(config.Headers) == 0 && config.Path != "" {
		// This is a simplified header parsing - in real use you might want more robust parsing
		config.Headers = make(map[string]string)
	}

	// Remove existing target if it exists
	if existing, exists := m.targets[config.ID]; exists {
		logger.Info("Replacing existing target with ID %d", config.ID)
		existing.cancel()
	}

	// Create new target
	ctx, cancel := context.WithCancel(context.Background())
	target := &Target{
		Config: config,
		Status: StatusUnknown,
		ctx:    ctx,
		cancel: cancel,
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					// Configure TLS settings based on certificate enforcement
					InsecureSkipVerify: !m.enforceCert,
					// Use SNI TLS header if present
					ServerName: config.TLSServerName,
				},
			},
		},
	}

	m.targets[config.ID] = target

	// Start monitoring if enabled
	if config.Enabled {
		logger.Info("Starting monitoring for target %d (%s:%d)", config.ID, config.Hostname, config.Port)
		go m.monitorTarget(target)
	} else {
		logger.Debug("Target %d added but monitoring is disabled", config.ID)
	}

	return nil
}

// RemoveTarget removes a health check target
func (m *Monitor) RemoveTarget(id int) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	target, exists := m.targets[id]
	if !exists {
		logger.Warn("Attempted to remove non-existent target with ID %d", id)
		return fmt.Errorf("target with id %d not found", id)
	}

	logger.Info("Removing health check target: ID=%d", id)
	target.cancel()
	delete(m.targets, id)

	// Notify callback of status change
	if m.callback != nil {
		go m.callback(m.GetTargets())
	}

	logger.Info("Successfully removed target %d", id)
	return nil
}

// RemoveTargets removes multiple health check targets
func (m *Monitor) RemoveTargets(ids []int) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	logger.Info("Removing %d health check targets", len(ids))
	var notFound []int

	for _, id := range ids {
		target, exists := m.targets[id]
		if !exists {
			notFound = append(notFound, id)
			logger.Warn("Target with ID %d not found during bulk removal", id)
			continue
		}

		logger.Debug("Removing target %d", id)
		target.cancel()
		delete(m.targets, id)
	}

	removedCount := len(ids) - len(notFound)
	logger.Info("Successfully removed %d targets", removedCount)

	// Notify callback of status change if any targets were removed
	if len(notFound) != len(ids) && m.callback != nil {
		go m.callback(m.GetTargets())
	}

	if len(notFound) > 0 {
		logger.Error("Some targets not found during removal: %v", notFound)
		return fmt.Errorf("targets not found: %v", notFound)
	}

	return nil
}

// RemoveTargetsByID is a convenience method that accepts either a single ID or multiple IDs
func (m *Monitor) RemoveTargetsByID(ids ...int) error {
	return m.RemoveTargets(ids)
}

// GetTargets returns a copy of all targets
func (m *Monitor) GetTargets() map[int]*Target {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.getAllTargetsUnsafe()
}

// getAllTargetsUnsafe returns a copy of all targets without acquiring the mutex (internal method)
func (m *Monitor) getAllTargetsUnsafe() map[int]*Target {
	targets := make(map[int]*Target)
	for id, target := range m.targets {
		// Create a copy to avoid race conditions
		targetCopy := *target
		targets[id] = &targetCopy
	}
	return targets
}

// getAllTargets returns a copy of all targets (deprecated, use GetTargets)
func (m *Monitor) getAllTargets() map[int]*Target {
	return m.GetTargets()
}

// monitorTarget monitors a single target
func (m *Monitor) monitorTarget(target *Target) {
	logger.Info("Starting health check monitoring for target %d (%s:%d)",
		target.Config.ID, target.Config.Hostname, target.Config.Port)

	// Initial check
	oldStatus := target.Status
	m.performHealthCheck(target)

	// Notify callback after initial check if status changed or if it's the first check
	if (oldStatus != target.Status || oldStatus == StatusUnknown) && m.callback != nil {
		logger.Info("Target %d initial status: %s", target.Config.ID, target.Status.String())
		go m.callback(m.GetTargets())
	}

	// Set up timer based on current status
	interval := time.Duration(target.Config.Interval) * time.Second
	if target.Status == StatusUnhealthy {
		interval = time.Duration(target.Config.UnhealthyInterval) * time.Second
	}

	logger.Debug("Target %d: initial check interval set to %v", target.Config.ID, interval)
	target.timer = time.NewTimer(interval)
	defer target.timer.Stop()

	for {
		select {
		case <-target.ctx.Done():
			logger.Info("Stopping health check monitoring for target %d", target.Config.ID)
			return
		case <-target.timer.C:
			oldStatus := target.Status
			m.performHealthCheck(target)

			// Update timer interval if status changed
			newInterval := time.Duration(target.Config.Interval) * time.Second
			if target.Status == StatusUnhealthy {
				newInterval = time.Duration(target.Config.UnhealthyInterval) * time.Second
			}

			if newInterval != interval {
				logger.Debug("Target %d: updating check interval from %v to %v due to status change",
					target.Config.ID, interval, newInterval)
				interval = newInterval
			}

			// Reset timer for next check with current interval
			target.timer.Reset(interval)

			// Notify callback if status changed
			if oldStatus != target.Status && m.callback != nil {
				logger.Info("Target %d status changed: %s -> %s",
					target.Config.ID, oldStatus.String(), target.Status.String())
				go m.callback(m.GetTargets())
			}
		}
	}
}

// performHealthCheck performs a health check on a target
func (m *Monitor) performHealthCheck(target *Target) {
	target.CheckCount++
	target.LastCheck = time.Now()
	target.LastError = ""
	target.LastLatencyMs = 0

	// Build URL
	url := fmt.Sprintf("%s://%s", target.Config.Scheme, target.Config.Hostname)
	if target.Config.Port > 0 {
		url = fmt.Sprintf("%s:%d", url, target.Config.Port)
	}
	if target.Config.Path != "" {
		if !strings.HasPrefix(target.Config.Path, "/") {
			url += "/"
		}
		url += target.Config.Path
	}

	logger.Debug("Target %d: performing health check %d to %s",
		target.Config.ID, target.CheckCount, url)

	if target.Config.Scheme == "https" {
		logger.Debug("Target %d: HTTPS health check with certificate enforcement: %t",
			target.Config.ID, m.enforceCert)
	}

	// Create request
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(target.Config.Timeout)*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, target.Config.Method, url, nil)
	if err != nil {
		target.Status = StatusUnhealthy
		target.LastError = fmt.Sprintf("failed to create request: %v", err)
		logger.Warn("Target %d: failed to create request: %v", target.Config.ID, err)
		return
	}

	// Add headers
	for key, value := range target.Config.Headers {
		// Handle Host header specially - it must be set on req.Host, not in headers
		if strings.EqualFold(key, "Host") {
			req.Host = value
		} else {
			req.Header.Set(key, value)
		}
	}

	// Perform request
	requestStart := time.Now()
	resp, err := target.client.Do(req)
	if err != nil {
		target.Status = StatusUnhealthy
		target.LastError = fmt.Sprintf("request failed: %v", err)
		logger.Warn("Target %d: health check failed: %v", target.Config.ID, err)
		return
	}
	defer resp.Body.Close()
	target.LastLatencyMs = time.Since(requestStart).Milliseconds()

	// Check response status
	var expectedStatus int
	if target.Config.Status > 0 {
		expectedStatus = target.Config.Status
	} else {
		expectedStatus = 0 // Use range check for 200-299
	}

	if expectedStatus > 0 {
		logger.Debug("Target %d: checking health status against expected code %d", target.Config.ID, expectedStatus)
		// Check for specific status code
		if resp.StatusCode == expectedStatus {
			target.Status = StatusHealthy
			logger.Debug("Target %d: health check passed (status: %d, expected: %d)", target.Config.ID, resp.StatusCode, expectedStatus)
		} else {
			target.Status = StatusUnhealthy
			target.LastError = fmt.Sprintf("unexpected status code: %d (expected: %d)", resp.StatusCode, expectedStatus)
			logger.Warn("Target %d: health check failed with status code %d (expected: %d)", target.Config.ID, resp.StatusCode, expectedStatus)
		}
	} else {
		// Check for 2xx range
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			target.Status = StatusHealthy
			logger.Debug("Target %d: health check passed (status: %d)", target.Config.ID, resp.StatusCode)
		} else {
			target.Status = StatusUnhealthy
			target.LastError = fmt.Sprintf("unhealthy status code: %d", resp.StatusCode)
			logger.Warn("Target %d: health check failed with status code %d", target.Config.ID, resp.StatusCode)
		}
	}
}

// Stop stops monitoring all targets
func (m *Monitor) Stop() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	targetCount := len(m.targets)
	logger.Info("Stopping health check monitor with %d targets", targetCount)

	for id, target := range m.targets {
		logger.Debug("Stopping monitoring for target %d", id)
		target.cancel()
	}
	m.targets = make(map[int]*Target)

	logger.Info("Health check monitor stopped")
}

// EnableTarget enables monitoring for a specific target
func (m *Monitor) EnableTarget(id int) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	target, exists := m.targets[id]
	if !exists {
		logger.Warn("Attempted to enable non-existent target with ID %d", id)
		return fmt.Errorf("target with id %d not found", id)
	}

	if !target.Config.Enabled {
		logger.Info("Enabling health check monitoring for target %d", id)
		target.Config.Enabled = true
		target.cancel() // Stop existing monitoring

		ctx, cancel := context.WithCancel(context.Background())
		target.ctx = ctx
		target.cancel = cancel

		go m.monitorTarget(target)
	} else {
		logger.Debug("Target %d is already enabled", id)
	}

	return nil
}

// DisableTarget disables monitoring for a specific target
func (m *Monitor) DisableTarget(id int) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	target, exists := m.targets[id]
	if !exists {
		logger.Warn("Attempted to disable non-existent target with ID %d", id)
		return fmt.Errorf("target with id %d not found", id)
	}

	if target.Config.Enabled {
		logger.Info("Disabling health check monitoring for target %d", id)
		target.Config.Enabled = false
		target.cancel()
		target.Status = StatusUnknown

		// Notify callback of status change
		if m.callback != nil {
			go m.callback(m.GetTargets())
		}
	} else {
		logger.Debug("Target %d is already disabled", id)
	}

	return nil
}
