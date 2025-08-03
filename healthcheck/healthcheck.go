package healthcheck

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Status represents the health status of a target
type Status int

const (
	StatusUnknown Status = iota
	StatusHealthy
	StatusUnhealthy
)

func (s Status) String() string {
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
	ID                string            `json:"id"`
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
}

// Target represents a health check target with its current status
type Target struct {
	Config     Config    `json:"config"`
	Status     Status    `json:"status"`
	LastCheck  time.Time `json:"lastCheck"`
	LastError  string    `json:"lastError,omitempty"`
	CheckCount int       `json:"checkCount"`
	ticker     *time.Ticker
	ctx        context.Context
	cancel     context.CancelFunc
}

// StatusChangeCallback is called when any target's status changes
type StatusChangeCallback func(targets map[string]*Target)

// Monitor manages health check targets and their monitoring
type Monitor struct {
	targets  map[string]*Target
	mutex    sync.RWMutex
	callback StatusChangeCallback
	client   *http.Client
}

// NewMonitor creates a new health check monitor
func NewMonitor(callback StatusChangeCallback) *Monitor {
	return &Monitor{
		targets:  make(map[string]*Target),
		callback: callback,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
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

	// Parse headers if provided as string
	if len(config.Headers) == 0 && config.Path != "" {
		// This is a simplified header parsing - in real use you might want more robust parsing
		config.Headers = make(map[string]string)
	}

	// Remove existing target if it exists
	if existing, exists := m.targets[config.ID]; exists {
		existing.cancel()
	}

	// Create new target
	ctx, cancel := context.WithCancel(context.Background())
	target := &Target{
		Config: config,
		Status: StatusUnknown,
		ctx:    ctx,
		cancel: cancel,
	}

	m.targets[config.ID] = target

	// Start monitoring if enabled
	if config.Enabled {
		go m.monitorTarget(target)
	}

	return nil
}

// RemoveTarget removes a health check target
func (m *Monitor) RemoveTarget(id string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	target, exists := m.targets[id]
	if !exists {
		return fmt.Errorf("target with id %s not found", id)
	}

	target.cancel()
	delete(m.targets, id)

	// Notify callback of status change
	if m.callback != nil {
		go m.callback(m.getAllTargets())
	}

	return nil
}

// GetTargets returns a copy of all targets
func (m *Monitor) GetTargets() map[string]*Target {
	return m.getAllTargets()
}

// getAllTargets returns a copy of all targets (internal method)
func (m *Monitor) getAllTargets() map[string]*Target {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	targets := make(map[string]*Target)
	for id, target := range m.targets {
		// Create a copy to avoid race conditions
		targetCopy := *target
		targets[id] = &targetCopy
	}
	return targets
}

// monitorTarget monitors a single target
func (m *Monitor) monitorTarget(target *Target) {
	// Initial check
	m.performHealthCheck(target)

	// Set up ticker based on current status
	interval := time.Duration(target.Config.Interval) * time.Second
	if target.Status == StatusUnhealthy {
		interval = time.Duration(target.Config.UnhealthyInterval) * time.Second
	}

	target.ticker = time.NewTicker(interval)
	defer target.ticker.Stop()

	for {
		select {
		case <-target.ctx.Done():
			return
		case <-target.ticker.C:
			oldStatus := target.Status
			m.performHealthCheck(target)

			// Update ticker interval if status changed
			newInterval := time.Duration(target.Config.Interval) * time.Second
			if target.Status == StatusUnhealthy {
				newInterval = time.Duration(target.Config.UnhealthyInterval) * time.Second
			}

			if newInterval != interval {
				target.ticker.Stop()
				target.ticker = time.NewTicker(newInterval)
				interval = newInterval
			}

			// Notify callback if status changed
			if oldStatus != target.Status && m.callback != nil {
				go m.callback(m.getAllTargets())
			}
		}
	}
}

// performHealthCheck performs a health check on a target
func (m *Monitor) performHealthCheck(target *Target) {
	target.CheckCount++
	target.LastCheck = time.Now()
	target.LastError = ""

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

	// Create request
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(target.Config.Timeout)*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, target.Config.Method, url, nil)
	if err != nil {
		target.Status = StatusUnhealthy
		target.LastError = fmt.Sprintf("failed to create request: %v", err)
		return
	}

	// Add headers
	for key, value := range target.Config.Headers {
		req.Header.Set(key, value)
	}

	// Perform request
	resp, err := m.client.Do(req)
	if err != nil {
		target.Status = StatusUnhealthy
		target.LastError = fmt.Sprintf("request failed: %v", err)
		return
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		target.Status = StatusHealthy
	} else {
		target.Status = StatusUnhealthy
		target.LastError = fmt.Sprintf("unhealthy status code: %d", resp.StatusCode)
	}
}

// Stop stops monitoring all targets
func (m *Monitor) Stop() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for _, target := range m.targets {
		target.cancel()
	}
	m.targets = make(map[string]*Target)
}

// EnableTarget enables monitoring for a specific target
func (m *Monitor) EnableTarget(id string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	target, exists := m.targets[id]
	if !exists {
		return fmt.Errorf("target with id %s not found", id)
	}

	if !target.Config.Enabled {
		target.Config.Enabled = true
		target.cancel() // Stop existing monitoring

		ctx, cancel := context.WithCancel(context.Background())
		target.ctx = ctx
		target.cancel = cancel

		go m.monitorTarget(target)
	}

	return nil
}

// DisableTarget disables monitoring for a specific target
func (m *Monitor) DisableTarget(id string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	target, exists := m.targets[id]
	if !exists {
		return fmt.Errorf("target with id %s not found", id)
	}

	if target.Config.Enabled {
		target.Config.Enabled = false
		target.cancel()
		target.Status = StatusUnknown

		// Notify callback of status change
		if m.callback != nil {
			go m.callback(m.getAllTargets())
		}
	}

	return nil
}
