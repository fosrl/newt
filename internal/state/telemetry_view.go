package state

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/fosrl/newt/internal/telemetry"
)

// TelemetryView is a minimal, thread-safe implementation to feed observables.
// Since one Newt process represents one site, we expose a single logical site.
// site_id is a resource attribute, so we do not emit per-site labels here.
type TelemetryView struct {
	online     atomic.Bool
	lastHBUnix atomic.Int64 // unix seconds
	// per-tunnel sessions
	sessMu   sync.RWMutex
	sessions map[string]*atomic.Int64
}

var (
	globalView atomic.Pointer[TelemetryView]
)

// Global returns a singleton TelemetryView.
func Global() *TelemetryView {
	if v := globalView.Load(); v != nil { return v }
	v := &TelemetryView{ sessions: make(map[string]*atomic.Int64) }
	globalView.Store(v)
	telemetry.RegisterStateView(v)
	return v
}

// Instrumentation helpers
func (v *TelemetryView) IncSessions(tunnelID string) {
	v.sessMu.Lock(); defer v.sessMu.Unlock()
	c := v.sessions[tunnelID]
	if c == nil { c = &atomic.Int64{}; v.sessions[tunnelID] = c }
	c.Add(1)
}
func (v *TelemetryView) DecSessions(tunnelID string) {
	v.sessMu.Lock(); defer v.sessMu.Unlock()
	if c := v.sessions[tunnelID]; c != nil {
		c.Add(-1)
		if c.Load() <= 0 { delete(v.sessions, tunnelID) }
	}
}
func (v *TelemetryView) ClearTunnel(tunnelID string) {
	v.sessMu.Lock(); defer v.sessMu.Unlock()
	delete(v.sessions, tunnelID)
}
func (v *TelemetryView) SetOnline(b bool) { v.online.Store(b) }
func (v *TelemetryView) TouchHeartbeat() { v.lastHBUnix.Store(time.Now().Unix()) }

// --- telemetry.StateView interface ---

func (v *TelemetryView) ListSites() []string { return []string{"self"} }
func (v *TelemetryView) Online(_ string) (bool, bool) { return v.online.Load(), true }
func (v *TelemetryView) LastHeartbeat(_ string) (time.Time, bool) {
	sec := v.lastHBUnix.Load()
	if sec == 0 { return time.Time{}, false }
	return time.Unix(sec, 0), true
}
func (v *TelemetryView) ActiveSessions(_ string) (int64, bool) {
	// aggregated sessions (not used for per-tunnel gauge)
	v.sessMu.RLock(); defer v.sessMu.RUnlock()
	var sum int64
	for _, c := range v.sessions { if c != nil { sum += c.Load() } }
	return sum, true
}

// Extended accessor used by telemetry callback to publish per-tunnel samples.
func (v *TelemetryView) SessionsByTunnel() map[string]int64 {
	v.sessMu.RLock(); defer v.sessMu.RUnlock()
	out := make(map[string]int64, len(v.sessions))
	for id, c := range v.sessions { if c != nil && c.Load() > 0 { out[id] = c.Load() } }
	return out
}

