package newt

import (
	"encoding/json"
	"testing"
)

// On reconnect the registration payload is decoded into wgData. Go's json merges
// a JSON array into an existing slice element-by-element by position, and a JSON
// null is a no-op for a non-pointer int (Config.Status). So decoding into a REUSED
// wgData lets a target whose hcStatus is null inherit the stale expected code from
// whatever target previously occupied that slot when the rows arrive reordered.
//
// handleConnect must therefore decode into a FRESH WgData (see connect.go). These
// tests pin both halves: the hazard of reuse, and the correctness of a fresh decode.
func TestReconnectHealthCheckHcStatus(t *testing.T) {
	// Target 47 (MCP) expects 401; target 5 (/manifest.json) has no expected code
	// (null -> newt defaults to 2xx). The two connects return the rows in a
	// different order, which is what triggers the positional merge.
	firstConnect := `{"healthCheckTargets":[
		{"id":47,"hcStatus":401,"hcPath":"/api/mcp"},
		{"id":5,"hcStatus":null,"hcPath":"/manifest.json"}
	]}`
	reconnect := `{"healthCheckTargets":[
		{"id":5,"hcStatus":null,"hcPath":"/manifest.json"},
		{"id":47,"hcStatus":401,"hcPath":"/api/mcp"}
	]}`

	hcStatusOf := func(wg WgData, id int) (int, bool) {
		for i := range wg.HealthCheckTargets {
			if wg.HealthCheckTargets[i].ID == id {
				return wg.HealthCheckTargets[i].Status, true
			}
		}
		return 0, false
	}

	// Characterize the hazard: reusing the same WgData corrupts target 5.
	t.Run("reused wgData inherits stale hcStatus", func(t *testing.T) {
		var wg WgData
		if err := json.Unmarshal([]byte(firstConnect), &wg); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(reconnect), &wg); err != nil {
			t.Fatal(err)
		}
		got, ok := hcStatusOf(wg, 5)
		if !ok {
			t.Fatal("target 5 not found")
		}
		if got != 401 {
			t.Fatalf("expected the reuse hazard to yield stale 401 for target 5, got %d", got)
		}
	})

	// Verify the fix: decoding each payload into a fresh WgData (what handleConnect
	// does) keeps target 5 free of target 47's expected code.
	t.Run("fresh wgData per connect is correct", func(t *testing.T) {
		var wg WgData
		if err := json.Unmarshal([]byte(firstConnect), &wg); err != nil {
			t.Fatal(err)
		}
		var fresh WgData
		if err := json.Unmarshal([]byte(reconnect), &fresh); err != nil {
			t.Fatal(err)
		}
		wg = fresh
		got, ok := hcStatusOf(wg, 5)
		if !ok {
			t.Fatal("target 5 not found")
		}
		if got != 0 {
			t.Fatalf("target 5 hcStatus = %d, expected 0 (unset); it must not inherit target 47's 401", got)
		}
	})
}
