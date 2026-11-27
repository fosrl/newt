package websocket

import "testing"

// A dropped config message must keep forcing a sync even after later messages
// (e.g. newt/wg/connect) store the server's current version again.
func TestPingConfigVersion_StaleSurvivesNewVersions(t *testing.T) {
	c := &Client{}
	c.setConfigVersion(4)
	c.MarkConfigStale()
	c.setConfigVersion(7)

	if got := c.pingConfigVersion(); got != -1 {
		t.Fatalf("stale ping version = %d, want -1", got)
	}

	c.ClearConfigStale()
	if got := c.pingConfigVersion(); got != 7 {
		t.Fatalf("ping version after sync = %d, want 7", got)
	}
}
