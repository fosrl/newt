package netstack2

import (
	"testing"
	"time"
)

func TestExtractIP(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		expected string
	}{
		{"ipv4 with port", "192.168.1.1:12345", "192.168.1.1"},
		{"ipv4 without port", "192.168.1.1", "192.168.1.1"},
		{"ipv6 with port", "[::1]:12345", "::1"},
		{"ipv6 without port", "::1", "::1"},
		{"empty string", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractIP(tt.addr)
			if result != tt.expected {
				t.Errorf("extractIP(%q) = %q, want %q", tt.addr, result, tt.expected)
			}
		})
	}
}

func TestConsolidateSessions_Empty(t *testing.T) {
	result := consolidateSessions(nil)
	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}

	result = consolidateSessions([]*AccessSession{})
	if len(result) != 0 {
		t.Errorf("expected empty slice, got %d items", len(result))
	}
}

func TestConsolidateSessions_SingleSession(t *testing.T) {
	now := time.Now()
	sessions := []*AccessSession{
		{
			SessionID:  "abc123",
			ResourceID: 1,
			SourceAddr: "10.0.0.1:5000",
			DestAddr:   "192.168.1.100:443",
			Protocol:   "tcp",
			StartedAt:  now,
			EndedAt:    now.Add(1 * time.Second),
		},
	}

	result := consolidateSessions(sessions)
	if len(result) != 1 {
		t.Fatalf("expected 1 session, got %d", len(result))
	}
	if result[0].SourceAddr != "10.0.0.1:5000" {
		t.Errorf("expected source addr preserved, got %q", result[0].SourceAddr)
	}
}

func TestConsolidateSessions_MergesBurstFromSameSourceIP(t *testing.T) {
	now := time.Now()
	sessions := []*AccessSession{
		{
			SessionID:  "s1",
			ResourceID: 1,
			SourceAddr: "10.0.0.1:5000",
			DestAddr:   "192.168.1.100:443",
			Protocol:   "tcp",
			StartedAt:  now,
			EndedAt:    now.Add(100 * time.Millisecond),
			BytesTx:    100,
			BytesRx:    200,
		},
		{
			SessionID:  "s2",
			ResourceID: 1,
			SourceAddr: "10.0.0.1:5001",
			DestAddr:   "192.168.1.100:443",
			Protocol:   "tcp",
			StartedAt:  now.Add(200 * time.Millisecond),
			EndedAt:    now.Add(300 * time.Millisecond),
			BytesTx:    150,
			BytesRx:    250,
		},
		{
			SessionID:  "s3",
			ResourceID: 1,
			SourceAddr: "10.0.0.1:5002",
			DestAddr:   "192.168.1.100:443",
			Protocol:   "tcp",
			StartedAt:  now.Add(400 * time.Millisecond),
			EndedAt:    now.Add(500 * time.Millisecond),
			BytesTx:    50,
			BytesRx:    75,
		},
	}

	result := consolidateSessions(sessions)
	if len(result) != 1 {
		t.Fatalf("expected 1 consolidated session, got %d", len(result))
	}

	s := result[0]
	if s.ConnectionCount != 3 {
		t.Errorf("expected ConnectionCount=3, got %d", s.ConnectionCount)
	}
	if s.SourceAddr != "10.0.0.1" {
		t.Errorf("expected source addr to be IP only (multiple ports), got %q", s.SourceAddr)
	}
	if s.DestAddr != "192.168.1.100:443" {
		t.Errorf("expected dest addr preserved, got %q", s.DestAddr)
	}
	if s.StartedAt != now {
		t.Errorf("expected StartedAt to be earliest time")
	}
	if s.EndedAt != now.Add(500*time.Millisecond) {
		t.Errorf("expected EndedAt to be latest time")
	}
	expectedTx := int64(300)
	expectedRx := int64(525)
	if s.BytesTx != expectedTx {
		t.Errorf("expected BytesTx=%d, got %d", expectedTx, s.BytesTx)
	}
	if s.BytesRx != expectedRx {
		t.Errorf("expected BytesRx=%d, got %d", expectedRx, s.BytesRx)
	}
}

func TestConsolidateSessions_SameSourcePortPreserved(t *testing.T) {
	now := time.Now()
	sessions := []*AccessSession{
		{
			SessionID:  "s1",
			ResourceID: 1,
			SourceAddr: "10.0.0.1:5000",
			DestAddr:   "192.168.1.100:443",
			Protocol:   "tcp",
			StartedAt:  now,
			EndedAt:    now.Add(100 * time.Millisecond),
		},
		{
			SessionID:  "s2",
			ResourceID: 1,
			SourceAddr: "10.0.0.1:5000",
			DestAddr:   "192.168.1.100:443",
			Protocol:   "tcp",
			StartedAt:  now.Add(200 * time.Millisecond),
			EndedAt:    now.Add(300 * time.Millisecond),
		},
	}

	result := consolidateSessions(sessions)
	if len(result) != 1 {
		t.Fatalf("expected 1 session, got %d", len(result))
	}
	if result[0].SourceAddr != "10.0.0.1:5000" {
		t.Errorf("expected source addr with port preserved when all ports are the same, got %q", result[0].SourceAddr)
	}
	if result[0].ConnectionCount != 2 {
		t.Errorf("expected ConnectionCount=2, got %d", result[0].ConnectionCount)
	}
}

func TestConsolidateSessions_GapSplitsSessions(t *testing.T) {
	now := time.Now()

	// First burst
	sessions := []*AccessSession{
		{
			SessionID:  "s1",
			ResourceID: 1,
			SourceAddr: "10.0.0.1:5000",
			DestAddr:   "192.168.1.100:443",
			Protocol:   "tcp",
			StartedAt:  now,
			EndedAt:    now.Add(100 * time.Millisecond),
		},
		{
			SessionID:  "s2",
			ResourceID: 1,
			SourceAddr: "10.0.0.1:5001",
			DestAddr:   "192.168.1.100:443",
			Protocol:   "tcp",
			StartedAt:  now.Add(200 * time.Millisecond),
			EndedAt:    now.Add(300 * time.Millisecond),
		},
		// Big gap here (10 seconds)
		{
			SessionID:  "s3",
			ResourceID: 1,
			SourceAddr: "10.0.0.1:5002",
			DestAddr:   "192.168.1.100:443",
			Protocol:   "tcp",
			StartedAt:  now.Add(10 * time.Second),
			EndedAt:    now.Add(10*time.Second + 100*time.Millisecond),
		},
		{
			SessionID:  "s4",
			ResourceID: 1,
			SourceAddr: "10.0.0.1:5003",
			DestAddr:   "192.168.1.100:443",
			Protocol:   "tcp",
			StartedAt:  now.Add(10*time.Second + 200*time.Millisecond),
			EndedAt:    now.Add(10*time.Second + 300*time.Millisecond),
		},
	}

	result := consolidateSessions(sessions)
	if len(result) != 2 {
		t.Fatalf("expected 2 consolidated sessions (gap split), got %d", len(result))
	}

	// Find the sessions by their start time
	var first, second *AccessSession
	for _, s := range result {
		if s.StartedAt.Equal(now) {
			first = s
		} else {
			second = s
		}
	}

	if first == nil || second == nil {
		t.Fatal("could not find both consolidated sessions")
	}

	if first.ConnectionCount != 2 {
		t.Errorf("first burst: expected ConnectionCount=2, got %d", first.ConnectionCount)
	}
	if second.ConnectionCount != 2 {
		t.Errorf("second burst: expected ConnectionCount=2, got %d", second.ConnectionCount)
	}
}

func TestConsolidateSessions_DifferentDestinationsNotMerged(t *testing.T) {
	now := time.Now()
	sessions := []*AccessSession{
		{
			SessionID:  "s1",
			ResourceID: 1,
			SourceAddr: "10.0.0.1:5000",
			DestAddr:   "192.168.1.100:443",
			Protocol:   "tcp",
			StartedAt:  now,
			EndedAt:    now.Add(100 * time.Millisecond),
		},
		{
			SessionID:  "s2",
			ResourceID: 1,
			SourceAddr: "10.0.0.1:5001",
			DestAddr:   "192.168.1.100:8080",
			Protocol:   "tcp",
			StartedAt:  now.Add(200 * time.Millisecond),
			EndedAt:    now.Add(300 * time.Millisecond),
		},
	}

	result := consolidateSessions(sessions)
	// Each goes to a different dest port so they should not be merged
	if len(result) != 2 {
		t.Fatalf("expected 2 sessions (different destinations), got %d", len(result))
	}
}

func TestConsolidateSessions_DifferentProtocolsNotMerged(t *testing.T) {
	now := time.Now()
	sessions := []*AccessSession{
		{
			SessionID:  "s1",
			ResourceID: 1,
			SourceAddr: "10.0.0.1:5000",
			DestAddr:   "192.168.1.100:443",
			Protocol:   "tcp",
			StartedAt:  now,
			EndedAt:    now.Add(100 * time.Millisecond),
		},
		{
			SessionID:  "s2",
			ResourceID: 1,
			SourceAddr: "10.0.0.1:5001",
			DestAddr:   "192.168.1.100:443",
			Protocol:   "udp",
			StartedAt:  now.Add(200 * time.Millisecond),
			EndedAt:    now.Add(300 * time.Millisecond),
		},
	}

	result := consolidateSessions(sessions)
	if len(result) != 2 {
		t.Fatalf("expected 2 sessions (different protocols), got %d", len(result))
	}
}

func TestConsolidateSessions_DifferentResourceIDsNotMerged(t *testing.T) {
	now := time.Now()
	sessions := []*AccessSession{
		{
			SessionID:  "s1",
			ResourceID: 1,
			SourceAddr: "10.0.0.1:5000",
			DestAddr:   "192.168.1.100:443",
			Protocol:   "tcp",
			StartedAt:  now,
			EndedAt:    now.Add(100 * time.Millisecond),
		},
		{
			SessionID:  "s2",
			ResourceID: 2,
			SourceAddr: "10.0.0.1:5001",
			DestAddr:   "192.168.1.100:443",
			Protocol:   "tcp",
			StartedAt:  now.Add(200 * time.Millisecond),
			EndedAt:    now.Add(300 * time.Millisecond),
		},
	}

	result := consolidateSessions(sessions)
	if len(result) != 2 {
		t.Fatalf("expected 2 sessions (different resource IDs), got %d", len(result))
	}
}

func TestConsolidateSessions_DifferentSourceIPsNotMerged(t *testing.T) {
	now := time.Now()
	sessions := []*AccessSession{
		{
			SessionID:  "s1",
			ResourceID: 1,
			SourceAddr: "10.0.0.1:5000",
			DestAddr:   "192.168.1.100:443",
			Protocol:   "tcp",
			StartedAt:  now,
			EndedAt:    now.Add(100 * time.Millisecond),
		},
		{
			SessionID:  "s2",
			ResourceID: 1,
			SourceAddr: "10.0.0.2:5001",
			DestAddr:   "192.168.1.100:443",
			Protocol:   "tcp",
			StartedAt:  now.Add(200 * time.Millisecond),
			EndedAt:    now.Add(300 * time.Millisecond),
		},
	}

	result := consolidateSessions(sessions)
	if len(result) != 2 {
		t.Fatalf("expected 2 sessions (different source IPs), got %d", len(result))
	}
}

func TestConsolidateSessions_OutOfOrderInput(t *testing.T) {
	now := time.Now()
	// Provide sessions out of chronological order to verify sorting
	sessions := []*AccessSession{
		{
			SessionID:  "s3",
			ResourceID: 1,
			SourceAddr: "10.0.0.1:5002",
			DestAddr:   "192.168.1.100:443",
			Protocol:   "tcp",
			StartedAt:  now.Add(400 * time.Millisecond),
			EndedAt:    now.Add(500 * time.Millisecond),
			BytesTx:    30,
		},
		{
			SessionID:  "s1",
			ResourceID: 1,
			SourceAddr: "10.0.0.1:5000",
			DestAddr:   "192.168.1.100:443",
			Protocol:   "tcp",
			StartedAt:  now,
			EndedAt:    now.Add(100 * time.Millisecond),
			BytesTx:    10,
		},
		{
			SessionID:  "s2",
			ResourceID: 1,
			SourceAddr: "10.0.0.1:5001",
			DestAddr:   "192.168.1.100:443",
			Protocol:   "tcp",
			StartedAt:  now.Add(200 * time.Millisecond),
			EndedAt:    now.Add(300 * time.Millisecond),
			BytesTx:    20,
		},
	}

	result := consolidateSessions(sessions)
	if len(result) != 1 {
		t.Fatalf("expected 1 consolidated session, got %d", len(result))
	}

	s := result[0]
	if s.ConnectionCount != 3 {
		t.Errorf("expected ConnectionCount=3, got %d", s.ConnectionCount)
	}
	if s.StartedAt != now {
		t.Errorf("expected StartedAt to be earliest time")
	}
	if s.EndedAt != now.Add(500*time.Millisecond) {
		t.Errorf("expected EndedAt to be latest time")
	}
	if s.BytesTx != 60 {
		t.Errorf("expected BytesTx=60, got %d", s.BytesTx)
	}
}

func TestConsolidateSessions_ExactlyAtGapThreshold(t *testing.T) {
	now := time.Now()
	sessions := []*AccessSession{
		{
			SessionID:  "s1",
			ResourceID: 1,
			SourceAddr: "10.0.0.1:5000",
			DestAddr:   "192.168.1.100:443",
			Protocol:   "tcp",
			StartedAt:  now,
			EndedAt:    now.Add(100 * time.Millisecond),
		},
		{
			// Starts exactly sessionGapThreshold after s1 ends — should still merge
			SessionID:  "s2",
			ResourceID: 1,
			SourceAddr: "10.0.0.1:5001",
			DestAddr:   "192.168.1.100:443",
			Protocol:   "tcp",
			StartedAt:  now.Add(100*time.Millisecond + sessionGapThreshold),
			EndedAt:    now.Add(100*time.Millisecond + sessionGapThreshold + 50*time.Millisecond),
		},
	}

	result := consolidateSessions(sessions)
	if len(result) != 1 {
		t.Fatalf("expected 1 session (gap exactly at threshold merges), got %d", len(result))
	}
	if result[0].ConnectionCount != 2 {
		t.Errorf("expected ConnectionCount=2, got %d", result[0].ConnectionCount)
	}
}

func TestConsolidateSessions_JustOverGapThreshold(t *testing.T) {
	now := time.Now()
	sessions := []*AccessSession{
		{
			SessionID:  "s1",
			ResourceID: 1,
			SourceAddr: "10.0.0.1:5000",
			DestAddr:   "192.168.1.100:443",
			Protocol:   "tcp",
			StartedAt:  now,
			EndedAt:    now.Add(100 * time.Millisecond),
		},
		{
			// Starts 1ms over the gap threshold after s1 ends — should split
			SessionID:  "s2",
			ResourceID: 1,
			SourceAddr: "10.0.0.1:5001",
			DestAddr:   "192.168.1.100:443",
			Protocol:   "tcp",
			StartedAt:  now.Add(100*time.Millisecond + sessionGapThreshold + 1*time.Millisecond),
			EndedAt:    now.Add(100*time.Millisecond + sessionGapThreshold + 50*time.Millisecond),
		},
	}

	result := consolidateSessions(sessions)
	if len(result) != 2 {
		t.Fatalf("expected 2 sessions (gap just over threshold splits), got %d", len(result))
	}
}

func TestConsolidateSessions_UDPSessions(t *testing.T) {
	now := time.Now()
	sessions := []*AccessSession{
		{
			SessionID:  "u1",
			ResourceID: 5,
			SourceAddr: "10.0.0.1:6000",
			DestAddr:   "192.168.1.100:53",
			Protocol:   "udp",
			StartedAt:  now,
			EndedAt:    now.Add(50 * time.Millisecond),
			BytesTx:    64,
			BytesRx:    512,
		},
		{
			SessionID:  "u2",
			ResourceID: 5,
			SourceAddr: "10.0.0.1:6001",
			DestAddr:   "192.168.1.100:53",
			Protocol:   "udp",
			StartedAt:  now.Add(100 * time.Millisecond),
			EndedAt:    now.Add(150 * time.Millisecond),
			BytesTx:    64,
			BytesRx:    256,
		},
		{
			SessionID:  "u3",
			ResourceID: 5,
			SourceAddr: "10.0.0.1:6002",
			DestAddr:   "192.168.1.100:53",
			Protocol:   "udp",
			StartedAt:  now.Add(200 * time.Millisecond),
			EndedAt:    now.Add(250 * time.Millisecond),
			BytesTx:    64,
			BytesRx:    128,
		},
	}

	result := consolidateSessions(sessions)
	if len(result) != 1 {
		t.Fatalf("expected 1 consolidated UDP session, got %d", len(result))
	}

	s := result[0]
	if s.Protocol != "udp" {
		t.Errorf("expected protocol=udp, got %q", s.Protocol)
	}
	if s.ConnectionCount != 3 {
		t.Errorf("expected ConnectionCount=3, got %d", s.ConnectionCount)
	}
	if s.SourceAddr != "10.0.0.1" {
		t.Errorf("expected source addr to be IP only, got %q", s.SourceAddr)
	}
	if s.BytesTx != 192 {
		t.Errorf("expected BytesTx=192, got %d", s.BytesTx)
	}
	if s.BytesRx != 896 {
		t.Errorf("expected BytesRx=896, got %d", s.BytesRx)
	}
}

func TestConsolidateSessions_MixedGroupsSomeConsolidatedSomeNot(t *testing.T) {
	now := time.Now()
	sessions := []*AccessSession{
		// Group 1: 3 connections to :443 from same IP — should consolidate
		{
			SessionID:  "s1",
			ResourceID: 1,
			SourceAddr: "10.0.0.1:5000",
			DestAddr:   "192.168.1.100:443",
			Protocol:   "tcp",
			StartedAt:  now,
			EndedAt:    now.Add(100 * time.Millisecond),
		},
		{
			SessionID:  "s2",
			ResourceID: 1,
			SourceAddr: "10.0.0.1:5001",
			DestAddr:   "192.168.1.100:443",
			Protocol:   "tcp",
			StartedAt:  now.Add(200 * time.Millisecond),
			EndedAt:    now.Add(300 * time.Millisecond),
		},
		{
			SessionID:  "s3",
			ResourceID: 1,
			SourceAddr: "10.0.0.1:5002",
			DestAddr:   "192.168.1.100:443",
			Protocol:   "tcp",
			StartedAt:  now.Add(400 * time.Millisecond),
			EndedAt:    now.Add(500 * time.Millisecond),
		},
		// Group 2: 1 connection to :8080 from different IP — should pass through
		{
			SessionID:  "s4",
			ResourceID: 2,
			SourceAddr: "10.0.0.2:6000",
			DestAddr:   "192.168.1.200:8080",
			Protocol:   "tcp",
			StartedAt:  now.Add(1 * time.Second),
			EndedAt:    now.Add(2 * time.Second),
		},
	}

	result := consolidateSessions(sessions)
	if len(result) != 2 {
		t.Fatalf("expected 2 sessions total, got %d", len(result))
	}

	var consolidated, passthrough *AccessSession
	for _, s := range result {
		if s.ConnectionCount > 1 {
			consolidated = s
		} else {
			passthrough = s
		}
	}

	if consolidated == nil {
		t.Fatal("expected a consolidated session")
	}
	if consolidated.ConnectionCount != 3 {
		t.Errorf("consolidated: expected ConnectionCount=3, got %d", consolidated.ConnectionCount)
	}

	if passthrough == nil {
		t.Fatal("expected a passthrough session")
	}
	if passthrough.SessionID != "s4" {
		t.Errorf("passthrough: expected session s4, got %s", passthrough.SessionID)
	}
}

func TestConsolidateSessions_OverlappingConnections(t *testing.T) {
	now := time.Now()
	// Connections that overlap in time (not sequential)
	sessions := []*AccessSession{
		{
			SessionID:  "s1",
			ResourceID: 1,
			SourceAddr: "10.0.0.1:5000",
			DestAddr:   "192.168.1.100:443",
			Protocol:   "tcp",
			StartedAt:  now,
			EndedAt:    now.Add(5 * time.Second),
			BytesTx:    100,
		},
		{
			SessionID:  "s2",
			ResourceID: 1,
			SourceAddr: "10.0.0.1:5001",
			DestAddr:   "192.168.1.100:443",
			Protocol:   "tcp",
			StartedAt:  now.Add(1 * time.Second),
			EndedAt:    now.Add(3 * time.Second),
			BytesTx:    200,
		},
		{
			SessionID:  "s3",
			ResourceID: 1,
			SourceAddr: "10.0.0.1:5002",
			DestAddr:   "192.168.1.100:443",
			Protocol:   "tcp",
			StartedAt:  now.Add(2 * time.Second),
			EndedAt:    now.Add(6 * time.Second),
			BytesTx:    300,
		},
	}

	result := consolidateSessions(sessions)
	if len(result) != 1 {
		t.Fatalf("expected 1 consolidated session, got %d", len(result))
	}

	s := result[0]
	if s.ConnectionCount != 3 {
		t.Errorf("expected ConnectionCount=3, got %d", s.ConnectionCount)
	}
	if s.StartedAt != now {
		t.Error("expected StartedAt to be earliest")
	}
	if s.EndedAt != now.Add(6*time.Second) {
		t.Error("expected EndedAt to be the latest end time")
	}
	if s.BytesTx != 600 {
		t.Errorf("expected BytesTx=600, got %d", s.BytesTx)
	}
}

func TestConsolidateSessions_DoesNotMutateOriginals(t *testing.T) {
	now := time.Now()
	s1 := &AccessSession{
		SessionID:  "s1",
		ResourceID: 1,
		SourceAddr: "10.0.0.1:5000",
		DestAddr:   "192.168.1.100:443",
		Protocol:   "tcp",
		StartedAt:  now,
		EndedAt:    now.Add(100 * time.Millisecond),
		BytesTx:    100,
	}
	s2 := &AccessSession{
		SessionID:  "s2",
		ResourceID: 1,
		SourceAddr: "10.0.0.1:5001",
		DestAddr:   "192.168.1.100:443",
		Protocol:   "tcp",
		StartedAt:  now.Add(200 * time.Millisecond),
		EndedAt:    now.Add(300 * time.Millisecond),
		BytesTx:    200,
	}

	// Save original values
	origS1Addr := s1.SourceAddr
	origS1Bytes := s1.BytesTx
	origS2Addr := s2.SourceAddr
	origS2Bytes := s2.BytesTx

	_ = consolidateSessions([]*AccessSession{s1, s2})

	if s1.SourceAddr != origS1Addr {
		t.Errorf("s1.SourceAddr was mutated: %q -> %q", origS1Addr, s1.SourceAddr)
	}
	if s1.BytesTx != origS1Bytes {
		t.Errorf("s1.BytesTx was mutated: %d -> %d", origS1Bytes, s1.BytesTx)
	}
	if s2.SourceAddr != origS2Addr {
		t.Errorf("s2.SourceAddr was mutated: %q -> %q", origS2Addr, s2.SourceAddr)
	}
	if s2.BytesTx != origS2Bytes {
		t.Errorf("s2.BytesTx was mutated: %d -> %d", origS2Bytes, s2.BytesTx)
	}
}

func TestConsolidateSessions_ThreeBurstsWithGaps(t *testing.T) {
	now := time.Now()

	sessions := make([]*AccessSession, 0, 9)

	// Burst 1: 3 connections at t=0
	for i := 0; i < 3; i++ {
		sessions = append(sessions, &AccessSession{
			SessionID:  generateSessionID(),
			ResourceID: 1,
			SourceAddr: "10.0.0.1:" + string(rune('A'+i)),
			DestAddr:   "192.168.1.100:443",
			Protocol:   "tcp",
			StartedAt:  now.Add(time.Duration(i*100) * time.Millisecond),
			EndedAt:    now.Add(time.Duration(i*100+50) * time.Millisecond),
		})
	}

	// Burst 2: 3 connections at t=20s (well past the 5s gap)
	for i := 0; i < 3; i++ {
		sessions = append(sessions, &AccessSession{
			SessionID:  generateSessionID(),
			ResourceID: 1,
			SourceAddr: "10.0.0.1:" + string(rune('D'+i)),
			DestAddr:   "192.168.1.100:443",
			Protocol:   "tcp",
			StartedAt:  now.Add(20*time.Second + time.Duration(i*100)*time.Millisecond),
			EndedAt:    now.Add(20*time.Second + time.Duration(i*100+50)*time.Millisecond),
		})
	}

	// Burst 3: 3 connections at t=40s
	for i := 0; i < 3; i++ {
		sessions = append(sessions, &AccessSession{
			SessionID:  generateSessionID(),
			ResourceID: 1,
			SourceAddr: "10.0.0.1:" + string(rune('G'+i)),
			DestAddr:   "192.168.1.100:443",
			Protocol:   "tcp",
			StartedAt:  now.Add(40*time.Second + time.Duration(i*100)*time.Millisecond),
			EndedAt:    now.Add(40*time.Second + time.Duration(i*100+50)*time.Millisecond),
		})
	}

	result := consolidateSessions(sessions)
	if len(result) != 3 {
		t.Fatalf("expected 3 consolidated sessions (3 bursts), got %d", len(result))
	}

	for _, s := range result {
		if s.ConnectionCount != 3 {
			t.Errorf("expected each burst to have ConnectionCount=3, got %d (started=%v)", s.ConnectionCount, s.StartedAt)
		}
	}
}

func TestFinalizeMergedSourceAddr(t *testing.T) {
	s := &AccessSession{SourceAddr: "10.0.0.1:5000"}
	ports := map[string]struct{}{"10.0.0.1:5000": {}}
	finalizeMergedSourceAddr(s, "10.0.0.1", ports)
	if s.SourceAddr != "10.0.0.1:5000" {
		t.Errorf("single port: expected addr preserved, got %q", s.SourceAddr)
	}

	s2 := &AccessSession{SourceAddr: "10.0.0.1:5000"}
	ports2 := map[string]struct{}{"10.0.0.1:5000": {}, "10.0.0.1:5001": {}}
	finalizeMergedSourceAddr(s2, "10.0.0.1", ports2)
	if s2.SourceAddr != "10.0.0.1" {
		t.Errorf("multiple ports: expected IP only, got %q", s2.SourceAddr)
	}
}

func TestCloneSession(t *testing.T) {
	original := &AccessSession{
		SessionID:  "test",
		ResourceID: 42,
		SourceAddr: "1.2.3.4:100",
		DestAddr:   "5.6.7.8:443",
		Protocol:   "tcp",
		BytesTx:    999,
	}

	clone := cloneSession(original)

	if clone == original {
		t.Error("clone should be a different pointer")
	}
	if clone.SessionID != original.SessionID {
		t.Error("clone should have same SessionID")
	}

	// Mutating clone should not affect original
	clone.BytesTx = 0
	clone.SourceAddr = "changed"
	if original.BytesTx != 999 {
		t.Error("mutating clone affected original BytesTx")
	}
	if original.SourceAddr != "1.2.3.4:100" {
		t.Error("mutating clone affected original SourceAddr")
	}
}