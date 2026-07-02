package proxy

import (
	"context"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fosrl/newt/internal/telemetry"
	"github.com/fosrl/newt/logger"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// TestRemoveTargetStopsAcceptLoop verifies that removing a TCP target on a
// netstack-backed ProxyManager causes the accept loop goroutine to actually
// stop retrying, instead of spinning forever logging
// "Error accepting TCP connection: ... endpoint is in invalid state".
func TestRemoveTargetStopsAcceptLoop(t *testing.T) {
	if _, err := telemetry.Init(context.Background(), telemetry.Config{ServiceName: "test"}); err != nil {
		t.Fatalf("telemetry.Init: %v", err)
	}

	logFile, err := os.CreateTemp(t.TempDir(), "newt-proxy-test-*.log")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer logFile.Close()
	logger.SetOutput(logFile)
	defer logger.SetOutput(os.Stdout)

	_, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr("100.64.0.1")},
		[]netip.Addr{},
		1420,
	)
	if err != nil {
		t.Fatalf("CreateNetTUN: %v", err)
	}

	pm := NewProxyManager(tnet)
	const listenIP = "100.64.0.1"
	const port = 53405

	if err := pm.AddTarget("tcp", listenIP, port, "127.0.0.1:9999"); err != nil {
		t.Fatalf("AddTarget: %v", err)
	}
	if err := pm.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	if err := pm.RemoveTarget("tcp", listenIP, port); err != nil {
		t.Fatalf("RemoveTarget: %v", err)
	}

	// If the bug is present, the accept loop spins every 100ms logging an
	// error forever. Sample the log twice, 400ms apart; a healthy accept
	// loop logs the error/close message once (or zero times) and then goes
	// silent, while the buggy loop keeps appending.
	time.Sleep(200 * time.Millisecond)
	countAt1 := countAcceptErrors(t, logFile.Name())

	time.Sleep(400 * time.Millisecond)
	countAt2 := countAcceptErrors(t, logFile.Name())

	t.Logf("accept-error-ish log lines: at 200ms=%d, at 600ms=%d", countAt1, countAt2)

	if countAt2 > countAt1 {
		t.Fatalf("accept loop kept logging after RemoveTarget (200ms=%d, 600ms=%d) -- it is spinning forever on the closed netstack listener instead of exiting", countAt1, countAt2)
	}
}

func countAcceptErrors(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "Error accepting TCP connection") {
			count++
		}
	}
	return count
}
