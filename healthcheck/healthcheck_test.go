package healthcheck

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestConcurrentStatusSnapshotNoRace exercises the monitor goroutine updating a
// target's status while status snapshots are taken concurrently (as the status
// reporter does via GetTargets). It must be run with -race; before the target
// lock was introduced, getAllTargetsUnsafe copied the whole Target struct while
// the monitor goroutine mutated it, which the race detector flagged.
func TestConcurrentStatusSnapshotNoRace(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	host, port := splitHostPort(t, srv.URL)

	m := NewMonitor(func(map[int]*Target) {}, false)
	defer m.Stop()

	cfg := Config{
		ID: 1, Enabled: true, Mode: "http", Scheme: "http",
		Hostname: host, Port: port, Path: "/", Status: 200,
		Interval: 1, Timeout: 2,
	}
	if err := m.AddTarget(cfg); err != nil {
		t.Fatal(err)
	}

	// Hammer the snapshot path while the monitor goroutine runs its checks.
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = m.GetTargets()
				}
			}
		}()
	}

	// Force repeated status field writes by re-adding (Replacing) the target,
	// mirroring the reconnect path that first surfaced the race.
	for i := 0; i < 20; i++ {
		_ = m.AddTarget(cfg)
		time.Sleep(20 * time.Millisecond)
	}

	close(stop)
	wg.Wait()

	if got := m.GetTargets(); got[1] == nil {
		t.Fatal("target 1 missing after churn")
	}
}

func splitHostPort(t *testing.T, rawURL string) (string, int) {
	t.Helper()
	hp := strings.TrimPrefix(rawURL, "http://")
	i := strings.LastIndex(hp, ":")
	if i < 0 {
		t.Fatalf("no port in %q", rawURL)
	}
	port, err := strconv.Atoi(hp[i+1:])
	if err != nil {
		t.Fatalf("bad port in %q: %v", rawURL, err)
	}
	return hp[:i], port
}
