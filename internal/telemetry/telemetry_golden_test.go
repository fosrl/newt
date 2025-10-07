package telemetry

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// Golden test that /metrics contains expected metric names.
func TestMetricsGoldenContains(t *testing.T) {
	ctx := context.Background()
cfg := Config{ServiceName: "newt", PromEnabled: true, AdminAddr: "127.0.0.1:0", BuildVersion: "test"}
	tel, err := Init(ctx, cfg)
	if err != nil { t.Fatalf("telemetry init error: %v", err) }
	defer func() { _ = tel.Shutdown(context.Background()) }()

	if tel.PrometheusHandler == nil { t.Fatalf("prom handler nil") }
	ts := httptest.NewServer(tel.PrometheusHandler)
	defer ts.Close()

	// Trigger a counter
	IncConnAttempt(ctx, "ignored", "websocket", "success")
	time.Sleep(100 * time.Millisecond)

	resp, err := http.Get(ts.URL)
	if err != nil { t.Fatalf("GET metrics failed: %v", err) }
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	body := string(b)

	f, err := os.Open("internal/telemetry/testdata/expected_contains.golden")
	if err != nil { t.Fatalf("read golden: %v", err) }
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		needle := strings.TrimSpace(s.Text())
		if needle == "" { continue }
		if !strings.Contains(body, needle) {
			t.Fatalf("expected metrics body to contain %q. body=\n%s", needle, body)
		}
	}
	if err := s.Err(); err != nil { t.Fatalf("scan golden: %v", err) }
}

