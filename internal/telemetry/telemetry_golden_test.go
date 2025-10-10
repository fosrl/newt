package telemetry

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Golden test that /metrics contains expected metric names.
func TestMetricsGoldenContains(t *testing.T) {
	ctx := context.Background()
	resetMetricsForTest()
	t.Setenv("NEWT_METRICS_INCLUDE_SITE_LABELS", "true")
	cfg := Config{ServiceName: "newt", PromEnabled: true, AdminAddr: "127.0.0.1:0", BuildVersion: "test"}
	tel, err := Init(ctx, cfg)
	if err != nil {
		t.Fatalf("telemetry init error: %v", err)
	}
	defer func() { _ = tel.Shutdown(context.Background()) }()

	if tel.PrometheusHandler == nil {
		t.Fatalf("prom handler nil")
	}
	ts := httptest.NewServer(tel.PrometheusHandler)
	defer ts.Close()

	// Trigger counters to ensure they appear in the scrape
	IncConnAttempt(ctx, "websocket", "success")
	IncWSReconnect(ctx, "io_error")
	IncProxyConnectionEvent(ctx, "", "tcp", ProxyConnectionOpened)
	if tel.MeterProvider != nil {
		_ = tel.MeterProvider.ForceFlush(ctx)
	}
	time.Sleep(100 * time.Millisecond)

	var body string
	for i := 0; i < 5; i++ {
		resp, err := http.Get(ts.URL)
		if err != nil {
			t.Fatalf("GET metrics failed: %v", err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		body = string(b)
		if strings.Contains(body, "newt_connection_attempts_total") {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	f, err := os.Open(filepath.Join("testdata", "expected_contains.golden"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		needle := strings.TrimSpace(s.Text())
		if needle == "" {
			continue
		}
		if !strings.Contains(body, needle) {
			t.Fatalf("expected metrics body to contain %q. body=\n%s", needle, body)
		}
	}
	if err := s.Err(); err != nil {
		t.Fatalf("scan golden: %v", err)
	}
}
