package telemetry

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Smoke test that /metrics contains at least one newt_* metric when Prom exporter is enabled.
func TestMetricsSmoke(t *testing.T) {
	ctx := context.Background()
	resetMetricsForTest()
	t.Setenv("NEWT_METRICS_INCLUDE_SITE_LABELS", "true")
	cfg := Config{
		ServiceName:          "newt",
		PromEnabled:          true,
		OTLPEnabled:          false,
		AdminAddr:            "127.0.0.1:0",
		BuildVersion:         "test",
		BuildCommit:          "deadbeef",
		MetricExportInterval: 5 * time.Second,
	}
	tel, err := Init(ctx, cfg)
	if err != nil {
		t.Fatalf("telemetry init error: %v", err)
	}
	defer func() { _ = tel.Shutdown(context.Background()) }()

	// Serve the Prom handler on a test server
	if tel.PrometheusHandler == nil {
		t.Fatalf("Prometheus handler nil; PromEnabled should enable it")
	}
	ts := httptest.NewServer(tel.PrometheusHandler)
	defer ts.Close()

	// Record a simple metric and then fetch /metrics
	IncConnAttempt(ctx, "websocket", "success")
	if tel.MeterProvider != nil {
		_ = tel.MeterProvider.ForceFlush(ctx)
	}
	// Give the exporter a tick to collect
	time.Sleep(100 * time.Millisecond)

	var body string
	for i := 0; i < 5; i++ {
		resp, err := http.Get(ts.URL)
		if err != nil {
			t.Fatalf("GET /metrics failed: %v", err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		body = string(b)
		if strings.Contains(body, "newt_connection_attempts_total") {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !strings.Contains(body, "newt_connection_attempts_total") {
		t.Fatalf("expected newt_connection_attempts_total in metrics, got:\n%s", body)
	}
}
