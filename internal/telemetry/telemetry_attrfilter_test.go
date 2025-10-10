package telemetry

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
)

// Test that disallowed attributes are filtered from the exposition.
func TestAttributeFilterDropsUnknownKeys(t *testing.T) {
        ctx := context.Background()
        resetMetricsForTest()
        t.Setenv("NEWT_METRICS_INCLUDE_SITE_LABELS", "true")
        cfg := Config{ServiceName: "newt", PromEnabled: true, AdminAddr: "127.0.0.1:0"}
	tel, err := Init(ctx, cfg)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer func() { _ = tel.Shutdown(context.Background()) }()

	if tel.PrometheusHandler == nil {
		t.Fatalf("prom handler nil")
	}
	ts := httptest.NewServer(tel.PrometheusHandler)
	defer ts.Close()

	// Add samples with disallowed attribute keys
	for _, k := range []string{"forbidden", "site_id", "host"} {
		set := attribute.NewSet(attribute.String(k, "x"))
		AddTunnelBytesSet(ctx, 123, set)
	}
	time.Sleep(50 * time.Millisecond)

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	body := string(b)
	if strings.Contains(body, "forbidden=") {
		t.Fatalf("unexpected forbidden attribute leaked into metrics: %s", body)
	}
	if !strings.Contains(body, "site_id=\"x\"") {
		t.Fatalf("expected allowed attribute site_id to be present in metrics, got: %s", body)
	}
}
