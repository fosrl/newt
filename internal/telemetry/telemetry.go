package telemetry

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	promclient "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/contrib/instrumentation/runtime"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/prometheus"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"google.golang.org/grpc/credentials"
)

// Config controls telemetry initialization via env flags.
//
// Defaults align with the issue requirements:
//   - Prometheus exporter enabled by default (/metrics)
//   - OTLP exporter disabled by default
//   - Durations in seconds, bytes in raw bytes
//   - Admin HTTP server address configurable (for mounting /metrics)
type Config struct {
	ServiceName    string
	ServiceVersion string

	// Optional resource attributes
	SiteID string
	Region string

	PromEnabled bool
	OTLPEnabled bool

	OTLPEndpoint string // host:port
	OTLPInsecure bool

	MetricExportInterval time.Duration
	AdminAddr            string // e.g.: ":2112"

	// Optional build info for newt_build_info metric
	BuildVersion string
	BuildCommit  string
}

// FromEnv reads configuration from environment variables.
//
//	NEWT_METRICS_PROMETHEUS_ENABLED (default: true)
//	NEWT_METRICS_OTLP_ENABLED       (default: false)
//	OTEL_EXPORTER_OTLP_ENDPOINT     (default: "localhost:4317")
//	OTEL_EXPORTER_OTLP_INSECURE     (default: true)
//	OTEL_METRIC_EXPORT_INTERVAL     (default: 15s)
//	OTEL_SERVICE_NAME               (default: "newt")
//	OTEL_SERVICE_VERSION            (default: "")
//	NEWT_ADMIN_ADDR                 (default: ":2112")
func FromEnv() Config {
	// Prefer explicit NEWT_* env vars, then fall back to OTEL_RESOURCE_ATTRIBUTES
	site := getenv("NEWT_SITE_ID", "")
	if site == "" {
		site = getenv("NEWT_ID", "")
	}
	region := os.Getenv("NEWT_REGION")
	if site == "" || region == "" {
		if ra := os.Getenv("OTEL_RESOURCE_ATTRIBUTES"); ra != "" {
			m := parseResourceAttributes(ra)
			if site == "" {
				site = m["site_id"]
			}
			if region == "" {
				region = m["region"]
			}
		}
	}
	return Config{
		ServiceName:          getenv("OTEL_SERVICE_NAME", "newt"),
		ServiceVersion:       os.Getenv("OTEL_SERVICE_VERSION"),
		SiteID:               site,
		Region:               region,
		PromEnabled:          getenv("NEWT_METRICS_PROMETHEUS_ENABLED", "true") == "true",
		OTLPEnabled:          getenv("NEWT_METRICS_OTLP_ENABLED", "false") == "true",
		OTLPEndpoint:         getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317"),
		OTLPInsecure:         getenv("OTEL_EXPORTER_OTLP_INSECURE", "true") == "true",
		MetricExportInterval: getdur("OTEL_METRIC_EXPORT_INTERVAL", 15*time.Second),
		AdminAddr:            getenv("NEWT_ADMIN_ADDR", "*********:2112"),
	}
}

// Setup holds initialized telemetry providers and (optionally) a /metrics handler.
// Call Shutdown when the process terminates to flush exporters.
type Setup struct {
	MeterProvider  *sdkmetric.MeterProvider
	TracerProvider *sdktrace.TracerProvider

	PrometheusHandler http.Handler // nil if Prometheus exporter disabled

	shutdowns []func(context.Context) error
}

// Init configures OpenTelemetry metrics and (optionally) tracing.
//
// It sets a global MeterProvider and TracerProvider, registers runtime instrumentation,
// installs recommended histogram views for *_latency_seconds, and returns a Setup with
// a Shutdown method to flush exporters.
func Init(ctx context.Context, cfg Config) (*Setup, error) {
	// Build resource with required attributes and only include optional ones when non-empty
	attrs := []attribute.KeyValue{
		semconv.ServiceName(cfg.ServiceName),
		semconv.ServiceVersion(cfg.ServiceVersion),
	}
	if cfg.SiteID != "" {
		attrs = append(attrs, attribute.String("site_id", cfg.SiteID))
	}
	if cfg.Region != "" {
		attrs = append(attrs, attribute.String("region", cfg.Region))
	}
	res, _ := resource.New(ctx,
		resource.WithFromEnv(),
		resource.WithHost(),
		resource.WithAttributes(attrs...),
	)

	// Seed global site/region for label propagation
	UpdateSiteInfo(cfg.SiteID, cfg.Region)

	s := &Setup{}

	// Build metric readers/exporters
	var readers []sdkmetric.Reader

	// Prometheus exporter exposes a native /metrics handler for scraping
	if cfg.PromEnabled {
		reg := promclient.NewRegistry()
		exp, err := prometheus.New(prometheus.WithRegisterer(reg))
		if err != nil {
			return nil, err
		}
		readers = append(readers, exp)
		s.PrometheusHandler = promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
	}

	// Optional OTLP metric exporter (gRPC)
	if cfg.OTLPEnabled {
		mopts := []otlpmetricgrpc.Option{otlpmetricgrpc.WithEndpoint(cfg.OTLPEndpoint)}
		// Headers support via OTEL_EXPORTER_OTLP_HEADERS (k=v,k2=v2)
		if hdrs := parseOTLPHeaders(os.Getenv("OTEL_EXPORTER_OTLP_HEADERS")); len(hdrs) > 0 {
			mopts = append(mopts, otlpmetricgrpc.WithHeaders(hdrs))
		}
		if cfg.OTLPInsecure {
			mopts = append(mopts, otlpmetricgrpc.WithInsecure())
		} else if certFile := os.Getenv("OTEL_EXPORTER_OTLP_CERTIFICATE"); certFile != "" {
			creds, cerr := credentials.NewClientTLSFromFile(certFile, "")
			if cerr == nil {
				mopts = append(mopts, otlpmetricgrpc.WithTLSCredentials(creds))
			}
		}
		mexp, err := otlpmetricgrpc.New(ctx, mopts...)
		if err != nil {
			return nil, err
		}
		readers = append(readers, sdkmetric.NewPeriodicReader(mexp, sdkmetric.WithInterval(cfg.MetricExportInterval)))
		s.shutdowns = append(s.shutdowns, mexp.Shutdown)
	}

	// Build provider options iteratively (WithReader is not variadic)
	var mpOpts []sdkmetric.Option
	mpOpts = append(mpOpts, sdkmetric.WithResource(res))
	for _, r := range readers {
		mpOpts = append(mpOpts, sdkmetric.WithReader(r))
	}
	// Default view for latency histograms in seconds.
	mpOpts = append(mpOpts, sdkmetric.WithView(sdkmetric.NewView(
		sdkmetric.Instrument{
			Name: "newt_*_latency_seconds",
		},
		sdkmetric.Stream{
			Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
				Boundaries: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30},
			},
		},
	)))
// Attribute whitelist: only allow expected low-cardinality keys on newt_* instruments.
	mpOpts = append(mpOpts, sdkmetric.WithView(sdkmetric.NewView(
		sdkmetric.Instrument{Name: "newt_*"},
		sdkmetric.Stream{
			AttributeFilter: func(kv attribute.KeyValue) bool {
				k := string(kv.Key)
				switch k {
				case "tunnel_id", "transport", "direction", "protocol", "result", "reason", "initiator", "error_type", "msg_type", "phase", "version", "commit", "site_id", "region":
					return true
				default:
					return false
				}
			},
		},
	)))
	mp := sdkmetric.NewMeterProvider(mpOpts...)
	otel.SetMeterProvider(mp)
	s.MeterProvider = mp
	s.shutdowns = append(s.shutdowns, mp.Shutdown)

	// Optional tracing (OTLP over gRPC)
	if cfg.OTLPEnabled {
		topts := []otlptracegrpc.Option{otlptracegrpc.WithEndpoint(cfg.OTLPEndpoint)}
		if hdrs := parseOTLPHeaders(os.Getenv("OTEL_EXPORTER_OTLP_HEADERS")); len(hdrs) > 0 {
			topts = append(topts, otlptracegrpc.WithHeaders(hdrs))
		}
		if cfg.OTLPInsecure {
			topts = append(topts, otlptracegrpc.WithInsecure())
		} else if certFile := os.Getenv("OTEL_EXPORTER_OTLP_CERTIFICATE"); certFile != "" {
			creds, cerr := credentials.NewClientTLSFromFile(certFile, "")
			if cerr == nil {
				topts = append(topts, otlptracegrpc.WithTLSCredentials(creds))
			}
		}
		exp, err := otlptracegrpc.New(ctx, topts...)
		if err == nil {
			tp := sdktrace.NewTracerProvider(
				sdktrace.WithBatcher(exp),
				sdktrace.WithResource(res),
			)
			otel.SetTracerProvider(tp)
			s.TracerProvider = tp
			s.shutdowns = append(s.shutdowns, func(ctx context.Context) error {
				return errors.Join(exp.Shutdown(ctx), tp.Shutdown(ctx))
			})
		}
	}

	// Export Go runtime metrics (goroutines, GC, mem, etc.)
	_ = runtime.Start(runtime.WithMeterProvider(mp))

	// Register instruments after provider is set
	if err := registerInstruments(); err != nil {
		return nil, err
	}
	// Optional build info metric
	if cfg.BuildVersion != "" || cfg.BuildCommit != "" {
		RegisterBuildInfo(cfg.BuildVersion, cfg.BuildCommit)
	}

	return s, nil
}

// Shutdown flushes exporters and providers in reverse init order.
func (s *Setup) Shutdown(ctx context.Context) error {
	var err error
	for i := len(s.shutdowns) - 1; i >= 0; i-- {
		err = errors.Join(err, s.shutdowns[i](ctx))
	}
	return err
}

func parseOTLPHeaders(h string) map[string]string {
	m := map[string]string{}
	if h == "" {
		return m
	}
	pairs := strings.Split(h, ",")
	for _, p := range pairs {
		kv := strings.SplitN(strings.TrimSpace(p), "=", 2)
		if len(kv) == 2 {
			m[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}
	return m
}

// parseResourceAttributes parses OTEL_RESOURCE_ATTRIBUTES formatted as k=v,k2=v2
func parseResourceAttributes(s string) map[string]string {
	m := map[string]string{}
	if s == "" {
		return m
	}
	parts := strings.Split(s, ",")
	for _, p := range parts {
		kv := strings.SplitN(strings.TrimSpace(p), "=", 2)
		if len(kv) == 2 {
			m[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}
	return m
}

// Global site/region used to enrich metric labels.
var siteIDVal atomic.Value
var regionVal atomic.Value

// UpdateSiteInfo updates the global site_id and region used for metric labels.
// Thread-safe via atomic.Value: subsequent metric emissions will include
// the new labels, prior emissions remain unchanged.
func UpdateSiteInfo(siteID, region string) {
	if siteID != "" {
		siteIDVal.Store(siteID)
	}
	if region != "" {
		regionVal.Store(region)
	}
}

func getSiteID() string {
	if v, ok := siteIDVal.Load().(string); ok {
		return v
	}
	return ""
}

func getRegion() string {
	if v, ok := regionVal.Load().(string); ok {
		return v
	}
	return ""
}

// siteAttrs returns label KVs for site_id and region (if set).
func siteAttrs() []attribute.KeyValue {
	var out []attribute.KeyValue
	if s := getSiteID(); s != "" {
		out = append(out, attribute.String("site_id", s))
	}
	if r := getRegion(); r != "" {
		out = append(out, attribute.String("region", r))
	}
	return out
}

// SiteLabelKVs exposes site label KVs for other packages (e.g., proxy manager).
func SiteLabelKVs() []attribute.KeyValue { return siteAttrs() }

func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func getdur(k string, d time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if p, e := time.ParseDuration(v); e == nil {
			return p
		}
	}
	return d
}
