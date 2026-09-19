package exitnode

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func replaceTransport(t *testing.T, transport http.RoundTripper) {
	t.Helper()
	previous := http.DefaultTransport
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = previous })
}

func TestPingExitNodesContextCancelsInFlightRequest(t *testing.T) {
	started := make(chan struct{})
	var requests atomic.Int32
	replaceTransport(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if requests.Add(1) == 1 {
			close(started)
		}
		<-r.Context().Done()
		return nil, r.Context().Err()
	}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := PingExitNodesContext(ctx, []ExitNode{{ID: 1, Endpoint: "first.invalid"}, {ID: 2, Endpoint: "second.invalid"}}, "", false)
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("HTTP request did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("selection returned %v; want canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("selection did not cancel the in-flight request")
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("made %d requests after cancellation; want 1", got)
	}
}

func TestPingExitNodesContextPreservesProbeFailures(t *testing.T) {
	var requests int
	replaceTransport(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests++
		if r.URL.Path != "/ping" {
			t.Errorf("request path = %q; want /ping", r.URL.Path)
		}
		return nil, errors.New("probe unavailable")
	}))
	nodes := []ExitNode{{ID: 1, Endpoint: "first.invalid"}, {ID: 2, Endpoint: "http://second.invalid/"}}
	results, err := PingExitNodesContext(context.Background(), nodes, "", false)
	if err != nil || len(results) != 2 || requests != 6 {
		t.Fatalf("selection = %v, %v (%d requests); want two failed results after six attempts", results, err, requests)
	}
	for i, result := range results {
		if result.ExitNodeID != nodes[i].ID || result.Error == "" {
			t.Errorf("result %d did not preserve node/probe error: %+v", i, result)
		}
	}
}

func TestPingExitNodesContextFastPaths(t *testing.T) {
	replaceTransport(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Error("fast-path selection made an HTTP request")
		return nil, errors.New("unexpected HTTP request")
	}))
	nodes := []ExitNode{{ID: 1, Endpoint: "first.invalid"}, {ID: 2, Endpoint: "second.invalid"}}
	results := PingExitNodes(nodes, "second.invalid", false)
	if len(results) != 1 || results[0].ExitNodeID != 2 {
		t.Fatalf("preferred result = %+v; want second node", results)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := PingExitNodesContext(ctx, nodes[:1], "", false); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled single-node selection = %v; want canceled", err)
	}
}
