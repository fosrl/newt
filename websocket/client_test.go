package websocket

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fosrl/newt/internal/telemetry"
	"github.com/gorilla/websocket"
)

// TestMain initialises the telemetry meter so SendMessage's IncWSMessage
// call has a populated counter to write to. Without this, tests that
// exercise SendMessage panic on a nil metric instrument.
func TestMain(m *testing.M) {
	_, err := telemetry.Init(context.Background(), telemetry.Config{
		ServiceName:          "newt-test",
		PromEnabled:          true,
		OTLPEnabled:          false,
		AdminAddr:            "127.0.0.1:0",
		MetricExportInterval: time.Second,
	})
	if err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

// startTestEchoServer stands up a minimal httptest websocket server that
// upgrades the request, reads inbound JSON messages, and counts them via
// the returned atomic. It is used for testing client-side send loops.
func startTestEchoServer(t *testing.T) (urlStr string, count *atomic.Int64, stop func()) {
	t.Helper()
	upgrader := websocket.Upgrader{}
	count = &atomic.Int64{}
	var wg sync.WaitGroup

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade: %v", err)
			return
		}
		wg.Add(1)
		defer wg.Done()
		defer c.Close()
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				return
			}
			count.Add(1)
		}
	}))

	u, _ := url.Parse(srv.URL)
	u.Scheme = "ws"
	return u.String(), count, func() {
		srv.Close()
		wg.Wait()
	}
}

// dialTestClient builds a minimal *Client around a fresh websocket
// connection pointed at the given test server URL. It bypasses
// Connect()/getToken() because those exercise auth flows we do not need
// here.
func dialTestClient(t *testing.T, urlStr string) *Client {
	t.Helper()
	conn, _, err := websocket.DefaultDialer.Dial(urlStr, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return &Client{conn: conn}
}

// TestSendMessageIntervalKeepsRunningPastOldCap is a regression guard for
// a fixed-attempt cap that previously lived in SendMessageInterval. The
// data-plane recovery path in startPingCheck uses SendMessageInterval to
// spam newt/ping/request every 3s when periodic ICMP pings to the
// WireGuard server start failing; recovery hinges on Pangolin replying
// with newt/ping/exitNodes, which feeds the exit-node-selection flow that
// ultimately ends with the server pushing a fresh newt/wg/connect to
// rebuild the tunnel.
//
// Pre-fix the goroutine silently exited after 10 attempts (~27s on a 3s
// interval), so any reply delayed past that window — websocket flap,
// server briefly busy, message lost — left newt waiting on a recovery
// loop that no longer existed. The fix is to keep retrying until the
// caller stops the loop, which is what every real call site does.
//
// This test sends on a tight interval long enough that the old cap would
// have terminated the goroutine, then asserts that substantially more
// than ten messages reached a real httptest websocket server.
func TestSendMessageIntervalKeepsRunningPastOldCap(t *testing.T) {
	urlStr, count, stopServer := startTestEchoServer(t)
	defer stopServer()

	client := dialTestClient(t, urlStr)
	defer client.conn.Close()

	const (
		interval    = 20 * time.Millisecond
		runFor      = 600 * time.Millisecond
		oldCap      = 10
		expectedMin = 20 // generous floor accounting for scheduling jitter
	)
	stop := client.SendMessageInterval("test/ping", map[string]string{"hi": "there"}, interval)
	time.Sleep(runFor)
	stop()

	// Drain server-side reads so any in-flight messages register before assertion.
	time.Sleep(50 * time.Millisecond)

	got := count.Load()
	if got <= int64(oldCap) {
		t.Fatalf("SendMessageInterval gave up after %d messages — the maxAttempts cap may have been reintroduced (got %d, want > %d)",
			oldCap, got, oldCap)
	}
	if got < int64(expectedMin) {
		t.Fatalf("SendMessageInterval sent fewer messages than expected over %v on a %v interval: got %d, want >= %d",
			runFor, interval, got, expectedMin)
	}
}

// TestSendMessageIntervalStopsOnSignal sanity-checks that the returned
// stop function actually halts the loop, so the unbounded retry above
// does not leak goroutines in production.
func TestSendMessageIntervalStopsOnSignal(t *testing.T) {
	urlStr, count, stopServer := startTestEchoServer(t)
	defer stopServer()

	client := dialTestClient(t, urlStr)
	defer client.conn.Close()

	stop := client.SendMessageInterval("test/ping", nil, 10*time.Millisecond)
	time.Sleep(100 * time.Millisecond)
	stop()
	time.Sleep(50 * time.Millisecond) // let any in-flight write finish

	frozen := count.Load()
	time.Sleep(150 * time.Millisecond)
	if got := count.Load(); got != frozen {
		t.Fatalf("SendMessageInterval kept sending after stop(): froze at %d, then saw %d", frozen, got)
	}
}
