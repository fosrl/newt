package proxy

import (
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fosrl/newt/internal/telemetry"
)

func initNativeProxyTelemetry(t *testing.T) {
	t.Helper()
	if _, err := telemetry.Init(context.Background(), telemetry.Config{ServiceName: "native-proxy-test"}); err != nil {
		t.Fatalf("telemetry.Init: %v", err)
	}
}

func stopNativeProxy(t *testing.T, pm *ProxyManager) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- pm.Stop() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Stop: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Stop did not finish (possible telemetry flush deadlock)")
	}
}

func TestNativeStopReleasesPartiallyStartedListeners(t *testing.T) {
	initNativeProxyTelemetry(t)
	occupied, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()

	pm := NewProxyManagerNative("127.0.0.1")
	pm.SetAsyncBytes(true)
	flushDone := pm.flushDone
	t.Cleanup(func() { stopNativeProxy(t, pm) })
	// Start always creates TCP listeners before UDP listeners, so the occupied
	// UDP port deterministically triggers a failure after a TCP socket exists.
	if err := pm.AddTarget("tcp", "127.0.0.1", 0, "127.0.0.1:1"); err != nil {
		t.Fatal(err)
	}
	if err := pm.AddTarget("udp", "127.0.0.1", occupied.LocalAddr().(*net.UDPAddr).Port, "127.0.0.1:1"); err != nil {
		t.Fatal(err)
	}
	if err := pm.Start(); err == nil || !strings.Contains(err.Error(), "UDP target") {
		t.Fatalf("expected a UDP bind failure, got %v", err)
	}
	if len(pm.listeners) != 1 || pm.running {
		t.Fatalf("expected a partially started manager: listeners=%d running=%v", len(pm.listeners), pm.running)
	}
	address := pm.listeners[0].Addr().String()
	stopNativeProxy(t, pm)
	select {
	case <-flushDone:
	default:
		t.Fatal("async telemetry worker still running after Stop")
	}
	if len(pm.listeners) != 0 || len(pm.udpConns) != 0 {
		t.Fatal("Stop retained listeners after partial startup")
	}
	rebound, err := net.Listen("tcp4", address)
	if err != nil {
		t.Fatalf("TCP socket leaked after failed Start and Stop: %v", err)
	}
	defer rebound.Close()
	stopNativeProxy(t, pm) // Must also be safe on an already stopped manager.
}

func TestNativeAsyncFlushStopsBeforeStartAndRestarts(t *testing.T) {
	initNativeProxyTelemetry(t)
	pm := NewProxyManagerNative("127.0.0.1")
	pm.SetTunnelID("test-tunnel")
	pm.SetAsyncBytes(true)
	firstDone := pm.flushDone
	entry := pm.getEntry("test-tunnel")
	entry.bytesInTCP.Add(123)
	stopNativeProxy(t, pm)
	select {
	case <-firstDone:
	default:
		t.Fatal("async telemetry worker still running before first Start")
	}
	if got := entry.bytesInTCP.Load(); got != 0 {
		t.Fatalf("Stop did not flush pending bytes: %d", got)
	}
	if err := pm.Start(); err != nil {
		t.Fatal(err)
	}
	secondDone := pm.flushDone
	if secondDone == nil || secondDone == firstDone {
		t.Fatal("Start did not restart the async telemetry worker")
	}
	stopNativeProxy(t, pm)
	select {
	case <-secondDone:
	default:
		t.Fatal("restarted async telemetry worker still running after Stop")
	}
}

func TestNativeStopFlushesBytesRecordedByExitingFlows(t *testing.T) {
	initNativeProxyTelemetry(t)
	pm := NewProxyManagerNative("127.0.0.1")
	t.Cleanup(func() { stopNativeProxy(t, pm) })
	pm.SetTunnelID("exiting-flow")
	pm.SetAsyncBytes(true)
	flushStop, flushDone := pm.flushStop, pm.flushDone
	entry := pm.getEntry("exiting-flow")
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	managed := newManagedListener(listener)
	pm.listeners = append(pm.listeners, managed)
	managed.workers.Add(1)
	go func() {
		defer managed.workers.Done()
		<-managed.ctx.Done()
		// Synchronize with Stop releasing its lock after canceling the flow.
		pm.mutex.Lock()
		pm.mutex.Unlock()
		select {
		case <-flushStop:
			// If Stop ended the flush loop before joining the flow, force the
			// final flush to precede this flow's last accounting update.
			<-flushDone
		default:
		}
		entry.bytesOutTCP.Add(123)
	}()
	stopNativeProxy(t, pm)
	if got := entry.bytesOutTCP.Load(); got != 0 {
		t.Fatalf("Stop left %d bytes unflushed from an exiting flow", got)
	}
}

func TestNativeTCPAndUDPForwarding(t *testing.T) {
	initNativeProxyTelemetry(t)
	tcpTarget, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpTarget.Close()
	go func() {
		conn, err := tcpTarget.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = io.Copy(conn, conn)
	}()
	udpTarget, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpTarget.Close()
	go func() {
		_ = udpTarget.SetDeadline(time.Now().Add(3 * time.Second))
		buffer := make([]byte, 1024)
		n, address, err := udpTarget.ReadFrom(buffer)
		if err == nil {
			_, _ = udpTarget.WriteTo(buffer[:n], address)
		}
	}()

	pm := NewProxyManagerNative("127.0.0.1")
	t.Cleanup(func() { stopNativeProxy(t, pm) })
	if err := pm.AddTarget("tcp", "127.0.0.1", 0, tcpTarget.Addr().String()); err != nil {
		t.Fatal(err)
	}
	if err := pm.AddTarget("udp", "127.0.0.1", 0, udpTarget.LocalAddr().String()); err != nil {
		t.Fatal(err)
	}
	if err := pm.Start(); err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct {
		protocol string
		address  string
	}{
		{protocol: "tcp", address: pm.listeners[0].Addr().String()},
		{protocol: "udp", address: pm.udpConns[0].LocalAddr().String()},
	} {
		t.Run(tt.protocol, func(t *testing.T) {
			client, err := net.DialTimeout(tt.protocol, tt.address, 3*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			payload := []byte("native " + tt.protocol + " proxy roundtrip")
			if _, err := client.Write(payload); err != nil {
				t.Fatal(err)
			}
			reply := make([]byte, len(payload))
			if _, err := io.ReadFull(client, reply); err != nil {
				t.Fatalf("read proxy reply: %v", err)
			}
			if string(reply) != string(payload) {
				t.Fatalf("proxy changed payload: got %q, want %q", reply, payload)
			}
		})
	}
}

func TestNativeStopClosesActiveTCPFlowsBeforeReturning(t *testing.T) {
	initNativeProxyTelemetry(t)
	target, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := target.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	pm := NewProxyManagerNative("127.0.0.1")
	pm.SetTunnelID("native-stop-active-tcp")
	t.Cleanup(func() { stopNativeProxy(t, pm) })
	if err := pm.AddTarget("tcp", "127.0.0.1", 0, target.Addr().String()); err != nil {
		t.Fatal(err)
	}
	if err := pm.Start(); err != nil {
		t.Fatal(err)
	}
	client, err := net.DialTimeout("tcp4", pm.listeners[0].Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var upstream net.Conn
	select {
	case upstream = <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("proxy did not connect to target")
	}
	defer upstream.Close()
	stopNativeProxy(t, pm)
	for _, conn := range []net.Conn{client, upstream} {
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		var buffer [1]byte
		if _, err := conn.Read(buffer[:]); err == nil {
			t.Fatal("connection remained readable after Stop")
		} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			t.Fatal("Stop left an accepted or upstream TCP socket open")
		}
	}
	if active := pm.getEntry("native-stop-active-tcp").activeTCP.Load(); active != 0 {
		t.Fatalf("Stop returned with %d active TCP flows", active)
	}
	if err := pm.Start(); err != nil {
		t.Fatal(err)
	}
	if pm.listeners[0].(*managedListener).ctx.Err() != nil {
		t.Fatal("restarted listener inherited cancellation from old generation")
	}
}

func TestNativeStopCancelsPendingTargetResolution(t *testing.T) {
	initNativeProxyTelemetry(t)
	for _, protocol := range []string{"tcp", "udp"} {
		t.Run(protocol, func(t *testing.T) {
			started := make(chan struct{})
			var once sync.Once
			previous := net.DefaultResolver
			net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				once.Do(func() { close(started) })
				<-ctx.Done()
				return nil, ctx.Err()
			}}
			t.Cleanup(func() { net.DefaultResolver = previous })
			pm := NewProxyManagerNative("127.0.0.1")
			pm.SetTunnelID("native-stop-pending-" + protocol)
			t.Cleanup(func() { stopNativeProxy(t, pm) })
			if err := pm.AddTarget(protocol, "127.0.0.1", 0, "pending-newt-proxy.invalid:12345"); err != nil {
				t.Fatal(err)
			}
			if err := pm.Start(); err != nil {
				t.Fatal(err)
			}
			var address string
			if protocol == "tcp" {
				address = pm.listeners[0].Addr().String()
			} else {
				address = pm.udpConns[0].LocalAddr().String()
			}
			client, err := net.DialTimeout(protocol, address, 3*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if _, err := client.Write([]byte("trigger target resolution")); err != nil {
				t.Fatal(err)
			}
			select {
			case <-started:
			case <-time.After(3 * time.Second):
				t.Fatal("proxy did not begin target resolution")
			}
			stopNativeProxy(t, pm)
			entry := pm.getEntry("native-stop-pending-" + protocol)
			if entry.activeTCP.Load() != 0 || entry.activeUDP.Load() != 0 {
				t.Fatal("canceled dial leaked active connection counters")
			}
		})
	}
}

func TestNativeStopJoinsActiveUDPFlows(t *testing.T) {
	initNativeProxyTelemetry(t)
	target, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	pm := NewProxyManagerNative("127.0.0.1")
	pm.SetTunnelID("native-stop-active-udp")
	t.Cleanup(func() { stopNativeProxy(t, pm) })
	if err := pm.AddTarget("udp", "127.0.0.1", 0, target.LocalAddr().String()); err != nil {
		t.Fatal(err)
	}
	if err := pm.Start(); err != nil {
		t.Fatal(err)
	}
	client, err := net.DialTimeout("udp4", pm.udpConns[0].LocalAddr().String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("keep an idle UDP flow open")); err != nil {
		t.Fatal(err)
	}
	_ = target.SetReadDeadline(time.Now().Add(3 * time.Second))
	var buffer [128]byte
	if _, _, err := target.ReadFrom(buffer[:]); err != nil {
		t.Fatal(err)
	}
	entry := pm.getEntry("native-stop-active-udp")
	if entry.activeUDP.Load() != 1 {
		t.Fatal("UDP flow was not opened")
	}
	stopNativeProxy(t, pm)
	if active := entry.activeUDP.Load(); active != 0 {
		t.Fatalf("Stop returned with %d active UDP flows", active)
	}
}
