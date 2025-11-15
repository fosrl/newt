//go:build !js

package bind

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	wgConn "golang.zx2c4.com/wireguard/conn"
)

// TestSharedBindCreation tests basic creation and initialization
func TestSharedBindCreation(t *testing.T) {
	// Create a UDP connection
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("Failed to create UDP connection: %v", err)
	}
	defer udpConn.Close()

	// Create SharedBind
	bind, err := New(udpConn)
	if err != nil {
		t.Fatalf("Failed to create SharedBind: %v", err)
	}

	if bind == nil {
		t.Fatal("SharedBind is nil")
	}

	// Verify initial reference count
	if bind.refCount.Load() != 1 {
		t.Errorf("Expected initial refCount to be 1, got %d", bind.refCount.Load())
	}

	// Clean up
	if err := bind.Close(); err != nil {
		t.Errorf("Failed to close SharedBind: %v", err)
	}
}

// TestSharedBindReferenceCount tests reference counting
func TestSharedBindReferenceCount(t *testing.T) {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("Failed to create UDP connection: %v", err)
	}

	bind, err := New(udpConn)
	if err != nil {
		t.Fatalf("Failed to create SharedBind: %v", err)
	}

	// Add references
	bind.AddRef()
	if bind.refCount.Load() != 2 {
		t.Errorf("Expected refCount to be 2, got %d", bind.refCount.Load())
	}

	bind.AddRef()
	if bind.refCount.Load() != 3 {
		t.Errorf("Expected refCount to be 3, got %d", bind.refCount.Load())
	}

	// Release references
	bind.Release()
	if bind.refCount.Load() != 2 {
		t.Errorf("Expected refCount to be 2 after release, got %d", bind.refCount.Load())
	}

	bind.Release()
	bind.Release() // This should close the connection

	if !bind.closed.Load() {
		t.Error("Expected bind to be closed after all references released")
	}
}

// TestSharedBindWriteToUDP tests the WriteToUDP functionality
func TestSharedBindWriteToUDP(t *testing.T) {
	// Create sender
	senderConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("Failed to create sender UDP connection: %v", err)
	}

	senderBind, err := New(senderConn)
	if err != nil {
		t.Fatalf("Failed to create sender SharedBind: %v", err)
	}
	defer senderBind.Close()

	// Create receiver
	receiverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("Failed to create receiver UDP connection: %v", err)
	}
	defer receiverConn.Close()

	receiverAddr := receiverConn.LocalAddr().(*net.UDPAddr)

	// Send data
	testData := []byte("Hello, SharedBind!")
	n, err := senderBind.WriteToUDP(testData, receiverAddr)
	if err != nil {
		t.Fatalf("WriteToUDP failed: %v", err)
	}

	if n != len(testData) {
		t.Errorf("Expected to send %d bytes, sent %d", len(testData), n)
	}

	// Receive data
	buf := make([]byte, 1024)
	receiverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err = receiverConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("Failed to receive data: %v", err)
	}

	if string(buf[:n]) != string(testData) {
		t.Errorf("Expected to receive %q, got %q", testData, buf[:n])
	}
}

// TestSharedBindConcurrentWrites tests thread-safety
func TestSharedBindConcurrentWrites(t *testing.T) {
	// Create sender
	senderConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("Failed to create sender UDP connection: %v", err)
	}

	senderBind, err := New(senderConn)
	if err != nil {
		t.Fatalf("Failed to create sender SharedBind: %v", err)
	}
	defer senderBind.Close()

	// Create receiver
	receiverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("Failed to create receiver UDP connection: %v", err)
	}
	defer receiverConn.Close()

	receiverAddr := receiverConn.LocalAddr().(*net.UDPAddr)

	// Launch concurrent writes
	numGoroutines := 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			data := []byte{byte(id)}
			_, err := senderBind.WriteToUDP(data, receiverAddr)
			if err != nil {
				t.Errorf("WriteToUDP failed in goroutine %d: %v", id, err)
			}
		}(i)
	}

	wg.Wait()
}

// TestSharedBindWireGuardInterface tests WireGuard Bind interface implementation
func TestSharedBindWireGuardInterface(t *testing.T) {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("Failed to create UDP connection: %v", err)
	}

	bind, err := New(udpConn)
	if err != nil {
		t.Fatalf("Failed to create SharedBind: %v", err)
	}
	defer bind.Close()

	// Test Open
	recvFuncs, port, err := bind.Open(0)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	if len(recvFuncs) == 0 {
		t.Error("Expected at least one receive function")
	}

	if port == 0 {
		t.Error("Expected non-zero port")
	}

	// Test SetMark (should be a no-op)
	if err := bind.SetMark(0); err != nil {
		t.Errorf("SetMark failed: %v", err)
	}

	// Test BatchSize
	batchSize := bind.BatchSize()
	if batchSize <= 0 {
		t.Error("Expected positive batch size")
	}
}

// TestSharedBindSend tests the Send method with WireGuard endpoints
func TestSharedBindSend(t *testing.T) {
	// Create sender
	senderConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("Failed to create sender UDP connection: %v", err)
	}

	senderBind, err := New(senderConn)
	if err != nil {
		t.Fatalf("Failed to create sender SharedBind: %v", err)
	}
	defer senderBind.Close()

	// Create receiver
	receiverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("Failed to create receiver UDP connection: %v", err)
	}
	defer receiverConn.Close()

	receiverAddr := receiverConn.LocalAddr().(*net.UDPAddr)

	// Create an endpoint
	addrPort := receiverAddr.AddrPort()
	endpoint := &wgConn.StdNetEndpoint{AddrPort: addrPort}

	// Send data
	testData := []byte("WireGuard packet")
	bufs := [][]byte{testData}
	err = senderBind.Send(bufs, endpoint)
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	// Receive data
	buf := make([]byte, 1024)
	receiverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := receiverConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("Failed to receive data: %v", err)
	}

	if string(buf[:n]) != string(testData) {
		t.Errorf("Expected to receive %q, got %q", testData, buf[:n])
	}
}

// TestSharedBindMultipleUsers simulates WireGuard and hole punch using the same bind
func TestSharedBindMultipleUsers(t *testing.T) {
	// Create shared bind
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("Failed to create UDP connection: %v", err)
	}

	sharedBind, err := New(udpConn)
	if err != nil {
		t.Fatalf("Failed to create SharedBind: %v", err)
	}

	// Add reference for hole punch sender
	sharedBind.AddRef()

	// Create receiver
	receiverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("Failed to create receiver UDP connection: %v", err)
	}
	defer receiverConn.Close()

	receiverAddr := receiverConn.LocalAddr().(*net.UDPAddr)

	var wg sync.WaitGroup

	// Simulate WireGuard using the bind
	wg.Add(1)
	go func() {
		defer wg.Done()
		addrPort := receiverAddr.AddrPort()
		endpoint := &wgConn.StdNetEndpoint{AddrPort: addrPort}

		for i := 0; i < 10; i++ {
			data := []byte("WireGuard packet")
			bufs := [][]byte{data}
			if err := sharedBind.Send(bufs, endpoint); err != nil {
				t.Errorf("WireGuard Send failed: %v", err)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	// Simulate hole punch sender using the bind
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			data := []byte("Hole punch packet")
			if _, err := sharedBind.WriteToUDP(data, receiverAddr); err != nil {
				t.Errorf("Hole punch WriteToUDP failed: %v", err)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	wg.Wait()

	// Release the hole punch reference
	sharedBind.Release()

	// Close WireGuard's reference (should close the connection)
	sharedBind.Close()

	if !sharedBind.closed.Load() {
		t.Error("Expected bind to be closed after all users released it")
	}
}

// TestEndpoint tests the Endpoint implementation
func TestEndpoint(t *testing.T) {
	addr := netip.MustParseAddr("192.168.1.1")
	addrPort := netip.AddrPortFrom(addr, 51820)

	ep := &Endpoint{AddrPort: addrPort}

	// Test DstIP
	if ep.DstIP() != addr {
		t.Errorf("Expected DstIP to be %v, got %v", addr, ep.DstIP())
	}

	// Test DstToString
	expected := "192.168.1.1:51820"
	if ep.DstToString() != expected {
		t.Errorf("Expected DstToString to be %q, got %q", expected, ep.DstToString())
	}

	// Test DstToBytes
	bytes := ep.DstToBytes()
	if len(bytes) == 0 {
		t.Error("Expected DstToBytes to return non-empty slice")
	}

	// Test SrcIP (should be zero)
	if ep.SrcIP().IsValid() {
		t.Error("Expected SrcIP to be invalid")
	}

	// Test ClearSrc (should not panic)
	ep.ClearSrc()
}

// TestParseEndpoint tests the ParseEndpoint method
func TestParseEndpoint(t *testing.T) {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("Failed to create UDP connection: %v", err)
	}

	bind, err := New(udpConn)
	if err != nil {
		t.Fatalf("Failed to create SharedBind: %v", err)
	}
	defer bind.Close()

	tests := []struct {
		name      string
		input     string
		wantErr   bool
		checkAddr func(*testing.T, wgConn.Endpoint)
	}{
		{
			name:    "valid IPv4",
			input:   "192.168.1.1:51820",
			wantErr: false,
			checkAddr: func(t *testing.T, ep wgConn.Endpoint) {
				if ep.DstToString() != "192.168.1.1:51820" {
					t.Errorf("Expected 192.168.1.1:51820, got %s", ep.DstToString())
				}
			},
		},
		{
			name:    "valid IPv6",
			input:   "[::1]:51820",
			wantErr: false,
			checkAddr: func(t *testing.T, ep wgConn.Endpoint) {
				if ep.DstToString() != "[::1]:51820" {
					t.Errorf("Expected [::1]:51820, got %s", ep.DstToString())
				}
			},
		},
		{
			name:    "invalid - missing port",
			input:   "192.168.1.1",
			wantErr: true,
		},
		{
			name:    "invalid - bad format",
			input:   "not-an-address",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep, err := bind.ParseEndpoint(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseEndpoint() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.checkAddr != nil {
				tt.checkAddr(t, ep)
			}
		})
	}
}
