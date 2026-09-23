package newt

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestMainAllowedIPsPreservesServerAndCanonicalizesSubnets(t *testing.T) {
	prefixes, err := mainAllowedIPs("100.89.0.1", []string{
		"10.40.0.55/24", "10.40.0.0/24", "100.89.0.1/32", "192.168.50.0/24",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("100.89.0.1/32"),
		netip.MustParsePrefix("10.40.0.0/24"),
		netip.MustParsePrefix("192.168.50.0/24"),
	}
	if !slices.Equal(prefixes, want) {
		t.Fatalf("AllowedIPs = %v, want %v", prefixes, want)
	}
	prefixes, err = mainAllowedIPs("100.89.0.1", nil)
	if err != nil || !slices.Equal(prefixes, want[:1]) {
		t.Fatalf("server route must survive empty subnet list: %v, %v", prefixes, err)
	}
}

func TestMainAllowedIPsRejectsInvalidAndIPv6Input(t *testing.T) {
	for _, tt := range []struct {
		name, server string
		subnets      []string
	}{
		{name: "empty server"},
		{name: "server prefix", server: "100.89.0.1/32"},
		{name: "IPv6 server", server: "fd00::1"},
		{name: "mapped IPv4 server", server: "::ffff:100.89.0.1"},
		{name: "invalid subnet", server: "100.89.0.1", subnets: []string{"10.20.0.1"}},
		{name: "invalid prefix length", server: "100.89.0.1", subnets: []string{"10.20.0.0/33"}},
		{name: "IPv6 subnet", server: "100.89.0.1", subnets: []string{"fd00::/64"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := mainAllowedIPs(tt.server, tt.subnets); err == nil {
				t.Fatal("invalid AllowedIP input was accepted")
			}
		})
	}
}

func TestResolveControlEndpointLiteralsAndInvalidURLs(t *testing.T) {
	for _, tt := range []struct {
		endpoint, want string
	}{
		{endpoint: "https://203.0.113.10:8443/path", want: "203.0.113.10"},
		{endpoint: "https://[2001:db8::10]:8443", want: "2001:db8::10"},
		{endpoint: "https://[::ffff:203.0.113.10]", want: "203.0.113.10"},
	} {
		t.Run(tt.endpoint, func(t *testing.T) {
			addresses, err := resolveControlEndpoint(context.Background(), tt.endpoint)
			if err != nil || len(addresses) != 1 || addresses[0] != netip.MustParseAddr(tt.want) {
				t.Fatalf("addresses = %v, error = %v", addresses, err)
			}
		})
	}
	for _, endpoint := range []string{"", "pangolin.example", "https://", "https://[invalid"} {
		t.Run("invalid "+endpoint, func(t *testing.T) {
			if _, err := resolveControlEndpoint(context.Background(), endpoint); err == nil {
				t.Fatal("invalid control endpoint was accepted")
			}
		})
	}
}

// Resolver.Dial exchanges DNS queries over an in-memory connection. These
// tests do not depend on Internet connectivity or the developer's DNS records.
func controlDNSConnection() net.Conn {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		var size [2]byte
		if _, err := io.ReadFull(server, size[:]); err != nil {
			return
		}
		queryBytes := make([]byte, binary.BigEndian.Uint16(size[:]))
		if _, err := io.ReadFull(server, queryBytes); err != nil {
			return
		}
		var query dnsmessage.Message
		if query.Unpack(queryBytes) != nil || len(query.Questions) != 1 {
			return
		}
		question := query.Questions[0]
		response := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: query.ID, Response: true, Authoritative: true, RecursionAvailable: true},
			Questions: query.Questions,
		}
		header := dnsmessage.ResourceHeader{Name: question.Name, Type: question.Type, Class: dnsmessage.ClassINET, TTL: 60}
		switch question.Type {
		case dnsmessage.TypeA:
			response.Answers = []dnsmessage.Resource{
				{Header: header, Body: &dnsmessage.AResource{A: [4]byte{203, 0, 113, 10}}},
				{Header: header, Body: &dnsmessage.AResource{A: [4]byte{203, 0, 113, 11}}},
			}
		case dnsmessage.TypeAAAA:
			response.Answers = []dnsmessage.Resource{{Header: header, Body: &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2001:db8::10").As16()}}}
		}
		packed, err := response.Pack()
		if err != nil {
			return
		}
		binary.BigEndian.PutUint16(size[:], uint16(len(packed)))
		_, _ = server.Write(append(size[:], packed...))
	}()
	return client
}

func TestResolveControlEndpointProtectsAllDNSAddresses(t *testing.T) {
	previous := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		return controlDNSConnection(), nil
	}}
	t.Cleanup(func() { net.DefaultResolver = previous })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	addresses, err := resolveControlEndpoint(ctx, "https://kernel-main-control.invalid")
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Addr{netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("203.0.113.11"), netip.MustParseAddr("2001:db8::10")}
	if len(addresses) != len(want) {
		t.Fatalf("addresses = %v, want %v", addresses, want)
	}
	for _, addr := range want {
		if !slices.Contains(addresses, addr) {
			t.Fatalf("control endpoint address %s was left unprotected: %v", addr, addresses)
		}
	}
}

func TestResolveControlEndpointReportsDNSFailure(t *testing.T) {
	previous := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("injected DNS failure")
	}}
	t.Cleanup(func() { net.DefaultResolver = previous })
	if _, err := resolveControlEndpoint(context.Background(), "https://kernel-main-control.invalid"); err == nil || !strings.Contains(err.Error(), "resolve Pangolin control endpoint") {
		t.Fatalf("DNS failure was not reported: %v", err)
	}
}

type mockKernelMain struct {
	allowed    []netip.Prefix
	setCalls   int
	closeCalls int
	setErr     error
	closeErr   error
	onClose    func()
}

func (m *mockKernelMain) SetAllowedIPs(prefixes []netip.Prefix) error {
	m.allowed = slices.Clone(prefixes)
	m.setCalls++
	return m.setErr
}

func (m *mockKernelMain) Close() error {
	m.closeCalls++
	if m.onClose != nil {
		m.onClose()
	}
	return m.closeErr
}

func TestKernelSubnetUpdatesPreserveServerAndCopyInput(t *testing.T) {
	device := &mockKernelMain{}
	n := &Newt{config: Config{UseKernelMainInterface: true}, kernelMain: device, connected: true,
		wgData: WgData{ServerIP: "100.89.0.1"}}
	subnets := []string{"10.40.0.55/24", "10.40.0.0/24"}
	if err := n.updateRemoteExitNodeSubnets(subnets); err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{netip.MustParsePrefix("100.89.0.1/32"), netip.MustParsePrefix("10.40.0.0/24")}
	if !slices.Equal(device.allowed, want) || device.setCalls != 1 || device.closeCalls != 0 || !n.connected {
		t.Fatal("kernel subnet update lost server route or closed working connection")
	}
	subnets[0] = "192.168.1.0/24"
	if n.activeRemoteSubnets[0] != "10.40.0.55/24" {
		t.Fatal("active subnets alias caller-owned input")
	}
	if err := n.updateRemoteExitNodeSubnets(nil); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(device.allowed, want[:1]) || len(n.activeRemoteSubnets) != 0 {
		t.Fatal("removing remote subnets must retain server route")
	}
}

func TestKernelSubnetFailureClosesTunnel(t *testing.T) {
	for _, invalidInput := range []bool{false, true} {
		name := "kernel update failed"
		if invalidInput {
			name = "invalid subnet input"
		}
		t.Run(name, func(t *testing.T) {
			injected := errors.New("kernel route update failed")
			device := &mockKernelMain{setErr: injected}
			n := &Newt{config: Config{UseKernelMainInterface: true}, kernelMain: device, connected: true,
				wgData: WgData{ServerIP: "100.89.0.1"}, activeRemoteSubnets: []string{"10.10.0.0/24"}}
			subnets := []string{"10.20.0.0/24"}
			if invalidInput {
				subnets = []string{"invalid"}
			}
			err := n.updateRemoteExitNodeSubnets(subnets)
			if err == nil || (!invalidInput && !errors.Is(err, injected)) {
				t.Fatalf("expected route update error, got %v", err)
			}
			if device.closeCalls != 1 || n.kernelMain != nil || n.connected || n.hasMainTunnel() || len(n.activeRemoteSubnets) != 0 {
				t.Fatal("failed update left partial kernel tunnel active")
			}
			if invalidInput && device.setCalls != 0 {
				t.Fatal("invalid input reached the kernel backend")
			}
		})
	}
}

func TestCloseKernelTunnelCancelsAndJoinsProbes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	retryStop, pingStop := make(chan struct{}), make(chan struct{})
	var workerStopped atomic.Bool
	device := &mockKernelMain{closeErr: errors.New("injected close failure")}
	device.onClose = func() {
		if !workerStopped.Load() {
			t.Error("kernel device closed before its ping worker stopped")
		}
	}
	n := &Newt{config: Config{UseKernelMainInterface: true}, kernelMain: device, connected: true,
		mainPingCancel: cancel, pingWithRetryStopChan: retryStop, pingStopChan: pingStop,
		activeRemoteSubnets: []string{"10.10.0.0/24"}}
	n.pingWorkers.Add(1)
	go func() {
		defer n.pingWorkers.Done()
		<-ctx.Done()
		<-retryStop
		<-pingStop
		workerStopped.Store(true)
	}()
	done := make(chan struct{})
	go func() {
		n.closeWgTunnel()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cleanup did not cancel and join ping worker")
	}
	if n.mainPingCancel != nil || n.pingWithRetryStopChan != nil || n.pingStopChan != nil || n.kernelMain != nil || n.connected || len(n.activeRemoteSubnets) != 0 {
		t.Fatal("cleanup left active main tunnel state")
	}
	n.closeWgTunnel()
	if device.closeCalls != 1 {
		t.Fatal("repeated cleanup closed kernel device more than once")
	}
}
