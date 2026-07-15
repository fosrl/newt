package network

import (
	"net"
	"syscall"
	"testing"
)

func TestSubnetsOverlap(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"10.200.4.0/23", "10.200.4.0/23", true},
		{"10.200.4.0/23", "10.200.4.0/24", true},
		{"10.200.4.0/24", "10.200.5.0/24", false},
		{"192.168.1.0/24", "10.0.0.0/8", false},
	}
	for _, tt := range tests {
		_, a, _ := net.ParseCIDR(tt.a)
		_, b, _ := net.ParseCIDR(tt.b)
		if got := subnetsOverlap(a, b); got != tt.want {
			t.Errorf("subnetsOverlap(%s, %s) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestMetricForRemoteSubnet(t *testing.T) {
	local := mustCIDR(t, "10.200.4.0/23")

	metric, overlap, err := metricForRemoteSubnet("10.200.4.0/23", []*net.IPNet{local})
	if err != nil || !overlap || metric != linuxOverlapTunnelRouteMetric {
		t.Fatalf("overlap: metric=%d overlap=%v err=%v", metric, overlap, err)
	}

	metric, overlap, err = metricForRemoteSubnet("10.10.0.0/16", []*net.IPNet{local})
	if err != nil || overlap || metric != linuxDefaultTunnelRouteMetric {
		t.Fatalf("no overlap: metric=%d overlap=%v err=%v", metric, overlap, err)
	}
}

func TestLinuxRouteFamily(t *testing.T) {
	if family := linuxRouteFamily(mustCIDR(t, "10.200.4.0/23")); family != syscall.AF_INET {
		t.Fatalf("IPv4 family = %d, want %d", family, syscall.AF_INET)
	}
	if family := linuxRouteFamily(mustCIDR(t, "fd00::/64")); family != syscall.AF_INET6 {
		t.Fatalf("IPv6 family = %d, want %d", family, syscall.AF_INET6)
	}
}

func mustCIDR(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatal(err)
	}
	return ipNet
}
