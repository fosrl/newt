package clients

import "testing"

func TestNormalizeInterfaceAddress(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantCIDR string
		wantIP   string
		wantErr  bool
	}{
		{name: "bare IPv4", input: "100.90.128.4", wantCIDR: "100.90.128.4/32", wantIP: "100.90.128.4"},
		{name: "bare IPv6", input: "2001:db8::4", wantCIDR: "2001:db8::4/128", wantIP: "2001:db8::4"},
		{name: "IPv4 prefix", input: "100.90.128.4/24", wantCIDR: "100.90.128.4/24", wantIP: "100.90.128.4"},
		{name: "IPv6 prefix", input: "2001:db8::4/64", wantCIDR: "2001:db8::4/64", wantIP: "2001:db8::4"},
		{name: "invalid", input: "100.90.128.4/33", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCIDR, gotIP, err := normalizeInterfaceAddress(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("normalizeInterfaceAddress(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if gotCIDR != tt.wantCIDR || gotIP.String() != tt.wantIP {
				t.Fatalf("normalizeInterfaceAddress(%q) = (%q, %q), want (%q, %q)", tt.input, gotCIDR, gotIP, tt.wantCIDR, tt.wantIP)
			}
		})
	}
}
