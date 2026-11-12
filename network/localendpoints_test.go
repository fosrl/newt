package network

import (
	"reflect"
	"testing"
)

func TestParseLocalEndpoint(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "192.168.1.10", want: "192.168.1.10:51820"},
		{in: " 10.0.0.5 ", want: "10.0.0.5:51820"},
		{in: "192.168.1.10:6000", want: "192.168.1.10:6000"},
		{in: "fd00::1", want: "[fd00::1]:51820"},
		{in: "[fd00::1]", want: "[fd00::1]:51820"},
		{in: "[fd00::1]:6000", want: "[fd00::1]:6000"},
		{in: "::ffff:10.0.0.1", want: "10.0.0.1:51820"},
		{in: "", wantErr: true},
		{in: "example.com", wantErr: true},
		{in: "example.com:51820", wantErr: true},
		{in: "10.0.0.1:0", wantErr: true},
		{in: "10.0.0.1:70000", wantErr: true},
		{in: "10.0.0.256", wantErr: true},
	}
	for _, tt := range tests {
		got, err := ParseLocalEndpoint(tt.in, 51820)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseLocalEndpoint(%q) = %q, want error", tt.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseLocalEndpoint(%q) unexpected error: %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseLocalEndpoint(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestMergeLocalEndpoints(t *testing.T) {
	discovered := []string{"192.168.1.10:51820", "172.17.0.1:51820"}

	if got := MergeLocalEndpoints(discovered, nil, 51820); !reflect.DeepEqual(got, discovered) {
		t.Errorf("no extras: got %v, want %v", got, discovered)
	}

	got := MergeLocalEndpoints(discovered, []string{"203.0.113.7", "192.168.1.10", "bad-host", "10.0.0.2:6000"}, 51820)
	want := []string{"203.0.113.7:51820", "192.168.1.10:51820", "10.0.0.2:6000", "172.17.0.1:51820"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("with extras: got %v, want %v", got, want)
	}
}
