package main

import (
	"net"
	"testing"
)

func TestParseTargetString(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		wantListenPort int
		wantTargetAddr string
		wantErr        bool
	}{
		// IPv4 test cases
		{
			name:           "valid IPv4 basic",
			input:          "3001:192.168.1.1:80",
			wantListenPort: 3001,
			wantTargetAddr: "192.168.1.1:80",
			wantErr:        false,
		},
		{
			name:           "valid IPv4 localhost",
			input:          "8080:127.0.0.1:3000",
			wantListenPort: 8080,
			wantTargetAddr: "127.0.0.1:3000",
			wantErr:        false,
		},
		{
			name:           "valid IPv4 same ports",
			input:          "443:10.0.0.1:443",
			wantListenPort: 443,
			wantTargetAddr: "10.0.0.1:443",
			wantErr:        false,
		},

		// IPv6 test cases
		{
			name:           "valid IPv6 loopback",
			input:          "3001:[::1]:8080",
			wantListenPort: 3001,
			wantTargetAddr: "[::1]:8080",
			wantErr:        false,
		},
		{
			name:           "valid IPv6 full address",
			input:          "80:[fd70:1452:b736:4dd5:caca:7db9:c588:f5b3]:8080",
			wantListenPort: 80,
			wantTargetAddr: "[fd70:1452:b736:4dd5:caca:7db9:c588:f5b3]:8080",
			wantErr:        false,
		},
		{
			name:           "valid IPv6 link-local",
			input:          "443:[fe80::1]:443",
			wantListenPort: 443,
			wantTargetAddr: "[fe80::1]:443",
			wantErr:        false,
		},
		{
			name:           "valid IPv6 all zeros compressed",
			input:          "8000:[::]:9000",
			wantListenPort: 8000,
			wantTargetAddr: "[::]:9000",
			wantErr:        false,
		},
		{
			name:           "valid IPv6 mixed notation",
			input:          "5000:[::ffff:192.168.1.1]:6000",
			wantListenPort: 5000,
			wantTargetAddr: "[::ffff:192.168.1.1]:6000",
			wantErr:        false,
		},

		// Hostname test cases
		{
			name:           "valid hostname",
			input:          "8080:example.com:80",
			wantListenPort: 8080,
			wantTargetAddr: "example.com:80",
			wantErr:        false,
		},
		{
			name:           "valid hostname with subdomain",
			input:          "443:api.example.com:8443",
			wantListenPort: 443,
			wantTargetAddr: "api.example.com:8443",
			wantErr:        false,
		},
		{
			name:           "valid localhost hostname",
			input:          "3000:localhost:3000",
			wantListenPort: 3000,
			wantTargetAddr: "localhost:3000",
			wantErr:        false,
		},

		// Error cases
		{
			name:    "invalid - no colons",
			input:   "invalid",
			wantErr: true,
		},
		{
			name:    "invalid - empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "invalid - non-numeric listen port",
			input:   "abc:192.168.1.1:80",
			wantErr: true,
		},
		{
			name:    "invalid - missing target port",
			input:   "3001:192.168.1.1",
			wantErr: true,
		},
		{
			name:    "invalid - IPv6 without brackets",
			input:   "3001:fd70:1452:b736:4dd5:caca:7db9:c588:f5b3:80",
			wantErr: true,
		},
		{
			name:    "invalid - only listen port",
			input:   "3001:",
			wantErr: true,
		},
		{
			name:    "invalid - missing host",
			input:   "3001::80",
			wantErr: true,
		},
		{
			name:    "invalid - IPv6 unclosed bracket",
			input:   "3001:[::1:80",
			wantErr: true,
		},
		{
			name:    "invalid - listen port zero",
			input:   "0:192.168.1.1:80",
			wantErr: true,
		},
		{
			name:    "invalid - listen port negative",
			input:   "-1:192.168.1.1:80",
			wantErr: true,
		},
		{
			name:    "invalid - listen port out of range",
			input:   "70000:192.168.1.1:80",
			wantErr: true,
		},
		{
			name:    "invalid - empty target port",
			input:   "3001:192.168.1.1:",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listenPort, targetAddr, err := parseTargetString(tt.input)

			if (err != nil) != tt.wantErr {
				t.Errorf("parseTargetString(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return // Don't check other values if we expected an error
			}

			if listenPort != tt.wantListenPort {
				t.Errorf("parseTargetString(%q) listenPort = %d, want %d", tt.input, listenPort, tt.wantListenPort)
			}

			if targetAddr != tt.wantTargetAddr {
				t.Errorf("parseTargetString(%q) targetAddr = %q, want %q", tt.input, targetAddr, tt.wantTargetAddr)
			}
		})
	}
}

// TestParseTargetStringNetDialCompatibility verifies that the output is compatible with net.Dial
func TestParseTargetStringNetDialCompatibility(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"IPv4", "8080:127.0.0.1:80"},
		{"IPv6 loopback", "8080:[::1]:80"},
		{"IPv6 full", "8080:[2001:db8::1]:80"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, targetAddr, err := parseTargetString(tt.input)
			if err != nil {
				t.Fatalf("parseTargetString(%q) unexpected error: %v", tt.input, err)
			}

			// Verify the format is valid for net.Dial by checking it can be split back
			// This doesn't actually dial, just validates the format
			_, _, err = net.SplitHostPort(targetAddr)
			if err != nil {
				t.Errorf("parseTargetString(%q) produced invalid net.Dial format %q: %v", tt.input, targetAddr, err)
			}
		})
	}
}
