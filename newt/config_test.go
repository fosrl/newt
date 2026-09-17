package newt

import (
	"strings"
	"testing"
)

func TestValidateKernelMainInterface(t *testing.T) {
	valid := Config{
		UseKernelMainInterface:  true,
		NativeMainInterfaceName: "newt-wg",
		InterfaceName:           "newt-clients",
		MTU:                     1280,
	}
	tests := []struct {
		name   string
		goos   string
		modify func(*Config)
		want   string
	}{
		{name: "linux", goos: "linux"},
		{name: "darwin", goos: "darwin", want: "requires Linux"},
		{name: "windows", goos: "windows", want: "requires Linux"},
		{name: "native conflict", goos: "linux", modify: func(c *Config) { c.UseNativeMainInterface = true }, want: "cannot be used together"},
		{name: "empty name", goos: "linux", modify: func(c *Config) { c.NativeMainInterfaceName = "" }, want: "invalid --interface-main"},
		{name: "long name", goos: "linux", modify: func(c *Config) { c.NativeMainInterfaceName = "1234567890123456" }, want: "invalid --interface-main"},
		{name: "maximum name length", goos: "linux", modify: func(c *Config) { c.NativeMainInterfaceName = "123456789012345" }},
		{name: "name measured in bytes", goos: "linux", modify: func(c *Config) { c.NativeMainInterfaceName = strings.Repeat("é", 8) }, want: "invalid --interface-main"},
		{name: "space", goos: "linux", modify: func(c *Config) { c.NativeMainInterfaceName = "newt wg" }, want: "invalid --interface-main"},
		{name: "tab", goos: "linux", modify: func(c *Config) { c.NativeMainInterfaceName = "newt\twg" }, want: "invalid --interface-main"},
		{name: "slash", goos: "linux", modify: func(c *Config) { c.NativeMainInterfaceName = "newt/wg" }, want: "invalid --interface-main"},
		{name: "colon", goos: "linux", modify: func(c *Config) { c.NativeMainInterfaceName = "newt:wg" }, want: "invalid --interface-main"},
		{name: "nul", goos: "linux", modify: func(c *Config) { c.NativeMainInterfaceName = "newt\x00wg" }, want: "invalid --interface-main"},
		{name: "dot", goos: "linux", modify: func(c *Config) { c.NativeMainInterfaceName = "." }, want: "invalid --interface-main"},
		{name: "dotdot", goos: "linux", modify: func(c *Config) { c.NativeMainInterfaceName = ".." }, want: "invalid --interface-main"},
		{name: "mtu too small", goos: "linux", modify: func(c *Config) { c.MTU = 575 }, want: "invalid --mtu"},
		{name: "minimum mtu", goos: "linux", modify: func(c *Config) { c.MTU = 576 }},
		{name: "maximum mtu", goos: "linux", modify: func(c *Config) { c.MTU = 65535 }},
		{name: "mtu too large", goos: "linux", modify: func(c *Config) { c.MTU = 65536 }, want: "invalid --mtu"},
		{name: "client interface collision", goos: "linux", modify: func(c *Config) { c.UseNativeInterface = true; c.InterfaceName = "newt-wg" }, want: "must differ"},
		{name: "distinct native clients", goos: "linux", modify: func(c *Config) { c.UseNativeInterface = true }},
		{name: "disabled clients allow matching names", goos: "linux", modify: func(c *Config) {
			c.UseNativeInterface = true
			c.DisableClients = true
			c.InterfaceName = "newt-wg"
		}},
		{name: "netstack clients allow matching names", goos: "linux", modify: func(c *Config) { c.InterfaceName = "newt-wg" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := valid
			if tt.modify != nil {
				tt.modify(&cfg)
			}
			err := cfg.validateMainInterfaceForOS(tt.goos)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("unexpected validation error: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestMainInterfaceModes(t *testing.T) {
	for _, tt := range []struct {
		name string
		cfg  Config
		host bool
	}{
		{name: "netstack"},
		{name: "native main", cfg: Config{UseNativeMainInterface: true}, host: true},
		{name: "kernel main", cfg: Config{UseKernelMainInterface: true}, host: true},
		{name: "native clients only", cfg: Config{UseNativeInterface: true}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.UsesHostMainInterface(); got != tt.host {
				t.Errorf("UsesHostMainInterface() = %v, want %v", got, tt.host)
			}
			if !tt.cfg.UseKernelMainInterface {
				if err := tt.cfg.validateMainInterfaceForOS("darwin"); err != nil {
					t.Errorf("existing tunnel mode rejected: %v", err)
				}
			}
		})
	}
}
