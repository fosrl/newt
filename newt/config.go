package newt

import (
	"fmt"
	"runtime"
	"strings"
	"time"
	"unicode"
)

// Config holds all runtime configuration for a Newt instance.
type Config struct {
	// Build info
	Version      string
	Platform     string
	Agent        string
	AgentVersion string

	// Logging
	LogLevel string

	// Connection
	Endpoint        string
	ID              string
	Secret          string
	ProvisioningKey string
	NewtName        string
	ConfigFile      string

	// Network
	MTU                     int
	DNS                     string
	InterfaceName           string
	Port                    uint16
	UseNativeInterface      bool
	UseNativeMainInterface  bool
	UseKernelMainInterface  bool
	NativeMainInterfaceName string
	NoCloud                 bool
	PreferEndpoint          string
	LocalEndpointInterfaces []string

	// Timing
	PingInterval        time.Duration
	PingTimeout         time.Duration
	UDPProxyIdleTimeout time.Duration

	// Features
	DisableClients            bool
	DisableSSH                bool
	EnforceHealthcheckCert    bool
	HealthFile                string
	BlueprintFile             string
	ProvisioningBlueprintFile string
	UpdownScript              string

	// Docker
	DockerSocket                   string
	DockerEnforceNetworkValidation bool

	// Auth daemon
	AuthDaemonKey                    string
	AuthDaemonPrincipalsFile         string
	AuthDaemonCACertPath             string
	AuthDaemonGenerateRandomPassword bool

	// TLS (mTLS)
	TLSClientCert string
	TLSClientKey  string
	TLSClientCAs  []string
	TLSPrivateKey string

	// Metrics/observability
	MetricsEnabled    bool
	OTLPEnabled       bool
	AdminAddr         string
	Region            string
	MetricsAsyncBytes bool
	PprofEnabled      bool

	// Callbacks
	OnRestart func() error
}

// UsesHostMainInterface reports whether the main tunnel uses the host network
// stack rather than the userspace netstack. Native mode still uses wireguard-go;
// kernel mode uses Linux's WireGuard implementation.
func (c Config) UsesHostMainInterface() bool {
	return c.UseNativeMainInterface || c.UseKernelMainInterface
}

// ValidateMainInterface checks kernel main-tunnel settings before any network
// resources are created. It also applies to callers embedding Newt directly.
func (c Config) ValidateMainInterface() error {
	return c.validateMainInterfaceForOS(runtime.GOOS)
}

func (c Config) validateMainInterfaceForOS(goos string) error {
	if !c.UseKernelMainInterface {
		return nil
	}
	if c.UseNativeMainInterface {
		return fmt.Errorf("--kernel-main and --native-main cannot be used together")
	}
	if goos != "linux" {
		return fmt.Errorf("--kernel-main requires Linux (running on %s)", goos)
	}
	name := c.NativeMainInterfaceName
	if name == "" || name == "." || name == ".." || len(name) > 15 ||
		strings.ContainsAny(name, "/:\x00") || strings.IndexFunc(name, unicode.IsSpace) >= 0 {
		return fmt.Errorf("invalid --interface-main %q: kernel interface names must be 1-15 bytes and cannot contain whitespace, '/', ':', or NUL, or be '.' or '..'", name)
	}
	if c.MTU < 576 || c.MTU > 65535 {
		return fmt.Errorf("invalid --mtu %d: --kernel-main requires an MTU between 576 and 65535", c.MTU)
	}
	if !c.DisableClients && c.UseNativeInterface && name == c.InterfaceName {
		return fmt.Errorf("--interface-main and --interface must differ when --kernel-main and native client tunnels are enabled")
	}
	return nil
}
