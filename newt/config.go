package newt

import "time"

// Config holds all runtime configuration for a Newt instance.
type Config struct {
	// Build info
	Version  string
	Platform string

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
	NativeMainInterfaceName string
	NoCloud                 bool
	PreferEndpoint          string

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
