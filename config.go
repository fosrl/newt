package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/fosrl/newt/logger"
	newtpkg "github.com/fosrl/newt/newt"
)

type stringSlice []string

func (s *stringSlice) String() string {
	return strings.Join(*s, ",")
}

func (s *stringSlice) Set(value string) error {
	*s = append(*s, value)
	return nil
}

// configSource records where a resolved setting came from, for --show-config.
type configSource string

const (
	sourceDefault configSource = "default"
	sourceFile    configSource = "file"
	sourceEnv     configSource = "environment"
	sourceCLI     configSource = "cli"
)

// fileSettings mirrors the on-disk JSON config file schema. Fields are
// pointers (or, for slices, nil-vs-non-empty) so that "absent from the file"
// can be distinguished from an explicit zero value.
type fileSettings struct {
	Endpoint        *string `json:"endpoint"`
	ID              *string `json:"id"`
	Secret          *string `json:"secret"`
	ProvisioningKey *string `json:"provisioningKey"`
	Name            *string `json:"name"`

	DNS           *string `json:"dns"`
	LogLevel      *string `json:"logLevel"`
	UpdownScript  *string `json:"updownScript"`
	InterfaceName *string `json:"interface"`
	MTU           *int    `json:"mtu"`
	Port          *int    `json:"port"`

	UseNativeInterface      *bool   `json:"native"`
	UseNativeMainInterface  *bool   `json:"nativeMain"`
	NativeMainInterfaceName *string `json:"interfaceMain"`
	NoCloud                 *bool   `json:"noCloud"`
	PreferEndpoint          *string `json:"preferEndpoint"`

	PingInterval        *string `json:"pingInterval"`
	PingTimeout         *string `json:"pingTimeout"`
	UDPProxyIdleTimeout *string `json:"udpProxyIdleTimeout"`

	DisableClients            *bool   `json:"disableClients"`
	DisableSSH                *bool   `json:"disableSsh"`
	EnforceHealthcheckCert    *bool   `json:"enforceHcCert"`
	HealthFile                *string `json:"healthFile"`
	BlueprintFile             *string `json:"blueprintFile"`
	ProvisioningBlueprintFile *string `json:"provisioningBlueprintFile"`

	DockerSocket                   *string `json:"dockerSocket"`
	DockerEnforceNetworkValidation *bool   `json:"dockerEnforceNetworkValidation"`

	AuthDaemonKey                    *string `json:"adPreSharedKey"`
	AuthDaemonPrincipalsFile         *string `json:"adPrincipalsFile"`
	AuthDaemonCACertPath             *string `json:"adCaCertPath"`
	AuthDaemonGenerateRandomPassword *bool   `json:"adGenerateRandomPassword"`

	TLSClientCert *string  `json:"tlsClientCertFile"`
	TLSClientKey  *string  `json:"tlsClientKey"`
	TLSClientCAs  []string `json:"tlsClientCa"`
	TLSPrivateKey *string  `json:"tlsClientCert"` // legacy PKCS12 path; matches the key already written by the credential-save path

	MetricsEnabled    *bool   `json:"metrics"`
	OTLPEnabled       *bool   `json:"otlp"`
	AdminAddr         *string `json:"metricsAdminAddr"`
	Region            *string `json:"region"`
	MetricsAsyncBytes *bool   `json:"metricsAsyncBytes"`
	PprofEnabled      *bool   `json:"pprof"`
}

// resolveConfigFilePath determines the settings/credentials file path using
// the same precedence as every other setting: CLI > env > OS default.
// It has to run before flag.Parse (which needs the file-resolved defaults),
// so it scans os.Args directly instead of using the flag package.
func resolveConfigFilePath(args []string) string {
	for i, a := range args {
		if a == "--config-file" || a == "-config-file" {
			if i+1 < len(args) {
				return args[i+1]
			}
		}
		if v, ok := strings.CutPrefix(a, "--config-file="); ok {
			return v
		}
		if v, ok := strings.CutPrefix(a, "-config-file="); ok {
			return v
		}
	}

	if v := os.Getenv("CONFIG_FILE"); v != "" {
		return v
	}

	var configDir string
	switch runtime.GOOS {
	case "darwin":
		configDir = filepath.Join(os.Getenv("HOME"), "Library", "Application Support", "newt-client")
	case "windows":
		configDir = filepath.Join(os.Getenv("PROGRAMDATA"), "newt", "newt-client")
	default: // linux and others
		configDir = filepath.Join(os.Getenv("HOME"), ".config", "newt-client")
	}

	if err := os.MkdirAll(configDir, 0755); err != nil {
		fmt.Printf("Warning: Failed to create config directory: %v\n", err)
	}

	return filepath.Join(configDir, "config.json")
}

// loadFileSettings reads and parses the config file. A missing or empty file
// is not an error (returns nil, nil) since the file may not exist yet.
func loadFileSettings(path string) (*fileSettings, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, nil
	}

	var fs fileSettings
	if err := json.Unmarshal(data, &fs); err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", path, err)
	}
	return &fs, nil
}

func applyStr(dst *string, v *string, key string, sources map[string]string, src configSource) {
	if v != nil {
		*dst = *v
		sources[key] = string(src)
	}
}

func applyBool(dst *bool, v *bool, key string, sources map[string]string, src configSource) {
	if v != nil {
		*dst = *v
		sources[key] = string(src)
	}
}

func applyEnvStr(dst *string, envName, key string, sources map[string]string) {
	if v := os.Getenv(envName); v != "" {
		*dst = v
		sources[key] = string(sourceEnv)
	}
}

func applyEnvBool(dst *bool, envName, key string, sources map[string]string) {
	if v := os.Getenv(envName); v != "" {
		*dst = v == "true"
		sources[key] = string(sourceEnv)
	}
}

// validateTLSConfig validates that TLS config fields are consistent and that
// referenced files exist.
func validateTLSConfig(cfg newtpkg.Config) error {
	pkcs12Specified := cfg.TLSPrivateKey != ""
	separateFilesSpecified := cfg.TLSClientCert != "" || cfg.TLSClientKey != "" || len(cfg.TLSClientCAs) > 0

	if pkcs12Specified && separateFilesSpecified {
		return fmt.Errorf("cannot use both PKCS12 format (--tls-client-cert) and separate certificate files (--tls-client-cert-file, --tls-client-key, --tls-client-ca)")
	}

	if (cfg.TLSClientCert != "" && cfg.TLSClientKey == "") || (cfg.TLSClientCert == "" && cfg.TLSClientKey != "") {
		return fmt.Errorf("both --tls-client-cert-file and --tls-client-key must be specified together")
	}

	if cfg.TLSClientCert != "" {
		if _, err := os.Stat(cfg.TLSClientCert); os.IsNotExist(err) {
			return fmt.Errorf("client certificate file does not exist: %s", cfg.TLSClientCert)
		}
	}

	if cfg.TLSClientKey != "" {
		if _, err := os.Stat(cfg.TLSClientKey); os.IsNotExist(err) {
			return fmt.Errorf("client key file does not exist: %s", cfg.TLSClientKey)
		}
	}

	for _, caFile := range cfg.TLSClientCAs {
		if _, err := os.Stat(caFile); os.IsNotExist(err) {
			return fmt.Errorf("CA certificate file does not exist: %s", caFile)
		}
	}

	if cfg.TLSPrivateKey != "" {
		if _, err := os.Stat(cfg.TLSPrivateKey); os.IsNotExist(err) {
			return fmt.Errorf("PKCS12 certificate file does not exist: %s", cfg.TLSPrivateKey)
		}
	}

	return nil
}

// parseDurationEnvOrFlag parses s as a duration, using defaultVal on failure.
func parseDurationEnvOrFlag(s string, defaultVal time.Duration, label string) time.Duration {
	if s == "" {
		return defaultVal
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		fmt.Printf("Invalid %s value: %s, using default %v\n", label, s, defaultVal)
		return defaultVal
	}
	return d
}

// loadNewtConfig resolves configuration with priority cli > env > file >
// default, then returns a populated newtpkg.Config. This function calls
// flag.Parse internally and will exit the process if --version or
// --show-config is passed.
func loadNewtConfig() newtpkg.Config {
	sources := make(map[string]string)

	configPath := resolveConfigFilePath(os.Args[1:])
	fileCfg, err := loadFileSettings(configPath)
	if err != nil {
		logger.Fatal("Failed to load config file: %v", err)
	}

	// ---- defaults ----
	cfg := newtpkg.Config{
		Version:  newtVersion,
		Platform: newtPlatform,

		DNS:                      "9.9.9.9",
		LogLevel:                 "INFO",
		InterfaceName:            "newt",
		NativeMainInterfaceName:  "newt",
		AuthDaemonPrincipalsFile: "/var/run/auth-daemon/principals",
		AuthDaemonCACertPath:     "/etc/ssh/ca.pem",
		AdminAddr:                "127.0.0.1:2112",
	}

	mtuStr := "1280"
	portStr := ""
	pingIntervalStr := "15s"
	pingTimeoutStr := "7s"
	udpProxyIdleTimeoutStr := "90s"
	dockerEnforceStr := "false"

	// ---- layer 1: config file ----
	if fileCfg != nil {
		applyStr(&cfg.Endpoint, fileCfg.Endpoint, "endpoint", sources, sourceFile)
		applyStr(&cfg.ID, fileCfg.ID, "id", sources, sourceFile)
		applyStr(&cfg.Secret, fileCfg.Secret, "secret", sources, sourceFile)
		applyStr(&cfg.ProvisioningKey, fileCfg.ProvisioningKey, "provisioning-key", sources, sourceFile)
		applyStr(&cfg.NewtName, fileCfg.Name, "name", sources, sourceFile)

		applyStr(&cfg.DNS, fileCfg.DNS, "dns", sources, sourceFile)
		applyStr(&cfg.LogLevel, fileCfg.LogLevel, "log-level", sources, sourceFile)
		applyStr(&cfg.UpdownScript, fileCfg.UpdownScript, "updown", sources, sourceFile)
		applyStr(&cfg.InterfaceName, fileCfg.InterfaceName, "interface", sources, sourceFile)
		if fileCfg.MTU != nil {
			mtuStr = strconv.Itoa(*fileCfg.MTU)
			sources["mtu"] = string(sourceFile)
		}
		if fileCfg.Port != nil {
			portStr = strconv.Itoa(*fileCfg.Port)
			sources["port"] = string(sourceFile)
		}

		applyBool(&cfg.UseNativeInterface, fileCfg.UseNativeInterface, "native", sources, sourceFile)
		applyBool(&cfg.UseNativeMainInterface, fileCfg.UseNativeMainInterface, "native-main", sources, sourceFile)
		applyStr(&cfg.NativeMainInterfaceName, fileCfg.NativeMainInterfaceName, "interface-main", sources, sourceFile)
		applyBool(&cfg.NoCloud, fileCfg.NoCloud, "no-cloud", sources, sourceFile)
		applyStr(&cfg.PreferEndpoint, fileCfg.PreferEndpoint, "prefer-endpoint", sources, sourceFile)

		applyStr(&pingIntervalStr, fileCfg.PingInterval, "ping-interval", sources, sourceFile)
		applyStr(&pingTimeoutStr, fileCfg.PingTimeout, "ping-timeout", sources, sourceFile)
		applyStr(&udpProxyIdleTimeoutStr, fileCfg.UDPProxyIdleTimeout, "udp-proxy-idle-timeout", sources, sourceFile)

		applyBool(&cfg.DisableClients, fileCfg.DisableClients, "disable-clients", sources, sourceFile)
		applyBool(&cfg.DisableSSH, fileCfg.DisableSSH, "disable-ssh", sources, sourceFile)
		applyBool(&cfg.EnforceHealthcheckCert, fileCfg.EnforceHealthcheckCert, "enforce-hc-cert", sources, sourceFile)
		applyStr(&cfg.HealthFile, fileCfg.HealthFile, "health-file", sources, sourceFile)
		applyStr(&cfg.BlueprintFile, fileCfg.BlueprintFile, "blueprint-file", sources, sourceFile)
		applyStr(&cfg.ProvisioningBlueprintFile, fileCfg.ProvisioningBlueprintFile, "provisioning-blueprint-file", sources, sourceFile)

		applyStr(&cfg.DockerSocket, fileCfg.DockerSocket, "docker-socket", sources, sourceFile)
		if fileCfg.DockerEnforceNetworkValidation != nil {
			dockerEnforceStr = strconv.FormatBool(*fileCfg.DockerEnforceNetworkValidation)
			sources["docker-enforce-network-validation"] = string(sourceFile)
		}

		applyStr(&cfg.AuthDaemonKey, fileCfg.AuthDaemonKey, "ad-pre-shared-key", sources, sourceFile)
		applyStr(&cfg.AuthDaemonPrincipalsFile, fileCfg.AuthDaemonPrincipalsFile, "ad-principals-file", sources, sourceFile)
		applyStr(&cfg.AuthDaemonCACertPath, fileCfg.AuthDaemonCACertPath, "ad-ca-cert-path", sources, sourceFile)
		applyBool(&cfg.AuthDaemonGenerateRandomPassword, fileCfg.AuthDaemonGenerateRandomPassword, "ad-generate-random-password", sources, sourceFile)

		applyStr(&cfg.TLSClientCert, fileCfg.TLSClientCert, "tls-client-cert-file", sources, sourceFile)
		applyStr(&cfg.TLSClientKey, fileCfg.TLSClientKey, "tls-client-key", sources, sourceFile)
		if len(fileCfg.TLSClientCAs) > 0 {
			cfg.TLSClientCAs = append(cfg.TLSClientCAs, fileCfg.TLSClientCAs...)
			sources["tls-client-ca"] = string(sourceFile)
		}
		applyStr(&cfg.TLSPrivateKey, fileCfg.TLSPrivateKey, "tls-client-cert", sources, sourceFile)

		applyBool(&cfg.MetricsEnabled, fileCfg.MetricsEnabled, "metrics", sources, sourceFile)
		applyBool(&cfg.OTLPEnabled, fileCfg.OTLPEnabled, "otlp", sources, sourceFile)
		applyStr(&cfg.AdminAddr, fileCfg.AdminAddr, "metrics-admin-addr", sources, sourceFile)
		applyStr(&cfg.Region, fileCfg.Region, "region", sources, sourceFile)
		applyBool(&cfg.MetricsAsyncBytes, fileCfg.MetricsAsyncBytes, "metrics-async-bytes", sources, sourceFile)
		applyBool(&cfg.PprofEnabled, fileCfg.PprofEnabled, "pprof", sources, sourceFile)
	}

	// ---- layer 2: environment variables ----
	applyEnvStr(&cfg.Endpoint, "PANGOLIN_ENDPOINT", "endpoint", sources)
	applyEnvStr(&cfg.ID, "NEWT_ID", "id", sources)
	applyEnvStr(&cfg.Secret, "NEWT_SECRET", "secret", sources)
	applyEnvStr(&cfg.ProvisioningKey, "NEWT_PROVISIONING_KEY", "provisioning-key", sources)
	applyEnvStr(&cfg.NewtName, "NEWT_NAME", "name", sources)

	applyEnvStr(&cfg.DNS, "DNS", "dns", sources)
	applyEnvStr(&cfg.LogLevel, "LOG_LEVEL", "log-level", sources)
	applyEnvStr(&cfg.UpdownScript, "UPDOWN_SCRIPT", "updown", sources)
	applyEnvStr(&cfg.InterfaceName, "INTERFACE", "interface", sources)
	applyEnvStr(&mtuStr, "MTU", "mtu", sources)
	applyEnvStr(&portStr, "PORT", "port", sources)

	applyEnvBool(&cfg.UseNativeInterface, "USE_NATIVE_INTERFACE", "native", sources)
	applyEnvBool(&cfg.UseNativeMainInterface, "USE_NATIVE_MAIN_INTERFACE", "native-main", sources)
	applyEnvStr(&cfg.NativeMainInterfaceName, "INTERFACE_MAIN", "interface-main", sources)
	applyEnvBool(&cfg.NoCloud, "NO_CLOUD", "no-cloud", sources)

	applyEnvStr(&pingIntervalStr, "PING_INTERVAL", "ping-interval", sources)
	applyEnvStr(&pingTimeoutStr, "PING_TIMEOUT", "ping-timeout", sources)
	applyEnvStr(&udpProxyIdleTimeoutStr, "NEWT_UDP_PROXY_IDLE_TIMEOUT", "udp-proxy-idle-timeout", sources)

	applyEnvBool(&cfg.DisableClients, "DISABLE_CLIENTS", "disable-clients", sources)
	applyEnvBool(&cfg.DisableSSH, "DISABLE_SSH", "disable-ssh", sources)
	applyEnvBool(&cfg.EnforceHealthcheckCert, "ENFORCE_HC_CERT", "enforce-hc-cert", sources)
	applyEnvStr(&cfg.HealthFile, "HEALTH_FILE", "health-file", sources)
	applyEnvStr(&cfg.BlueprintFile, "BLUEPRINT_FILE", "blueprint-file", sources)
	applyEnvStr(&cfg.ProvisioningBlueprintFile, "PROVISIONING_BLUEPRINT_FILE", "provisioning-blueprint-file", sources)

	applyEnvStr(&cfg.DockerSocket, "DOCKER_SOCKET", "docker-socket", sources)
	applyEnvStr(&dockerEnforceStr, "DOCKER_ENFORCE_NETWORK_VALIDATION", "docker-enforce-network-validation", sources)

	applyEnvStr(&cfg.AuthDaemonKey, "AD_KEY", "ad-pre-shared-key", sources)
	applyEnvStr(&cfg.AuthDaemonPrincipalsFile, "AD_PRINCIPALS_FILE", "ad-principals-file", sources)
	applyEnvStr(&cfg.AuthDaemonCACertPath, "AD_CA_CERT_PATH", "ad-ca-cert-path", sources)
	if v, err := strconv.ParseBool(os.Getenv("AD_GENERATE_RANDOM_PASSWORD")); err == nil {
		cfg.AuthDaemonGenerateRandomPassword = v
		sources["ad-generate-random-password"] = string(sourceEnv)
	}

	applyEnvStr(&cfg.TLSClientCert, "TLS_CLIENT_CERT", "tls-client-cert-file", sources)
	applyEnvStr(&cfg.TLSClientKey, "TLS_CLIENT_KEY", "tls-client-key", sources)
	if tlsClientCAsEnv := os.Getenv("TLS_CLIENT_CAS"); tlsClientCAsEnv != "" {
		for _, ca := range strings.Split(tlsClientCAsEnv, ",") {
			cfg.TLSClientCAs = append(cfg.TLSClientCAs, strings.TrimSpace(ca))
		}
		sources["tls-client-ca"] = string(sourceEnv)
	}
	applyEnvStr(&cfg.TLSPrivateKey, "TLS_CLIENT_CERT_PKCS12", "tls-client-cert", sources)

	// Legacy PKCS12 backward-compat: fall back to the (already layered)
	// separate-cert-file value for PKCS12 when the newer fields are unset.
	if cfg.TLSPrivateKey == "" && cfg.TLSClientKey == "" && len(cfg.TLSClientCAs) == 0 && cfg.TLSClientCert != "" {
		cfg.TLSPrivateKey = cfg.TLSClientCert
		sources["tls-client-cert"] = sources["tls-client-cert-file"]
	}

	if metricsEnabledEnv := os.Getenv("NEWT_METRICS_PROMETHEUS_ENABLED"); metricsEnabledEnv != "" {
		if v, err := strconv.ParseBool(metricsEnabledEnv); err == nil {
			cfg.MetricsEnabled = v
		} else {
			cfg.MetricsEnabled = true
		}
		sources["metrics"] = string(sourceEnv)
	}
	applyEnvBool(&cfg.OTLPEnabled, "NEWT_METRICS_OTLP_ENABLED", "otlp", sources)
	applyEnvStr(&cfg.AdminAddr, "NEWT_ADMIN_ADDR", "metrics-admin-addr", sources)
	applyEnvStr(&cfg.Region, "NEWT_REGION", "region", sources)
	applyEnvBool(&cfg.MetricsAsyncBytes, "NEWT_METRICS_ASYNC_BYTES", "metrics-async-bytes", sources)
	applyEnvBool(&cfg.PprofEnabled, "NEWT_PPROF_ENABLED", "pprof", sources)

	// ---- layer 3: CLI flags (always registered; default = file/env-resolved value) ----
	origEndpoint, origID, origSecret := cfg.Endpoint, cfg.ID, cfg.Secret
	origMTU, origDNS, origLogLevel := mtuStr, cfg.DNS, cfg.LogLevel
	origUpdown, origInterface, origPort := cfg.UpdownScript, cfg.InterfaceName, portStr
	origNative, origNativeMain, origInterfaceMain := cfg.UseNativeInterface, cfg.UseNativeMainInterface, cfg.NativeMainInterfaceName
	origDisableClients, origDisableSSH, origEnforceHC := cfg.DisableClients, cfg.DisableSSH, cfg.EnforceHealthcheckCert
	origDockerSocket, origPingInterval, origPingTimeout := cfg.DockerSocket, pingIntervalStr, pingTimeoutStr
	origUDPIdle, origProvisioningKey, origName := udpProxyIdleTimeoutStr, cfg.ProvisioningKey, cfg.NewtName
	origTLSCert, origTLSKey, origDockerEnforce := cfg.TLSClientCert, cfg.TLSClientKey, dockerEnforceStr
	origHealthFile, origBlueprintFile, origProvBlueprintFile := cfg.HealthFile, cfg.BlueprintFile, cfg.ProvisioningBlueprintFile
	origNoCloud, origTLSPrivateKey := cfg.NoCloud, cfg.TLSPrivateKey
	origMetrics, origOTLP, origAdminAddr := cfg.MetricsEnabled, cfg.OTLPEnabled, cfg.AdminAddr
	origMetricsAsync, origPprof, origRegion := cfg.MetricsAsyncBytes, cfg.PprofEnabled, cfg.Region
	origADKey, origADPrincipals, origADCACert := cfg.AuthDaemonKey, cfg.AuthDaemonPrincipalsFile, cfg.AuthDaemonCACertPath
	origADRandomPass := cfg.AuthDaemonGenerateRandomPassword

	flag.StringVar(&cfg.Endpoint, "endpoint", cfg.Endpoint, "Endpoint of your pangolin server")
	flag.StringVar(&cfg.ID, "id", cfg.ID, "Newt ID")
	flag.StringVar(&cfg.Secret, "secret", cfg.Secret, "Newt secret")
	flag.StringVar(&mtuStr, "mtu", mtuStr, "MTU to use")
	flag.StringVar(&cfg.DNS, "dns", cfg.DNS, "DNS server to use")
	flag.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "Log level (DEBUG, INFO, WARN, ERROR, FATAL)")
	flag.StringVar(&cfg.UpdownScript, "updown", cfg.UpdownScript, "Path to updown script to be called when targets are added or removed")
	flag.StringVar(&cfg.InterfaceName, "interface", cfg.InterfaceName, "Name of the WireGuard interface")
	flag.StringVar(&portStr, "port", portStr, "Port for client WireGuard interface")
	flag.BoolVar(&cfg.UseNativeInterface, "native", cfg.UseNativeInterface, "Use native WireGuard interface for client tunnels")
	flag.BoolVar(&cfg.UseNativeMainInterface, "native-main", cfg.UseNativeMainInterface, "Use native WireGuard interface for the main tunnel (instead of netstack)")
	// making this the same as above should prevent them from running together
	flag.StringVar(&cfg.NativeMainInterfaceName, "interface-main", cfg.NativeMainInterfaceName, "Name of the native main tunnel WireGuard interface (used with --native-main)")
	flag.BoolVar(&cfg.DisableClients, "disable-clients", cfg.DisableClients, "Disable clients on the WireGuard interface")
	flag.BoolVar(&cfg.DisableSSH, "disable-ssh", cfg.DisableSSH, "Disable SSH auth daemon and native SSH mode (remote auth daemon still works)")
	flag.BoolVar(&cfg.EnforceHealthcheckCert, "enforce-hc-cert", cfg.EnforceHealthcheckCert, "Enforce certificate validation for health checks (default: false, accepts any cert)")
	flag.StringVar(&cfg.DockerSocket, "docker-socket", cfg.DockerSocket, "Path or address to Docker socket (typically unix:///var/run/docker.sock)")
	flag.StringVar(&pingIntervalStr, "ping-interval", pingIntervalStr, "Interval for pinging the server (default 15s)")
	flag.StringVar(&pingTimeoutStr, "ping-timeout", pingTimeoutStr, "Timeout for each ping (default 7s)")
	flag.StringVar(&udpProxyIdleTimeoutStr, "udp-proxy-idle-timeout", udpProxyIdleTimeoutStr, "Idle timeout for UDP proxied client flows before cleanup")
	flag.StringVar(&cfg.PreferEndpoint, "prefer-endpoint", cfg.PreferEndpoint, "Prefer this endpoint for the connection (if set, will override the endpoint from the server)")
	flag.StringVar(&cfg.ProvisioningKey, "provisioning-key", cfg.ProvisioningKey, "One-time provisioning key used to obtain a newt ID and secret from the server")
	flag.StringVar(&cfg.NewtName, "name", cfg.NewtName, "Name for the site created during provisioning (supports {{env.VAR}} interpolation)")
	flag.StringVar(&cfg.ConfigFile, "config-file", configPath, "Path to config file (overrides CONFIG_FILE env var and default location)")
	flag.StringVar(&cfg.TLSClientCert, "tls-client-cert-file", cfg.TLSClientCert, "Path to client certificate file (PEM/DER format)")
	flag.StringVar(&cfg.TLSClientKey, "tls-client-key", cfg.TLSClientKey, "Path to client private key file (PEM/DER format)")
	// Backward-compat dummy flag (auth daemon is always enabled now)
	flag.Bool("auth-daemon", false, "Enable auth daemon mode (deprecated, always enabled)")

	var tlsClientCAsFlag stringSlice
	flag.Var(&tlsClientCAsFlag, "tls-client-ca", "Path to CA certificate file for validating remote certificates (can be specified multiple times)")

	flag.StringVar(&cfg.TLSPrivateKey, "tls-client-cert", cfg.TLSPrivateKey, "Path to client certificate (PKCS12 format) - DEPRECATED: use --tls-client-cert-file and --tls-client-key instead")
	flag.StringVar(&dockerEnforceStr, "docker-enforce-network-validation", dockerEnforceStr, "Enforce validation of container on newt network (true or false)")
	flag.StringVar(&cfg.HealthFile, "health-file", cfg.HealthFile, "Path to health file (if unset, health file won't be written)")
	flag.StringVar(&cfg.BlueprintFile, "blueprint-file", cfg.BlueprintFile, "Path to blueprint file (if unset, no blueprint will be applied)")
	flag.StringVar(&cfg.ProvisioningBlueprintFile, "provisioning-blueprint-file", cfg.ProvisioningBlueprintFile, "Path to blueprint file applied once after a provisioning credential exchange (if unset, no provisioning blueprint will be applied)")
	flag.BoolVar(&cfg.NoCloud, "no-cloud", cfg.NoCloud, "Disable cloud failover")
	flag.BoolVar(&cfg.MetricsEnabled, "metrics", cfg.MetricsEnabled, "Enable Prometheus metrics exporter")
	flag.BoolVar(&cfg.OTLPEnabled, "otlp", cfg.OTLPEnabled, "Enable OTLP exporters (metrics/traces) to OTEL_EXPORTER_OTLP_ENDPOINT")
	flag.StringVar(&cfg.AdminAddr, "metrics-admin-addr", cfg.AdminAddr, "Admin/metrics bind address")
	flag.BoolVar(&cfg.MetricsAsyncBytes, "metrics-async-bytes", cfg.MetricsAsyncBytes, "Enable async bytes counting (background flush; lower hot path overhead)")
	flag.BoolVar(&cfg.PprofEnabled, "pprof", cfg.PprofEnabled, "Enable pprof debug endpoints on admin server")
	flag.StringVar(&cfg.Region, "region", cfg.Region, "Optional region resource attribute (also NEWT_REGION)")
	flag.StringVar(&cfg.AuthDaemonKey, "ad-pre-shared-key", cfg.AuthDaemonKey, "Pre-shared key for auth daemon authentication")
	flag.StringVar(&cfg.AuthDaemonPrincipalsFile, "ad-principals-file", cfg.AuthDaemonPrincipalsFile, "Path to the principals file for auth daemon")
	flag.StringVar(&cfg.AuthDaemonCACertPath, "ad-ca-cert-path", cfg.AuthDaemonCACertPath, "Path to the CA certificate file for auth daemon")
	flag.BoolVar(&cfg.AuthDaemonGenerateRandomPassword, "ad-generate-random-password", cfg.AuthDaemonGenerateRandomPassword, "Generate a random password for authenticated users")

	version := flag.Bool("version", false, "Print the version")
	showConfig := flag.Bool("show-config", false, "Show configuration values and their sources, then exit")

	flag.Parse()

	// ---- post-parse processing ----

	// Merge CLI CA files onto whatever file/env already contributed.
	if len(tlsClientCAsFlag) > 0 {
		cfg.TLSClientCAs = append(cfg.TLSClientCAs, tlsClientCAsFlag...)
		sources["tls-client-ca"] = string(sourceCLI)
	}

	markCLI := func(key string, changed bool) {
		if changed {
			sources[key] = string(sourceCLI)
		}
	}
	markCLI("endpoint", cfg.Endpoint != origEndpoint)
	markCLI("id", cfg.ID != origID)
	markCLI("secret", cfg.Secret != origSecret)
	markCLI("mtu", mtuStr != origMTU)
	markCLI("dns", cfg.DNS != origDNS)
	markCLI("log-level", cfg.LogLevel != origLogLevel)
	markCLI("updown", cfg.UpdownScript != origUpdown)
	markCLI("interface", cfg.InterfaceName != origInterface)
	markCLI("port", portStr != origPort)
	markCLI("native", cfg.UseNativeInterface != origNative)
	markCLI("native-main", cfg.UseNativeMainInterface != origNativeMain)
	markCLI("interface-main", cfg.NativeMainInterfaceName != origInterfaceMain)
	markCLI("disable-clients", cfg.DisableClients != origDisableClients)
	markCLI("disable-ssh", cfg.DisableSSH != origDisableSSH)
	markCLI("enforce-hc-cert", cfg.EnforceHealthcheckCert != origEnforceHC)
	markCLI("docker-socket", cfg.DockerSocket != origDockerSocket)
	markCLI("ping-interval", pingIntervalStr != origPingInterval)
	markCLI("ping-timeout", pingTimeoutStr != origPingTimeout)
	markCLI("udp-proxy-idle-timeout", udpProxyIdleTimeoutStr != origUDPIdle)
	markCLI("provisioning-key", cfg.ProvisioningKey != origProvisioningKey)
	markCLI("name", cfg.NewtName != origName)
	markCLI("tls-client-cert-file", cfg.TLSClientCert != origTLSCert)
	markCLI("tls-client-key", cfg.TLSClientKey != origTLSKey)
	markCLI("tls-client-cert", cfg.TLSPrivateKey != origTLSPrivateKey)
	markCLI("docker-enforce-network-validation", dockerEnforceStr != origDockerEnforce)
	markCLI("health-file", cfg.HealthFile != origHealthFile)
	markCLI("blueprint-file", cfg.BlueprintFile != origBlueprintFile)
	markCLI("provisioning-blueprint-file", cfg.ProvisioningBlueprintFile != origProvBlueprintFile)
	markCLI("no-cloud", cfg.NoCloud != origNoCloud)
	markCLI("metrics", cfg.MetricsEnabled != origMetrics)
	markCLI("otlp", cfg.OTLPEnabled != origOTLP)
	markCLI("metrics-admin-addr", cfg.AdminAddr != origAdminAddr)
	markCLI("metrics-async-bytes", cfg.MetricsAsyncBytes != origMetricsAsync)
	markCLI("pprof", cfg.PprofEnabled != origPprof)
	markCLI("region", cfg.Region != origRegion)
	markCLI("ad-pre-shared-key", cfg.AuthDaemonKey != origADKey)
	markCLI("ad-principals-file", cfg.AuthDaemonPrincipalsFile != origADPrincipals)
	markCLI("ad-ca-cert-path", cfg.AuthDaemonCACertPath != origADCACert)
	markCLI("ad-generate-random-password", cfg.AuthDaemonGenerateRandomPassword != origADRandomPass)
	if cfg.ConfigFile != configPath {
		sources["config-file"] = string(sourceCLI)
	}

	// Version check (exits process)
	if *version {
		fmt.Println("Newt version " + newtVersion)
		os.Exit(0)
	}

	if *showConfig {
		printShowConfig(cfg, sources, configPath, mtuStr, portStr, pingIntervalStr, pingTimeoutStr, udpProxyIdleTimeoutStr, dockerEnforceStr)
		os.Exit(0)
	}

	logger.Info("Newt version %s", newtVersion)

	// Parse port
	if portStr != "" {
		portInt, err := strconv.Atoi(portStr)
		if err != nil {
			logger.Warn("Failed to parse PORT, choosing a random port")
		} else {
			cfg.Port = uint16(portInt)
		}
	}

	// Parse MTU
	if mtuStr == "" {
		mtuStr = "1280"
	}
	mtuInt, err := strconv.Atoi(mtuStr)
	if err != nil {
		logger.Fatal("Failed to parse MTU: %v", err)
	}
	cfg.MTU = mtuInt

	// Parse docker network validation flag
	if v, err := strconv.ParseBool(dockerEnforceStr); err == nil {
		cfg.DockerEnforceNetworkValidation = v
	} else {
		logger.Info("Docker enforce network validation cannot be parsed. Defaulting to 'false'")
		cfg.DockerEnforceNetworkValidation = false
	}

	// Parse durations (after flag.Parse so CLI flags take effect)
	cfg.PingInterval = parseDurationEnvOrFlag(pingIntervalStr, 15*time.Second, "PING_INTERVAL")
	cfg.PingTimeout = parseDurationEnvOrFlag(pingTimeoutStr, 7*time.Second, "PING_TIMEOUT")
	cfg.UDPProxyIdleTimeout = parseDurationEnvOrFlag(udpProxyIdleTimeoutStr, 90*time.Second, "NEWT_UDP_PROXY_IDLE_TIMEOUT")

	return cfg
}

// printShowConfig prints the resolved configuration and the source of each value
func printShowConfig(cfg newtpkg.Config, sources map[string]string, configPath, mtuStr, portStr, pingIntervalStr, pingTimeoutStr, udpProxyIdleTimeoutStr, dockerEnforceStr string) {
	getSource := func(key string) string {
		if s, ok := sources[key]; ok && s != "" {
			return s
		}
		return string(sourceDefault)
	}
	mask := func(key, value string) string {
		if key == "secret" && value != "" {
			if len(value) > 8 {
				return value[:4] + "****" + value[len(value)-4:]
			}
			return "****"
		}
		if value == "" {
			return "(not set)"
		}
		return value
	}

	fmt.Print("\n=== Newt Configuration ===\n\n")
	fmt.Printf("Config File: %s\n", configPath)
	if _, err := os.Stat(configPath); err == nil {
		fmt.Printf("Config File Status: exists\n")
	} else {
		fmt.Printf("Config File Status: not found\n")
	}

	fmt.Println("\n--- Configuration Values ---")
	fmt.Print("(Format: Setting = Value [source])\n\n")

	fmt.Println("Connection:")
	fmt.Printf("  endpoint         = %s [%s]\n", mask("endpoint", cfg.Endpoint), getSource("endpoint"))
	fmt.Printf("  id               = %s [%s]\n", mask("id", cfg.ID), getSource("id"))
	fmt.Printf("  secret           = %s [%s]\n", mask("secret", cfg.Secret), getSource("secret"))
	fmt.Printf("  provisioning-key = %s [%s]\n", mask("provisioning-key", cfg.ProvisioningKey), getSource("provisioning-key"))
	fmt.Printf("  name             = %s [%s]\n", mask("name", cfg.NewtName), getSource("name"))
	fmt.Printf("  prefer-endpoint  = %s [%s]\n", mask("prefer-endpoint", cfg.PreferEndpoint), getSource("prefer-endpoint"))

	fmt.Println("\nNetwork:")
	fmt.Printf("  mtu              = %s [%s]\n", mtuStr, getSource("mtu"))
	fmt.Printf("  dns              = %s [%s]\n", cfg.DNS, getSource("dns"))
	fmt.Printf("  interface        = %s [%s]\n", cfg.InterfaceName, getSource("interface"))
	fmt.Printf("  port             = %s [%s]\n", mask("port", portStr), getSource("port"))
	fmt.Printf("  native           = %v [%s]\n", cfg.UseNativeInterface, getSource("native"))
	fmt.Printf("  native-main      = %v [%s]\n", cfg.UseNativeMainInterface, getSource("native-main"))
	fmt.Printf("  interface-main   = %s [%s]\n", cfg.NativeMainInterfaceName, getSource("interface-main"))
	fmt.Printf("  no-cloud         = %v [%s]\n", cfg.NoCloud, getSource("no-cloud"))

	fmt.Println("\nLogging:")
	fmt.Printf("  log-level        = %s [%s]\n", cfg.LogLevel, getSource("log-level"))

	fmt.Println("\nTiming:")
	fmt.Printf("  ping-interval           = %s [%s]\n", pingIntervalStr, getSource("ping-interval"))
	fmt.Printf("  ping-timeout            = %s [%s]\n", pingTimeoutStr, getSource("ping-timeout"))
	fmt.Printf("  udp-proxy-idle-timeout  = %s [%s]\n", udpProxyIdleTimeoutStr, getSource("udp-proxy-idle-timeout"))

	fmt.Println("\nFeatures:")
	fmt.Printf("  disable-clients             = %v [%s]\n", cfg.DisableClients, getSource("disable-clients"))
	fmt.Printf("  disable-ssh                 = %v [%s]\n", cfg.DisableSSH, getSource("disable-ssh"))
	fmt.Printf("  enforce-hc-cert             = %v [%s]\n", cfg.EnforceHealthcheckCert, getSource("enforce-hc-cert"))
	fmt.Printf("  health-file                 = %s [%s]\n", mask("health-file", cfg.HealthFile), getSource("health-file"))
	fmt.Printf("  blueprint-file              = %s [%s]\n", mask("blueprint-file", cfg.BlueprintFile), getSource("blueprint-file"))
	fmt.Printf("  provisioning-blueprint-file = %s [%s]\n", mask("provisioning-blueprint-file", cfg.ProvisioningBlueprintFile), getSource("provisioning-blueprint-file"))
	fmt.Printf("  updown                      = %s [%s]\n", mask("updown", cfg.UpdownScript), getSource("updown"))

	fmt.Println("\nDocker:")
	fmt.Printf("  docker-socket                     = %s [%s]\n", mask("docker-socket", cfg.DockerSocket), getSource("docker-socket"))
	fmt.Printf("  docker-enforce-network-validation = %s [%s]\n", dockerEnforceStr, getSource("docker-enforce-network-validation"))

	fmt.Println("\nAuth Daemon:")
	fmt.Printf("  ad-pre-shared-key           = %s [%s]\n", mask("ad-pre-shared-key", cfg.AuthDaemonKey), getSource("ad-pre-shared-key"))
	fmt.Printf("  ad-principals-file          = %s [%s]\n", cfg.AuthDaemonPrincipalsFile, getSource("ad-principals-file"))
	fmt.Printf("  ad-ca-cert-path             = %s [%s]\n", cfg.AuthDaemonCACertPath, getSource("ad-ca-cert-path"))
	fmt.Printf("  ad-generate-random-password = %v [%s]\n", cfg.AuthDaemonGenerateRandomPassword, getSource("ad-generate-random-password"))

	fmt.Println("\nTLS:")
	fmt.Printf("  tls-client-cert-file = %s [%s]\n", mask("tls-client-cert-file", cfg.TLSClientCert), getSource("tls-client-cert-file"))
	fmt.Printf("  tls-client-key       = %s [%s]\n", mask("tls-client-key", cfg.TLSClientKey), getSource("tls-client-key"))
	fmt.Printf("  tls-client-ca        = %v [%s]\n", cfg.TLSClientCAs, getSource("tls-client-ca"))
	fmt.Printf("  tls-client-cert      = %s [%s] (deprecated PKCS12 path)\n", mask("tls-client-cert", cfg.TLSPrivateKey), getSource("tls-client-cert"))

	fmt.Println("\nMetrics/Observability:")
	fmt.Printf("  metrics             = %v [%s]\n", cfg.MetricsEnabled, getSource("metrics"))
	fmt.Printf("  otlp                = %v [%s]\n", cfg.OTLPEnabled, getSource("otlp"))
	fmt.Printf("  metrics-admin-addr  = %s [%s]\n", cfg.AdminAddr, getSource("metrics-admin-addr"))
	fmt.Printf("  metrics-async-bytes = %v [%s]\n", cfg.MetricsAsyncBytes, getSource("metrics-async-bytes"))
	fmt.Printf("  pprof               = %v [%s]\n", cfg.PprofEnabled, getSource("pprof"))
	fmt.Printf("  region              = %s [%s]\n", cfg.Region, getSource("region"))

	fmt.Println("\n--- Source Legend ---")
	fmt.Println("  default     = Built-in default value")
	fmt.Println("  file        = Loaded from config file")
	fmt.Println("  environment = Set via environment variable")
	fmt.Println("  cli         = Provided as command-line argument")
	fmt.Println("\nPriority: cli > environment > file > default")
	fmt.Println()
}
