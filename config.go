package main

import (
	"flag"
	"fmt"
	"os"
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

// loadNewtConfig reads environment variables and command-line flags, then
// returns a populated newtpkg.Config. This function calls flag.Parse internally
// and will exit the process if --version is passed.
func loadNewtConfig() newtpkg.Config {
	// ---- read environment variables first ----
	cfg := newtpkg.Config{
		Version:  newtVersion,
		Platform: newtPlatform,

		Endpoint:        os.Getenv("PANGOLIN_ENDPOINT"),
		ID:              os.Getenv("NEWT_ID"),
		Secret:          os.Getenv("NEWT_SECRET"),
		DNS:             os.Getenv("DNS"),
		LogLevel:        os.Getenv("LOG_LEVEL"),
		UpdownScript:    os.Getenv("UPDOWN_SCRIPT"),
		InterfaceName:   os.Getenv("INTERFACE"),
		DockerSocket:    os.Getenv("DOCKER_SOCKET"),
		HealthFile:      os.Getenv("HEALTH_FILE"),
		BlueprintFile:   os.Getenv("BLUEPRINT_FILE"),
		ConfigFile:      os.Getenv("CONFIG_FILE"),
		ProvisioningKey: os.Getenv("NEWT_PROVISIONING_KEY"),
		NewtName:        os.Getenv("NEWT_NAME"),
		TLSClientCert:   os.Getenv("TLS_CLIENT_CERT"),
		TLSClientKey:    os.Getenv("TLS_CLIENT_KEY"),
		TLSPrivateKey:   os.Getenv("TLS_CLIENT_CERT_PKCS12"),

		AuthDaemonKey:            os.Getenv("AD_KEY"),
		AuthDaemonPrincipalsFile: os.Getenv("AD_PRINCIPALS_FILE"),
		AuthDaemonCACertPath:     os.Getenv("AD_CA_CERT_PATH"),

		NativeMainInterfaceName:   os.Getenv("INTERFACE_MAIN"),
		ProvisioningBlueprintFile: os.Getenv("PROVISIONING_BLUEPRINT_FILE"),
		Region:                    os.Getenv("NEWT_REGION"),
		AdminAddr:                 os.Getenv("NEWT_ADMIN_ADDR"),
	}

	// Legacy PKCS12 backward-compat: fall back to TLS_CLIENT_CERT for PKCS12
	// when the newer env vars are not set.
	if cfg.TLSPrivateKey == "" && cfg.TLSClientKey == "" && len(cfg.TLSClientCAs) == 0 {
		cfg.TLSPrivateKey = os.Getenv("TLS_CLIENT_CERT")
	}

	// TLS CA files: comma-separated list from env
	if tlsClientCAsEnv := os.Getenv("TLS_CLIENT_CAS"); tlsClientCAsEnv != "" {
		for _, ca := range strings.Split(tlsClientCAsEnv, ",") {
			cfg.TLSClientCAs = append(cfg.TLSClientCAs, strings.TrimSpace(ca))
		}
	}

	// Boolean env vars
	disableClientsEnv := os.Getenv("DISABLE_CLIENTS")
	disableSSHEnv := os.Getenv("DISABLE_SSH")
	useNativeInterfaceEnv := os.Getenv("USE_NATIVE_INTERFACE")
	useNativeMainInterfaceEnv := os.Getenv("USE_NATIVE_MAIN_INTERFACE")
	enforceHealthcheckCertEnv := os.Getenv("ENFORCE_HC_CERT")
	noCloudEnv := os.Getenv("NO_CLOUD")
	adGenerateRandomPasswordEnv := os.Getenv("AD_GENERATE_RANDOM_PASSWORD")

	cfg.DisableClients = disableClientsEnv == "true"
	cfg.DisableSSH = disableSSHEnv == "true"
	cfg.UseNativeInterface = useNativeInterfaceEnv == "true"
	cfg.UseNativeMainInterface = useNativeMainInterfaceEnv == "true"
	cfg.EnforceHealthcheckCert = enforceHealthcheckCertEnv == "true"
	cfg.NoCloud = noCloudEnv == "true"

	if v, err := strconv.ParseBool(adGenerateRandomPasswordEnv); err == nil {
		cfg.AuthDaemonGenerateRandomPassword = v
	}

	// Metrics env vars (parsing happens below after flag.Parse)
	metricsEnabledEnv := os.Getenv("NEWT_METRICS_PROMETHEUS_ENABLED")
	otlpEnabledEnv := os.Getenv("NEWT_METRICS_OTLP_ENABLED")
	asyncBytesEnv := os.Getenv("NEWT_METRICS_ASYNC_BYTES")
	pprofEnabledEnv := os.Getenv("NEWT_PPROF_ENABLED")

	if metricsEnabledEnv != "" {
		if v, err := strconv.ParseBool(metricsEnabledEnv); err == nil {
			cfg.MetricsEnabled = v
		} else {
			cfg.MetricsEnabled = true
		}
	}
	if v, err := strconv.ParseBool(otlpEnabledEnv); err == nil {
		cfg.OTLPEnabled = v
	}
	if v, err := strconv.ParseBool(asyncBytesEnv); err == nil {
		cfg.MetricsAsyncBytes = v
	}
	if v, err := strconv.ParseBool(pprofEnabledEnv); err == nil {
		cfg.PprofEnabled = v
	}

	// Numeric / duration env vars (kept as strings; parsed after flag.Parse)
	mtuStr := os.Getenv("MTU")
	portStr := os.Getenv("PORT")
	pingIntervalStr := os.Getenv("PING_INTERVAL")
	pingTimeoutStr := os.Getenv("PING_TIMEOUT")
	udpProxyIdleTimeoutStr := os.Getenv("NEWT_UDP_PROXY_IDLE_TIMEOUT")
	dockerEnforceStr := os.Getenv("DOCKER_ENFORCE_NETWORK_VALIDATION")

	// ---- register CLI flags (only when env was not set) ----

	if cfg.Endpoint == "" {
		flag.StringVar(&cfg.Endpoint, "endpoint", "", "Endpoint of your pangolin server")
	}
	if cfg.ID == "" {
		flag.StringVar(&cfg.ID, "id", "", "Newt ID")
	}
	if cfg.Secret == "" {
		flag.StringVar(&cfg.Secret, "secret", "", "Newt secret")
	}
	if mtuStr == "" {
		flag.StringVar(&mtuStr, "mtu", "1280", "MTU to use")
	}
	if cfg.DNS == "" {
		flag.StringVar(&cfg.DNS, "dns", "9.9.9.9", "DNS server to use")
	}
	if cfg.LogLevel == "" {
		flag.StringVar(&cfg.LogLevel, "log-level", "INFO", "Log level (DEBUG, INFO, WARN, ERROR, FATAL)")
	}
	if cfg.UpdownScript == "" {
		flag.StringVar(&cfg.UpdownScript, "updown", "", "Path to updown script to be called when targets are added or removed")
	}
	if cfg.InterfaceName == "" {
		flag.StringVar(&cfg.InterfaceName, "interface", "newt", "Name of the WireGuard interface")
	}
	if portStr == "" {
		flag.StringVar(&portStr, "port", "", "Port for client WireGuard interface")
	}
	if useNativeInterfaceEnv == "" {
		flag.BoolVar(&cfg.UseNativeInterface, "native", false, "Use native WireGuard interface for client tunnels")
	}
	if useNativeMainInterfaceEnv == "" {
		flag.BoolVar(&cfg.UseNativeMainInterface, "native-main", false, "Use native WireGuard interface for the main tunnel (instead of netstack)")
	}
	if cfg.NativeMainInterfaceName == "" {
		flag.StringVar(&cfg.NativeMainInterfaceName, "interface-main", "newtm", "Name of the native main tunnel WireGuard interface (used with --native-main)")
	}
	if disableClientsEnv == "" {
		flag.BoolVar(&cfg.DisableClients, "disable-clients", false, "Disable clients on the WireGuard interface")
	}
	if disableSSHEnv == "" {
		flag.BoolVar(&cfg.DisableSSH, "disable-ssh", false, "Disable SSH auth daemon and native SSH mode (remote auth daemon still works)")
	}
	if enforceHealthcheckCertEnv == "" {
		flag.BoolVar(&cfg.EnforceHealthcheckCert, "enforce-hc-cert", false, "Enforce certificate validation for health checks (default: false, accepts any cert)")
	}
	if cfg.DockerSocket == "" {
		flag.StringVar(&cfg.DockerSocket, "docker-socket", "", "Path or address to Docker socket (typically unix:///var/run/docker.sock)")
	}
	if pingIntervalStr == "" {
		flag.StringVar(&pingIntervalStr, "ping-interval", "15s", "Interval for pinging the server (default 15s)")
	}
	if pingTimeoutStr == "" {
		flag.StringVar(&pingTimeoutStr, "ping-timeout", "7s", "Timeout for each ping (default 7s)")
	}
	if udpProxyIdleTimeoutStr == "" {
		flag.StringVar(&udpProxyIdleTimeoutStr, "udp-proxy-idle-timeout", "90s", "Idle timeout for UDP proxied client flows before cleanup")
	}
	flag.StringVar(&cfg.PreferEndpoint, "prefer-endpoint", "", "Prefer this endpoint for the connection (if set, will override the endpoint from the server)")
	if cfg.ProvisioningKey == "" {
		flag.StringVar(&cfg.ProvisioningKey, "provisioning-key", "", "One-time provisioning key used to obtain a newt ID and secret from the server")
	}
	if cfg.NewtName == "" {
		flag.StringVar(&cfg.NewtName, "name", "", "Name for the site created during provisioning (supports {{env.VAR}} interpolation)")
	}
	if cfg.ConfigFile == "" {
		flag.StringVar(&cfg.ConfigFile, "config-file", "", "Path to config file (overrides CONFIG_FILE env var and default location)")
	}
	if cfg.TLSClientCert == "" {
		flag.StringVar(&cfg.TLSClientCert, "tls-client-cert-file", "", "Path to client certificate file (PEM/DER format)")
	}
	if cfg.TLSClientKey == "" {
		flag.StringVar(&cfg.TLSClientKey, "tls-client-key", "", "Path to client private key file (PEM/DER format)")
	}
	// Backward-compat dummy flag (auth daemon is always enabled now)
	flag.Bool("auth-daemon", false, "Enable auth daemon mode (deprecated, always enabled)")

	var tlsClientCAsFlag stringSlice
	flag.Var(&tlsClientCAsFlag, "tls-client-ca", "Path to CA certificate file for validating remote certificates (can be specified multiple times)")

	if cfg.TLSPrivateKey == "" {
		flag.StringVar(&cfg.TLSPrivateKey, "tls-client-cert", "", "Path to client certificate (PKCS12 format) - DEPRECATED: use --tls-client-cert-file and --tls-client-key instead")
	}
	if dockerEnforceStr == "" {
		flag.StringVar(&dockerEnforceStr, "docker-enforce-network-validation", "false", "Enforce validation of container on newt network (true or false)")
	}
	if cfg.HealthFile == "" {
		flag.StringVar(&cfg.HealthFile, "health-file", "", "Path to health file (if unset, health file won't be written)")
	}
	if cfg.BlueprintFile == "" {
		flag.StringVar(&cfg.BlueprintFile, "blueprint-file", "", "Path to blueprint file (if unset, no blueprint will be applied)")
	}
	if cfg.ProvisioningBlueprintFile == "" {
		flag.StringVar(&cfg.ProvisioningBlueprintFile, "provisioning-blueprint-file", "", "Path to blueprint file applied once after a provisioning credential exchange (if unset, no provisioning blueprint will be applied)")
	}
	if noCloudEnv == "" {
		flag.BoolVar(&cfg.NoCloud, "no-cloud", false, "Disable cloud failover")
	}
	if metricsEnabledEnv == "" {
		flag.BoolVar(&cfg.MetricsEnabled, "metrics", false, "Enable Prometheus metrics exporter")
	}
	if otlpEnabledEnv == "" {
		flag.BoolVar(&cfg.OTLPEnabled, "otlp", false, "Enable OTLP exporters (metrics/traces) to OTEL_EXPORTER_OTLP_ENDPOINT")
	}
	if cfg.AdminAddr == "" {
		flag.StringVar(&cfg.AdminAddr, "metrics-admin-addr", "127.0.0.1:2112", "Admin/metrics bind address")
	}
	if asyncBytesEnv == "" {
		flag.BoolVar(&cfg.MetricsAsyncBytes, "metrics-async-bytes", false, "Enable async bytes counting (background flush; lower hot path overhead)")
	}
	if pprofEnabledEnv == "" {
		flag.BoolVar(&cfg.PprofEnabled, "pprof", false, "Enable pprof debug endpoints on admin server")
	}
	if cfg.Region == "" {
		flag.StringVar(&cfg.Region, "region", "", "Optional region resource attribute (also NEWT_REGION)")
	}
	if cfg.AuthDaemonKey == "" {
		flag.StringVar(&cfg.AuthDaemonKey, "ad-pre-shared-key", "", "Pre-shared key for auth daemon authentication")
	}
	if cfg.AuthDaemonPrincipalsFile == "" {
		flag.StringVar(&cfg.AuthDaemonPrincipalsFile, "ad-principals-file", "/var/run/auth-daemon/principals", "Path to the principals file for auth daemon")
	}
	if cfg.AuthDaemonCACertPath == "" {
		flag.StringVar(&cfg.AuthDaemonCACertPath, "ad-ca-cert-path", "/etc/ssh/ca.pem", "Path to the CA certificate file for auth daemon")
	}
	if adGenerateRandomPasswordEnv == "" {
		flag.BoolVar(&cfg.AuthDaemonGenerateRandomPassword, "ad-generate-random-password", false, "Generate a random password for authenticated users")
	}

	version := flag.Bool("version", false, "Print the version")

	flag.Parse()

	// ---- post-parse processing ----

	// Merge CLI CA files with env CA files
	if len(tlsClientCAsFlag) > 0 {
		cfg.TLSClientCAs = append(cfg.TLSClientCAs, tlsClientCAsFlag...)
	}

	// Version check (exits process)
	if *version {
		fmt.Println("Newt version " + newtVersion)
		os.Exit(0)
	} else {
		logger.Info("Newt version %s", newtVersion)
	}

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
	if dockerEnforceStr != "" {
		if v, err := strconv.ParseBool(dockerEnforceStr); err == nil {
			cfg.DockerEnforceNetworkValidation = v
		} else {
			logger.Info("Docker enforce network validation cannot be parsed. Defaulting to 'false'")
			cfg.DockerEnforceNetworkValidation = false
		}
	}

	// Parse durations (after flag.Parse so CLI flags take effect)
	cfg.PingInterval = parseDurationEnvOrFlag(pingIntervalStr, 15*time.Second, "PING_INTERVAL")
	cfg.PingTimeout = parseDurationEnvOrFlag(pingTimeoutStr, 7*time.Second, "PING_TIMEOUT")
	cfg.UDPProxyIdleTimeout = parseDurationEnvOrFlag(udpProxyIdleTimeoutStr, 90*time.Second, "NEWT_UDP_PROXY_IDLE_TIMEOUT")

	return cfg
}
