package newtconfig

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func clearNewtEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"PANGOLIN_ENDPOINT", "NEWT_ID", "NEWT_SECRET", "DNS", "LOG_LEVEL",
		"MTU", "CONFIG_FILE", "NEWT_PROVISIONING_KEY", "NEWT_NAME",
		"DISABLE_SSH", "DISABLE_CLIENTS", "SITE_ID", "SITE_SECRET",
		"USE_NATIVE_INTERFACE", "USE_NATIVE_MAIN_INTERFACE", "USE_KERNEL_MAIN_INTERFACE",
		"INTERFACE", "INTERFACE_MAIN",
	} {
		t.Setenv(k, "")
	}
}

func TestLoadNewtConfig_KernelMainPrecedence(t *testing.T) {
	for _, tt := range []struct {
		name string
		file string
		env  string
		args []string
		want bool
	}{
		{name: "default"},
		{name: "file true", file: `{"kernelMain":true}`, want: true},
		{name: "file false", file: `{"kernelMain":false}`},
		{name: "env true overrides file", file: `{"kernelMain":false}`, env: "true", want: true},
		{name: "env false overrides file", file: `{"kernelMain":true}`, env: "false"},
		{name: "cli true overrides env", file: `{"kernelMain":false}`, env: "false", args: []string{"--kernel-main"}, want: true},
		{name: "cli false overrides env", file: `{"kernelMain":true}`, env: "true", args: []string{"--kernel-main=false"}},
		{name: "cli false overrides file", file: `{"kernelMain":true}`, args: []string{"--kernel-main=false"}},
		{name: "cli false matches default", args: []string{"--kernel-main=false"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			clearNewtEnv(t)
			configPath := filepath.Join(t.TempDir(), "config.json")
			if tt.file != "" {
				if err := os.WriteFile(configPath, []byte(tt.file), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("USE_KERNEL_MAIN_INTERFACE", tt.env)
			args := append([]string{"--config-file", configPath}, tt.args...)
			// Platform is display/build metadata, not an OS validation override.
			cfg, err := Load(Options{Args: args, Platform: "linux"})
			if tt.want && runtime.GOOS != "linux" {
				if err == nil || !strings.Contains(err.Error(), "requires Linux") {
					t.Fatalf("expected Linux-only validation, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load returned error: %v", err)
			}
			if cfg.UseKernelMainInterface != tt.want {
				t.Errorf("kernel main = %v, want %v", cfg.UseKernelMainInterface, tt.want)
			}
			if cfg.UseNativeMainInterface {
				t.Error("kernel-main must not implicitly enable native-main")
			}
			if cfg.NativeMainInterfaceName != "pangolin" {
				t.Errorf("unexpected default main interface name: %q", cfg.NativeMainInterfaceName)
			}
		})
	}
}

func TestLoadNewtConfig_KernelNativeConflict(t *testing.T) {
	clearNewtEnv(t)
	t.Setenv("USE_NATIVE_MAIN_INTERFACE", "true")
	_, err := Load(Options{Args: []string{
		"--config-file", filepath.Join(t.TempDir(), "missing.json"), "--kernel-main",
	}})
	if err == nil || !strings.Contains(err.Error(), "cannot be used together") {
		t.Fatalf("expected conflicting backend error, got %v", err)
	}
}

func TestLoadNewtConfig_SiteIDSecretEnvAliases(t *testing.T) {
	clearNewtEnv(t)
	t.Setenv("SITE_ID", "from-site-id")
	t.Setenv("SITE_SECRET", "from-site-secret")

	cfg, err := Load(Options{Args: []string{"--config-file", filepath.Join(t.TempDir(), "missing.json")}})
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.ID != "from-site-id" {
		t.Errorf("expected id from SITE_ID, got %q", cfg.ID)
	}
	if cfg.Secret != "from-site-secret" {
		t.Errorf("expected secret from SITE_SECRET, got %q", cfg.Secret)
	}
}

func TestLoadNewtConfig_NewtIDSecretWinOverSiteAliases(t *testing.T) {
	clearNewtEnv(t)
	t.Setenv("SITE_ID", "from-site-id")
	t.Setenv("SITE_SECRET", "from-site-secret")
	t.Setenv("NEWT_ID", "from-newt-id")
	t.Setenv("NEWT_SECRET", "from-newt-secret")

	cfg, err := Load(Options{Args: []string{"--config-file", filepath.Join(t.TempDir(), "missing.json")}})
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.ID != "from-newt-id" {
		t.Errorf("expected NEWT_ID to win over SITE_ID, got %q", cfg.ID)
	}
	if cfg.Secret != "from-newt-secret" {
		t.Errorf("expected NEWT_SECRET to win over SITE_SECRET, got %q", cfg.Secret)
	}
}

func TestLoadNewtConfig_Defaults(t *testing.T) {
	clearNewtEnv(t)

	cfg, err := Load(Options{Args: []string{"--config-file", filepath.Join(t.TempDir(), "missing.json")}})
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.DNS != "9.9.9.9" {
		t.Errorf("expected default dns, got %q", cfg.DNS)
	}
	if cfg.MTU != 1280 {
		t.Errorf("expected default mtu 1280, got %d", cfg.MTU)
	}
	if cfg.LogLevel != "INFO" {
		t.Errorf("expected default log level INFO, got %q", cfg.LogLevel)
	}
}

func TestLoadNewtConfig_FileOverridesDefault(t *testing.T) {
	clearNewtEnv(t)

	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configPath, []byte(`{"dns":"1.1.1.1","mtu":1300,"disableSsh":true}`), 0o644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg, err := Load(Options{Args: []string{"--config-file", configPath}})
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.DNS != "1.1.1.1" {
		t.Errorf("expected dns from file, got %q", cfg.DNS)
	}
	if cfg.MTU != 1300 {
		t.Errorf("expected mtu from file, got %d", cfg.MTU)
	}
	if !cfg.DisableSSH {
		t.Errorf("expected disableSsh from file to be true")
	}
}

func TestLoadNewtConfig_EnvOverridesFile(t *testing.T) {
	clearNewtEnv(t)

	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configPath, []byte(`{"dns":"1.1.1.1"}`), 0o644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}
	t.Setenv("DNS", "8.8.4.4")

	cfg, err := Load(Options{Args: []string{"--config-file", configPath}})
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.DNS != "8.8.4.4" {
		t.Errorf("expected env to override file dns, got %q", cfg.DNS)
	}
}

func TestLoadNewtConfig_CLIOverridesEnv(t *testing.T) {
	clearNewtEnv(t)

	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configPath, []byte(`{"dns":"1.1.1.1"}`), 0o644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}
	t.Setenv("DNS", "8.8.4.4")

	cfg, err := Load(Options{Args: []string{"--config-file", configPath, "--dns", "4.2.2.2"}})
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.DNS != "4.2.2.2" {
		t.Errorf("expected cli to override env dns, got %q", cfg.DNS)
	}
}

func TestLoadNewtConfig_TLSClientCAMergesAcrossSources(t *testing.T) {
	clearNewtEnv(t)

	tmpDir := t.TempDir()
	caFromFile := filepath.Join(tmpDir, "file-ca.pem")
	caFromEnv := filepath.Join(tmpDir, "env-ca.pem")
	caFromCLI := filepath.Join(tmpDir, "cli-ca.pem")
	for _, ca := range []string{caFromFile, caFromEnv, caFromCLI} {
		if err := os.WriteFile(ca, []byte("test"), 0o644); err != nil {
			t.Fatalf("failed to write CA file: %v", err)
		}
	}

	configPath := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(configPath, []byte(`{"tlsClientCa":["`+caFromFile+`"]}`), 0o644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}
	t.Setenv("TLS_CLIENT_CAS", caFromEnv)

	cfg, err := Load(Options{Args: []string{"--config-file", configPath, "--tls-client-ca", caFromCLI}})
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	want := map[string]bool{caFromFile: true, caFromEnv: true, caFromCLI: true}
	if len(cfg.TLSClientCAs) != len(want) {
		t.Fatalf("expected %d CA entries, got %v", len(want), cfg.TLSClientCAs)
	}
	for _, ca := range cfg.TLSClientCAs {
		if !want[ca] {
			t.Errorf("unexpected CA entry: %s", ca)
		}
	}
}

func TestResolveConfigFilePath_Precedence(t *testing.T) {
	t.Setenv("CONFIG_FILE", "")
	t.Setenv("HOME", t.TempDir())

	// CLI flag wins over env.
	t.Setenv("CONFIG_FILE", "/env/path/config.json")
	if got := resolveConfigFilePath([]string{"--config-file", "/cli/path/config.json"}, ""); got != "/cli/path/config.json" {
		t.Errorf("expected cli path to win, got %q", got)
	}
	if got := resolveConfigFilePath([]string{"--config-file=/cli/eq/config.json"}, ""); got != "/cli/eq/config.json" {
		t.Errorf("expected cli = path to win, got %q", got)
	}

	// Env wins over default when no CLI flag given.
	if got := resolveConfigFilePath([]string{}, ""); got != "/env/path/config.json" {
		t.Errorf("expected env path, got %q", got)
	}
}
