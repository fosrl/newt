package main

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// resetFlags allows flag.Parse() to be called again in each test, since
// loadNewtConfig registers flags on the global flag.CommandLine.
func resetFlags(t *testing.T) {
	t.Helper()
	oldArgs := os.Args
	oldCommandLine := flag.CommandLine
	t.Cleanup(func() {
		os.Args = oldArgs
		flag.CommandLine = oldCommandLine
	})
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
}

func clearNewtEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"PANGOLIN_ENDPOINT", "NEWT_ID", "NEWT_SECRET", "DNS", "LOG_LEVEL",
		"MTU", "CONFIG_FILE", "NEWT_PROVISIONING_KEY", "NEWT_NAME",
		"DISABLE_SSH", "DISABLE_CLIENTS",
	} {
		t.Setenv(k, "")
	}
}

func TestLoadNewtConfig_Defaults(t *testing.T) {
	resetFlags(t)
	clearNewtEnv(t)
	os.Args = []string{"newt", "--config-file", filepath.Join(t.TempDir(), "missing.json")}

	cfg := loadNewtConfig()

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
	resetFlags(t)
	clearNewtEnv(t)

	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configPath, []byte(`{"dns":"1.1.1.1","mtu":1300,"disableSsh":true}`), 0o644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}
	os.Args = []string{"newt", "--config-file", configPath}

	cfg := loadNewtConfig()

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
	resetFlags(t)
	clearNewtEnv(t)

	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configPath, []byte(`{"dns":"1.1.1.1"}`), 0o644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}
	t.Setenv("DNS", "8.8.4.4")
	os.Args = []string{"newt", "--config-file", configPath}

	cfg := loadNewtConfig()

	if cfg.DNS != "8.8.4.4" {
		t.Errorf("expected env to override file dns, got %q", cfg.DNS)
	}
}

func TestLoadNewtConfig_CLIOverridesEnv(t *testing.T) {
	resetFlags(t)
	clearNewtEnv(t)

	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configPath, []byte(`{"dns":"1.1.1.1"}`), 0o644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}
	t.Setenv("DNS", "8.8.4.4")
	os.Args = []string{"newt", "--config-file", configPath, "--dns", "4.2.2.2"}

	cfg := loadNewtConfig()

	if cfg.DNS != "4.2.2.2" {
		t.Errorf("expected cli to override env dns, got %q", cfg.DNS)
	}
}

func TestLoadNewtConfig_TLSClientCAMergesAcrossSources(t *testing.T) {
	resetFlags(t)
	clearNewtEnv(t)

	tmpDir := t.TempDir()
	caFromFile := filepath.Join(tmpDir, "file-ca.pem")
	caFromEnv := filepath.Join(tmpDir, "env-ca.pem")
	caFromCLI := filepath.Join(tmpDir, "cli-ca.pem")

	configPath := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(configPath, []byte(`{"tlsClientCa":["`+caFromFile+`"]}`), 0o644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}
	t.Setenv("TLS_CLIENT_CAS", caFromEnv)
	os.Args = []string{"newt", "--config-file", configPath, "--tls-client-ca", caFromCLI}

	cfg := loadNewtConfig()

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
	if got := resolveConfigFilePath([]string{"--config-file", "/cli/path/config.json"}); got != "/cli/path/config.json" {
		t.Errorf("expected cli path to win, got %q", got)
	}
	if got := resolveConfigFilePath([]string{"--config-file=/cli/eq/config.json"}); got != "/cli/eq/config.json" {
		t.Errorf("expected cli = path to win, got %q", got)
	}

	// Env wins over default when no CLI flag given.
	if got := resolveConfigFilePath([]string{}); got != "/env/path/config.json" {
		t.Errorf("expected env path, got %q", got)
	}
}
