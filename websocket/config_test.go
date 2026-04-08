package websocket

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig_EmptyFileMarksConfigForSave(t *testing.T) {
	t.Setenv("CONFIG_FILE", "")

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(configPath, []byte(""), 0o644); err != nil {
		t.Fatalf("failed to create empty config file: %v", err)
	}

	client := &Client{
		config: &Config{
			Endpoint:        "https://example.com",
			ProvisioningKey: "spk-test",
		},
		clientType:     "newt",
		configFilePath: configPath,
	}

	if err := client.loadConfig(); err != nil {
		t.Fatalf("loadConfig returned error for empty file: %v", err)
	}

	if !client.configNeedsSave {
		t.Fatal("expected empty config file to mark configNeedsSave")
	}
}

