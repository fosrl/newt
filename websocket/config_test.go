package websocket

import (
	"encoding/json"
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

func TestSaveConfig_PreservesUnrelatedSettings(t *testing.T) {
	t.Setenv("CONFIG_FILE", "")

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")
	initial := `{
  "mtu": 1300,
  "dns": "1.1.1.1",
  "provisioningKey": "spk-test"
}`
	if err := os.WriteFile(configPath, []byte(initial), 0o644); err != nil {
		t.Fatalf("failed to create config file: %v", err)
	}

	client := &Client{
		config: &Config{
			ID:       "newt-id",
			Secret:   "newt-secret",
			Endpoint: "https://example.com",
			// ProvisioningKey cleared, simulating a completed provisioning exchange.
		},
		clientType:      "newt",
		configFilePath:  configPath,
		configNeedsSave: true,
	}

	if err := client.saveConfig(); err != nil {
		t.Fatalf("saveConfig returned error: %v", err)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("failed to read saved config: %v", err)
	}

	var saved map[string]interface{}
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatalf("saved config is not valid JSON: %v", err)
	}

	if saved["mtu"] != float64(1300) {
		t.Errorf("expected mtu to be preserved, got %v", saved["mtu"])
	}
	if saved["dns"] != "1.1.1.1" {
		t.Errorf("expected dns to be preserved, got %v", saved["dns"])
	}
	if saved["id"] != "newt-id" {
		t.Errorf("expected id to be updated, got %v", saved["id"])
	}
	if saved["secret"] != "newt-secret" {
		t.Errorf("expected secret to be updated, got %v", saved["secret"])
	}
	if _, ok := saved["provisioningKey"]; ok {
		t.Errorf("expected provisioningKey to be cleared after provisioning, got %v", saved["provisioningKey"])
	}
	if client.configNeedsSave {
		t.Error("expected configNeedsSave to be reset after a successful save")
	}
}

