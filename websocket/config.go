package websocket

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"runtime"
)

func getConfigPath() string {
	var configDir string
	switch runtime.GOOS {
	case "darwin":
		configDir = filepath.Join(os.Getenv("HOME"), "Library", "Application Support", "newt-client")
	case "windows":
		configDir = filepath.Join(os.Getenv("APPDATA"), "newt-client")
	default: // linux and others
		configDir = filepath.Join(os.Getenv("HOME"), ".config", "newt-client")
	}

	if err := os.MkdirAll(configDir, 0755); err != nil {
		log.Printf("Failed to create config directory: %v", err)
	}

	return filepath.Join(configDir, "config.json")
}

func (c *Client) loadConfig() error {
	if c.config.NewtID != "" && c.config.Secret != "" && c.config.Endpoint != "" {
		return nil
	}

	configPath := getConfigPath()
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}

	if c.config.NewtID == "" {
		c.config.NewtID = config.NewtID
	}
	if c.config.Token == "" {
		c.config.Token = config.Token
	}
	if c.config.Secret == "" {
		c.config.Secret = config.Secret
	}
	if c.config.TlsClientCert == "" {
		c.config.TlsClientCert = config.TlsClientCert
	}
	if c.config.Endpoint == "" {
		c.config.Endpoint = config.Endpoint
		c.baseURL = config.Endpoint
	}

	return nil
}

func (c *Client) saveConfig() error {
	configPath := getConfigPath()
	data, err := json.MarshalIndent(c.config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configPath, data, 0644)
}
