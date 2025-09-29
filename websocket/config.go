package websocket

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"runtime"

	"github.com/fosrl/newt/logger"
)

func getConfigPath(clientType string) string {
	configFile := os.Getenv("CONFIG_FILE")
	if configFile == "" {
		var configDir string
		switch runtime.GOOS {
		case "darwin":
			configDir = filepath.Join(os.Getenv("HOME"), "Library", "Application Support", clientType+"-client")
		case "windows":
			logDir := filepath.Join(os.Getenv("PROGRAMDATA"), "olm")
			configDir = filepath.Join(logDir, clientType+"-client")
		default: // linux and others
			configDir = filepath.Join(os.Getenv("HOME"), ".config", clientType+"-client")
		}

		if err := os.MkdirAll(configDir, 0755); err != nil {
			log.Printf("Failed to create config directory: %v", err)
		}

		return filepath.Join(configDir, "config.json")
	}

	return configFile
}

func (c *Client) loadConfig() error {
	if c.config.ID != "" && c.config.Secret != "" && c.config.Endpoint != "" {
		logger.Debug("Config already provided, skipping loading from file")
		return nil
	}

	configPath := getConfigPath(c.clientType)
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

	if c.config.ID == "" {
		c.config.ID = config.ID
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

	logger.Debug("Loaded config from %s", configPath)
	logger.Debug("Config: %+v", c.config)

	return nil
}

func (c *Client) saveConfig() error {
	configPath := getConfigPath(c.clientType)
	data, err := json.MarshalIndent(c.config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configPath, data, 0644)
}
