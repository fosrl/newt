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
	originalConfig := *c.config // Store original config to detect changes
	configPath := getConfigPath(c.clientType)

	if c.config.ID != "" && c.config.Secret != "" && c.config.Endpoint != "" {
		logger.Debug("Config already provided, skipping loading from file")
		// Check if config file exists, if not, we should save it
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			logger.Info("Config file does not exist at %s, will create it", configPath)
			c.configNeedsSave = true
		}
		return nil
	}

	logger.Info("Loading config from: %s", configPath)
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Info("Config file does not exist at %s, will create it with provided values", configPath)
			c.configNeedsSave = true
			return nil
		}
		return err
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}

	// Track what was loaded from file vs provided by CLI
	fileHadID := c.config.ID == ""
	fileHadSecret := c.config.Secret == ""
	fileHadCert := c.config.TlsClientCert == ""
	fileHadEndpoint := c.config.Endpoint == ""

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

	// Check if CLI args provided values that override file values
	if (!fileHadID && originalConfig.ID != "") ||
		(!fileHadSecret && originalConfig.Secret != "") ||
		(!fileHadCert && originalConfig.TlsClientCert != "") ||
		(!fileHadEndpoint && originalConfig.Endpoint != "") {
		logger.Info("CLI arguments provided, config will be updated")
		c.configNeedsSave = true
	}

	logger.Debug("Loaded config from %s", configPath)
	logger.Debug("Config: %+v", c.config)

	return nil
}

func (c *Client) saveConfig() error {
	if !c.configNeedsSave {
		logger.Debug("Config has not changed, skipping save")
		return nil
	}

	configPath := getConfigPath(c.clientType)
	data, err := json.MarshalIndent(c.config, "", "  ")
	if err != nil {
		return err
	}

	logger.Info("Saving config to: %s", configPath)
	err = os.WriteFile(configPath, data, 0644)
	if err == nil {
		c.configNeedsSave = false // Reset flag after successful save
	}
	return err
}
