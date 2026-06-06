package websocket

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/fosrl/newt/logger"
)

func getConfigPath(clientType string, overridePath string) string {
	if overridePath != "" {
		return overridePath
	}
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
	configPath := getConfigPath(c.clientType, c.configFilePath)

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
	if len(bytes.TrimSpace(data)) == 0 {
		logger.Info("Config file at %s is empty, will initialize it with provided values", configPath)
		c.configNeedsSave = true
		return nil
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
	// Always load the provisioning key from the file if not already set
	if c.config.ProvisioningKey == "" {
		c.config.ProvisioningKey = config.ProvisioningKey
	}
	// Always load the name from the file if not already set
	if c.config.Name == "" {
		c.config.Name = config.Name
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

	configPath := getConfigPath(c.clientType, c.configFilePath)
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

// interpolateString replaces {{env.VAR}} tokens in s with the corresponding
// environment variable values. Tokens that do not match a supported scheme are
// left unchanged, mirroring the blueprint interpolation logic.
func interpolateString(s string) string {
	re := regexp.MustCompile(`\{\{([^}]+)\}\}`)
	return re.ReplaceAllStringFunc(s, func(match string) string {
		inner := strings.TrimSpace(match[2 : len(match)-2])
		if strings.HasPrefix(inner, "env.") {
			varName := strings.TrimPrefix(inner, "env.")
			return os.Getenv(varName)
		}
		return match
	})
}

// provisionIfNeeded checks whether a provisioning key is present and, if so,
// exchanges it for a newt ID and secret by calling the registration endpoint.
// On success the config is updated in-place and flagged for saving so that
// subsequent runs use the permanent credentials directly.
func (c *Client) provisionIfNeeded() error {
	if c.config.ProvisioningKey == "" {
		return nil
	}

	// If we already have both credentials there is nothing to provision.
	if c.config.ID != "" && c.config.Secret != "" {
		logger.Debug("Credentials already present, skipping provisioning")
		return nil
	}

	logger.Info("Provisioning key found – exchanging for newt credentials...")

	baseURL, err := url.Parse(c.baseURL)
	if err != nil {
		return fmt.Errorf("failed to parse base URL for provisioning: %w", err)
	}
	baseEndpoint := strings.TrimRight(baseURL.String(), "/")

	// Interpolate any {{env.VAR}} tokens in the name before sending.
	name := interpolateString(c.config.Name)

	reqBody := map[string]interface{}{
		"provisioningKey": c.config.ProvisioningKey,
	}
	if name != "" {
		reqBody["name"] = name
	}
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal provisioning request: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(
		ctx,
		"POST",
		baseEndpoint+"/api/v1/auth/newt/register",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return fmt.Errorf("failed to create provisioning request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", "x-csrf-protection")

	// Mirror the TLS setup used by getToken so mTLS / self-signed CAs work.
	var tlsCfg *tls.Config
	if c.tlsConfig.ClientCertFile != "" || c.tlsConfig.ClientKeyFile != "" ||
		len(c.tlsConfig.CAFiles) > 0 || c.tlsConfig.PKCS12File != "" {
		tlsCfg, err = c.setupTLS()
		if err != nil {
			return fmt.Errorf("failed to setup TLS for provisioning: %w", err)
		}
	}
	if os.Getenv("SKIP_TLS_VERIFY") == "true" {
		if tlsCfg == nil {
			tlsCfg = &tls.Config{}
		}
		tlsCfg.InsecureSkipVerify = true
		logger.Debug("TLS certificate verification disabled for provisioning via SKIP_TLS_VERIFY")
	}

	httpClient := &http.Client{}
	if tlsCfg != nil {
		httpClient.Transport = &http.Transport{TLSClientConfig: tlsCfg}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("provisioning request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	logger.Debug("Provisioning response body: %s", string(body))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("provisioning endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	var provResp ProvisioningResponse
	if err := json.Unmarshal(body, &provResp); err != nil {
		return fmt.Errorf("failed to decode provisioning response: %w", err)
	}

	if !provResp.Success {
		return fmt.Errorf("provisioning failed: %s", provResp.Message)
	}

	if provResp.Data.NewtID == "" || provResp.Data.Secret == "" {
		return fmt.Errorf("provisioning response is missing newt ID or secret")
	}

	logger.Info("Successfully provisioned – newt ID: %s", provResp.Data.NewtID)

	// Persist the returned credentials and clear the one-time provisioning key
	// so subsequent runs authenticate normally.
	c.config.ID = provResp.Data.NewtID
	c.config.Secret = provResp.Data.Secret
	c.config.ProvisioningKey = ""
	c.config.Name = ""
	c.configNeedsSave = true
	c.justProvisioned = true

	// Save immediately so that if the subsequent connection attempt fails the
	// provisioning key is already gone from disk and the next retry uses the
	// permanent credentials instead of trying to provision again.
	if err := c.saveConfig(); err != nil {
		logger.Error("Failed to save config after provisioning: %v", err)
	}

	return nil
}