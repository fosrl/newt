package updates

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/fosrl/newt/logger"
)

// SelfUpdateConfig holds the configuration required to perform a self-update.
type SelfUpdateConfig struct {
	// Endpoint is the base URL of the pangolin server (e.g. "https://app.pangolin.net")
	Endpoint string
	// NewtID is the newt client identifier used for authentication.
	NewtID string
	// Secret is the newt client secret used for authentication.
	Secret string
	// CurrentVersion is the version of the currently running binary.
	CurrentVersion string
	// Platform is the OS+arch string embedded at build time via ldflags
	// (e.g. "linux_amd64", "darwin_arm64").  When non-empty it is used
	// directly; when empty the value is derived from runtime.GOOS/GOARCH.
	Platform string
	// TLSConfig is an optional TLS configuration for the HTTP client (may be nil).
	TLSConfig *tls.Config
}

// versionResponse mirrors the JSON returned by POST /api/v1/auth/newt/version
type versionResponse struct {
	Data struct {
		LatestVersion   string `json:"latestVersion"`
		CurrentIsLatest bool   `json:"currentIsLatest"`
		DownloadUrl     string `json:"downloadUrl"`
		Sha256          string `json:"sha256"`
	} `json:"data"`
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// isOfficialContainer returns true when the process is running inside an
// official Fossorial-built container image.  The image sets
// NEWT_SYSTEM_SUBSTRATE="CONTAINER" at build time; users running newt in their own
// containers (or bare-metal) will not have this variable set.
func isOfficialContainer() bool {
	return os.Getenv("NEWT_SYSTEM_SUBSTRATE") == "CONTAINER"
}

// platform returns the OS+arch string used in the newt release binary names,
// e.g. "linux_amd64", "darwin_arm64", "windows_amd64".
// It is used as a fallback when no platform was embedded at build time.
func platform() string {
	goarch := runtime.GOARCH
	goos := runtime.GOOS

	// Map Go arch names to the names used by newt releases
	archMap := map[string]string{
		"amd64":   "amd64",
		"arm64":   "arm64",
		"arm":     "arm32",
		"riscv64": "riscv64",
	}

	arch, ok := archMap[goarch]
	if !ok {
		arch = goarch
	}

	return fmt.Sprintf("%s_%s", goos, arch)
}

// verifySHA256 checks that the file at path has the expected SHA-256 hex digest.
func verifySHA256(path, expected string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open file for hashing: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("failed to hash file: %w", err)
	}

	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, expected) {
		return fmt.Errorf("sha256 mismatch: expected %s, got %s", expected, got)
	}
	return nil
}

// CheckAndSelfUpdate contacts the pangolin server, checks whether a newer
// version of newt is available, downloads it if so, replaces the running
// binary on disk, and re-executes from the new binary.
//
// It returns an error when the check or update fails.  On a successful update
// the function does not return – the process is replaced by the new binary via
// syscall.Exec.
func CheckAndSelfUpdate(cfg SelfUpdateConfig) error {
	logger.Debug("checkAndSelfUpdate: starting update check (currentVersion=%s)", cfg.CurrentVersion)

	if isOfficialContainer() {
		logger.Debug("checkAndSelfUpdate: running inside official container, skipping auto-update")
		return fmt.Errorf("auto-update is not supported in official Fossorial container images; pull a new image tag instead")
	}

	if cfg.CurrentVersion == "version_replaceme" {
		logger.Debug("checkAndSelfUpdate: development build detected, skipping auto-update")
		return fmt.Errorf("cannot auto-update a development build (version_replaceme)")
	}

	baseEndpoint := strings.TrimRight(cfg.Endpoint, "/")

	// Build the HTTP client.
	httpClient := &http.Client{Timeout: 30 * time.Second}
	if cfg.TLSConfig != nil {
		httpClient.Transport = &http.Transport{TLSClientConfig: cfg.TLSConfig}
	}

	// Check the current binary path before we do anything else so we can fail
	// fast if the executable path cannot be determined.
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to determine current executable path: %w", err)
	}
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		return fmt.Errorf("failed to resolve symlinks for executable path: %w", err)
	}
	logger.Debug("checkAndSelfUpdate: current executable path: %s", exePath)

	// --- Step 1: Ask the server for the latest version ---
	plat := cfg.Platform
	if plat == "" {
		plat = platform()
	}
	logger.Debug("checkAndSelfUpdate: querying server for latest version (platform=%s, endpoint=%s)", plat, baseEndpoint)
	reqBody, err := json.Marshal(map[string]string{
		"newtId":   cfg.NewtID,
		"secret":   cfg.Secret,
		"platform": plat,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal version request: %w", err)
	}

	versionURL, err := url.JoinPath(baseEndpoint, "/api/v1/auth/newt/version")
	if err != nil {
		return fmt.Errorf("failed to build version URL: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", versionURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return fmt.Errorf("failed to create version request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", "x-csrf-protection")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to request version info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent { // updates are disabled
		logger.Debug("checkAndSelfUpdate: server indicated updates are disabled (204 No Content)")
		return nil
	}

	if resp.StatusCode == http.StatusNotFound { // older server without version endpoint
		logger.Debug("checkAndSelfUpdate: server does not support version endpoint (404 Not Found), skipping")
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}

	var verResp versionResponse
	if err := json.NewDecoder(resp.Body).Decode(&verResp); err != nil {
		return fmt.Errorf("failed to parse version response: %w", err)
	}

	if !verResp.Success {
		return fmt.Errorf("server error: %s", verResp.Message)
	}

	if verResp.Data.CurrentIsLatest {
		logger.Debug("checkAndSelfUpdate: already up to date (%s)", cfg.CurrentVersion)
		return nil
	}

	logger.Debug("checkAndSelfUpdate: update available %s → %s", cfg.CurrentVersion, verResp.Data.LatestVersion)

	// --- Pre-download: verify we can write to the binary's directory ---
	// Do this before downloading so a permission failure doesn't waste bandwidth.
	exeDir := filepath.Dir(exePath)
	logger.Debug("checkAndSelfUpdate: verifying write access to %s", exeDir)
	writeTestFile, err := os.CreateTemp(exeDir, ".newt-write-test-*")
	if err != nil {
		return fmt.Errorf("cannot write to %s (you may need to run as root or with elevated permissions): %w", exeDir, err)
	}
	writeTestFile.Close()
	_ = os.Remove(writeTestFile.Name())

	// --- Step 2: Download the new binary ---
	logger.Debug("checkAndSelfUpdate: beginning download of new binary")
	dlCtx, dlCancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer dlCancel()

	dlReq, err := http.NewRequestWithContext(dlCtx, "GET", verResp.Data.DownloadUrl, nil)
	if err != nil {
		return fmt.Errorf("failed to create download request: %w", err)
	}

	dlResp, err := httpClient.Do(dlReq)
	if err != nil {
		return fmt.Errorf("failed to download new binary: %w", err)
	}
	defer dlResp.Body.Close()

	if dlResp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with status %d", dlResp.StatusCode)
	}

	// Write to a temp file in the same directory as the current binary so that
	// an atomic rename works even across filesystem boundaries.
	tmpFile, err := os.CreateTemp(exeDir, ".newt-update-*")
	tmpPath := tmpFile.Name()

	// Ensure the temp file is cleaned up on any error path.
	defer func() {
		_ = os.Remove(tmpPath)
	}()

	if _, err := io.Copy(tmpFile, dlResp.Body); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to write downloaded binary: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	// --- Verify SHA256 checksum if the server provided one ---
	if verResp.Data.Sha256 != "" {
		logger.Debug("checkAndSelfUpdate: verifying SHA256 checksum")
		if err := verifySHA256(tmpPath, verResp.Data.Sha256); err != nil {
			return fmt.Errorf("binary integrity check failed: %w", err)
		}
		logger.Debug("checkAndSelfUpdate: SHA256 checksum verified")
	} else {
		logger.Debug("checkAndSelfUpdate: no SHA256 checksum provided by server, skipping verification")
	}

	// Make the new binary executable.
	if err := os.Chmod(tmpPath, 0755); err != nil {
		return fmt.Errorf("failed to set executable permission: %w", err)
	}

	// --- Step 3: Replace the running binary ---
	// On Unix an atomic rename works even while the file is running.
	logger.Debug("checkAndSelfUpdate: replacing binary at %s", exePath)
	if err := os.Rename(tmpPath, exePath); err != nil {
		return fmt.Errorf("failed to replace binary (you may need to run as root): %w", err)
	}

	systemSubstrate := os.Getenv("NEWT_SYSTEM_SUBSTRATE")
	logger.Debug("checkAndSelfUpdate: system substrate: %s", systemSubstrate)
	if systemSubstrate == "ADVANTECH_ROUTER_APP" {
		pidFile := os.Getenv("NEWT_PID_FILE")
		if err := postUpdateAdvantech(verResp.Data.LatestVersion, pidFile); err != nil {
			logger.Debug("checkAndSelfUpdate: advantech post-update steps failed: %v", err)
		}
	}

	// --- Step 4: Re-exec ---
	logger.Debug("checkAndSelfUpdate: re-executing new binary")
	return reexec(exePath)
}
