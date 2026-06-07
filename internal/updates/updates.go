package updates

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// GitHubRelease represents the GitHub API response for a release
type GitHubRelease struct {
	TagName string `json:"tag_name"`
	Name    string `json:"name"`
	HTMLURL string `json:"html_url"`
}

// Version represents a semantic version
type Version struct {
	Major int
	Minor int
	Patch int
}

// parseVersion parses a semantic version string (e.g., "v1.2.3" or "1.2.3")
func parseVersion(versionStr string) (Version, error) {
	// Remove 'v' prefix if present
	versionStr = strings.TrimPrefix(versionStr, "v")

	parts := strings.Split(versionStr, ".")
	if len(parts) != 3 {
		return Version{}, fmt.Errorf("invalid version format: %s", versionStr)
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return Version{}, fmt.Errorf("invalid major version: %s", parts[0])
	}

	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return Version{}, fmt.Errorf("invalid minor version: %s", parts[1])
	}

	patch, err := strconv.Atoi(parts[2])
	if err != nil {
		return Version{}, fmt.Errorf("invalid patch version: %s", parts[2])
	}

	return Version{Major: major, Minor: minor, Patch: patch}, nil
}

// isNewer returns true if v2 is newer than v1
func (v1 Version) isNewer(v2 Version) bool {
	if v2.Major > v1.Major {
		return true
	}
	if v2.Major < v1.Major {
		return false
	}

	if v2.Minor > v1.Minor {
		return true
	}
	if v2.Minor < v1.Minor {
		return false
	}

	return v2.Patch > v1.Patch
}

// String returns the version as a string
func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// CheckForUpdate checks GitHub for a newer version and prints an update banner if found
func CheckForUpdate(owner, repo, currentVersion string) error {
	if currentVersion == "version_replaceme" {
		return nil
	}

	// GitHub API URL for latest release
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", owner, repo)

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Make the request
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("failed to fetch release info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GitHub API returned status: %d", resp.StatusCode)
	}

	// Parse the JSON response
	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return fmt.Errorf("failed to parse release info: %w", err)
	}

	// Parse current and latest versions
	currentVer, err := parseVersion(currentVersion)
	if err != nil {
		return fmt.Errorf("invalid current version: %w", err)
	}

	latestVer, err := parseVersion(release.TagName)
	if err != nil {
		return fmt.Errorf("invalid latest version: %w", err)
	}

	// Check if update is available
	if currentVer.isNewer(latestVer) {
		printUpdateBanner(currentVer.String(), latestVer.String(), "curl -fsSL https://static.pangolin.net/get-newt.sh | bash")
	}

	return nil
}

// printUpdateBanner prints a colorful update notification banner
func printUpdateBanner(currentVersion, latestVersion, releaseURL string) {
	const contentWidth = 70 // width between the border lines

	borderTop := "╔" + strings.Repeat("═", contentWidth) + "╗"
	borderMid := "╠" + strings.Repeat("═", contentWidth) + "╣"
	borderBot := "╚" + strings.Repeat("═", contentWidth) + "╝"
	emptyLine := "║" + strings.Repeat(" ", contentWidth) + "║"

	lines := []string{
		borderTop,
		"║" + centerText("UPDATE AVAILABLE", contentWidth) + "║",
		borderMid,
		emptyLine,
		"║  Current Version: " + padRight(currentVersion, contentWidth-19) + "║",
		"║  Latest Version:  " + padRight(latestVersion, contentWidth-19) + "║",
		emptyLine,
		"║  A newer version is available! Please update to get the" + padRight("", contentWidth-56) + "║",
		"║  latest features, bug fixes, and security improvements." + padRight("", contentWidth-56) + "║",
		emptyLine,
		"║  Update: " + padRight(releaseURL, contentWidth-10) + "║",
		emptyLine,
		borderBot,
	}

	for _, line := range lines {
		fmt.Println(line)
	}
}

// padRight pads s with spaces on the right to the given width
func padRight(s string, width int) string {
	if len(s) > width {
		return s[:width]
	}
	return s + strings.Repeat(" ", width-len(s))
}

// centerText centers s in a field of width w
func centerText(s string, w int) string {
	if len(s) >= w {
		return s[:w]
	}
	padding := (w - len(s)) / 2
	return strings.Repeat(" ", padding) + s + strings.Repeat(" ", w-len(s)-padding)
}
