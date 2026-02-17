//go:build linux

package authdaemon

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/fosrl/newt/logger"
)

// writeCACertIfNotExists writes contents to path only if the file does not exist.
func writeCACertIfNotExists(path, contents string) error {
	if _, err := os.Stat(path); err == nil {
		logger.Debug("auth-daemon: CA cert already exists at %s, skipping write", path)
		return nil
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	contents = strings.TrimSpace(contents)
	if contents != "" && !strings.HasSuffix(contents, "\n") {
		contents += "\n"
	}
	if err := os.WriteFile(path, []byte(contents), 0644); err != nil {
		return fmt.Errorf("write CA cert: %w", err)
	}
	logger.Info("auth-daemon: wrote CA cert to %s", path)
	return nil
}

// ensureSSHDTrustedUserCAKeys ensures sshd_config contains TrustedUserCAKeys caCertPath.
func ensureSSHDTrustedUserCAKeys(sshdConfigPath, caCertPath string) error {
	if sshdConfigPath == "" {
		sshdConfigPath = "/etc/ssh/sshd_config"
	}
	data, err := os.ReadFile(sshdConfigPath)
	if err != nil {
		return fmt.Errorf("read sshd_config: %w", err)
	}
	directive := "TrustedUserCAKeys " + caCertPath
	lines := strings.Split(string(data), "\n")
	found := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		// strip inline comment
		if idx := strings.Index(trimmed, "#"); idx >= 0 {
			trimmed = strings.TrimSpace(trimmed[:idx])
		}
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "TrustedUserCAKeys") {
			if strings.TrimSpace(trimmed) == directive {
				logger.Debug("auth-daemon: sshd_config already has TrustedUserCAKeys %s", caCertPath)
				return nil
			}
			lines[i] = directive
			found = true
			break
		}
	}
	if !found {
		lines = append(lines, directive)
	}
	out := strings.Join(lines, "\n")
	if !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	if err := os.WriteFile(sshdConfigPath, []byte(out), 0644); err != nil {
		return fmt.Errorf("write sshd_config: %w", err)
	}
	logger.Info("auth-daemon: updated %s with TrustedUserCAKeys %s", sshdConfigPath, caCertPath)
	return nil
}

// reloadSSHD runs the given shell command to reload sshd (e.g. "systemctl reload sshd").
func reloadSSHD(reloadCmd string) error {
	if reloadCmd == "" {
		return nil
	}
	cmd := exec.Command("sh", "-c", reloadCmd)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("reload sshd %q: %w (output: %s)", reloadCmd, err, string(out))
	}
	logger.Info("auth-daemon: reloaded sshd")
	return nil
}

// writePrincipals updates the principals file at path: JSON object keyed by username, value is array of principals. Adds username and niceId to that user's list (deduped).
func writePrincipals(path, username, niceId string) error {
	if path == "" {
		return nil
	}
	username = strings.TrimSpace(username)
	niceId = strings.TrimSpace(niceId)
	if username == "" {
		return nil
	}
	data := make(map[string][]string)
	if raw, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(raw, &data)
	}
	list := data[username]
	seen := make(map[string]struct{}, len(list)+2)
	for _, p := range list {
		seen[p] = struct{}{}
	}
	for _, p := range []string{username, niceId} {
		if p == "" {
			continue
		}
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			list = append(list, p)
		}
	}
	data[username] = list
	body, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal principals: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	if err := os.WriteFile(path, body, 0644); err != nil {
		return fmt.Errorf("write principals: %w", err)
	}
	logger.Debug("auth-daemon: wrote principals to %s", path)
	return nil
}

// sudoGroup returns the name of the sudo group (wheel or sudo) that exists on the system. Prefers wheel.
func sudoGroup() string {
	f, err := os.Open("/etc/group")
	if err != nil {
		return "sudo"
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	hasWheel := false
	hasSudo := false
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "wheel:") {
			hasWheel = true
		}
		if strings.HasPrefix(line, "sudo:") {
			hasSudo = true
		}
	}
	if hasWheel {
		return "wheel"
	}
	if hasSudo {
		return "sudo"
	}
	return "sudo"
}

// ensureUser creates the system user if missing, or reconciles sudo and homedir to match meta.
func ensureUser(username string, meta ConnectionMetadata) error {
	if username == "" {
		return nil
	}
	u, err := user.Lookup(username)
	if err != nil {
		if _, ok := err.(user.UnknownUserError); !ok {
			return fmt.Errorf("lookup user %s: %w", username, err)
		}
		return createUser(username, meta)
	}
	return reconcileUser(u, meta)
}

func createUser(username string, meta ConnectionMetadata) error {
	args := []string{}
	if meta.Homedir {
		args = append(args, "-m")
	} else {
		args = append(args, "-M")
	}
	args = append(args, username)
	cmd := exec.Command("useradd", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("useradd %s: %w (output: %s)", username, err, string(out))
	}
	logger.Info("auth-daemon: created user %s (homedir=%v)", username, meta.Homedir)
	if meta.Sudo {
		group := sudoGroup()
		cmd := exec.Command("usermod", "-aG", group, username)
		if out, err := cmd.CombinedOutput(); err != nil {
			logger.Warn("auth-daemon: usermod -aG %s %s: %v (output: %s)", group, username, err, string(out))
		} else {
			logger.Info("auth-daemon: added %s to %s", username, group)
		}
	}
	return nil
}

func mustAtoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func reconcileUser(u *user.User, meta ConnectionMetadata) error {
	group := sudoGroup()
	inGroup, err := userInGroup(u.Username, group)
	if err != nil {
		logger.Warn("auth-daemon: check group %s: %v", group, err)
		inGroup = false
	}
	if meta.Sudo && !inGroup {
		cmd := exec.Command("usermod", "-aG", group, u.Username)
		if out, err := cmd.CombinedOutput(); err != nil {
			logger.Warn("auth-daemon: usermod -aG %s %s: %v (output: %s)", group, u.Username, err, string(out))
		} else {
			logger.Info("auth-daemon: added %s to %s", u.Username, group)
		}
	} else if !meta.Sudo && inGroup {
		cmd := exec.Command("gpasswd", "-d", u.Username, group)
		if out, err := cmd.CombinedOutput(); err != nil {
			logger.Warn("auth-daemon: gpasswd -d %s %s: %v (output: %s)", u.Username, group, err, string(out))
		} else {
			logger.Info("auth-daemon: removed %s from %s", u.Username, group)
		}
	}
	if meta.Homedir && u.HomeDir != "" {
		if st, err := os.Stat(u.HomeDir); err != nil || !st.IsDir() {
			if err := os.MkdirAll(u.HomeDir, 0755); err != nil {
				logger.Warn("auth-daemon: mkdir %s: %v", u.HomeDir, err)
			} else {
				uid, gid := mustAtoi(u.Uid), mustAtoi(u.Gid)
				_ = os.Chown(u.HomeDir, uid, gid)
				logger.Info("auth-daemon: created home %s for %s", u.HomeDir, u.Username)
			}
		}
	}
	return nil
}

func userInGroup(username, groupName string) (bool, error) {
	// getent group wheel returns "wheel:x:10:user1,user2"
	cmd := exec.Command("getent", "group", groupName)
	out, err := cmd.Output()
	if err != nil {
		return false, err
	}
	parts := strings.SplitN(strings.TrimSpace(string(out)), ":", 4)
	if len(parts) < 4 {
		return false, nil
	}
	members := strings.Split(parts[3], ",")
	for _, m := range members {
		if strings.TrimSpace(m) == username {
			return true, nil
		}
	}
	return false, nil
}
