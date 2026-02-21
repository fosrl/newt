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

// writeCACertIfNotExists writes contents to path. If the file already exists: when force is false, skip; when force is true, overwrite only if content differs.
func writeCACertIfNotExists(path, contents string, force bool) error {
	contents = strings.TrimSpace(contents)
	if contents != "" && !strings.HasSuffix(contents, "\n") {
		contents += "\n"
	}
	existing, err := os.ReadFile(path)
	if err == nil {
		existingStr := strings.TrimSpace(string(existing))
		if existingStr != "" && !strings.HasSuffix(existingStr, "\n") {
			existingStr += "\n"
		}
		if existingStr == contents {
			logger.Debug("auth-daemon: CA cert unchanged at %s, skipping write", path)
			return nil
		}
		if !force {
			logger.Debug("auth-daemon: CA cert already exists at %s, skipping write (Force disabled)", path)
			return nil
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w", path, err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	if err := os.WriteFile(path, []byte(contents), 0644); err != nil {
		return fmt.Errorf("write CA cert: %w", err)
	}
	logger.Info("auth-daemon: wrote CA cert to %s", path)
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

const skelDir = "/etc/skel"

// copySkelInto copies files from srcDir (e.g. /etc/skel) into dstDir (e.g. user's home).
// Only creates files that don't already exist. All created paths are chowned to uid:gid.
func copySkelInto(srcDir, dstDir string, uid, gid int) {
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.Warn("auth-daemon: read %s: %v", srcDir, err)
		}
		return
	}
	for _, e := range entries {
		name := e.Name()
		src := filepath.Join(srcDir, name)
		dst := filepath.Join(dstDir, name)
		if e.IsDir() {
			if st, err := os.Stat(dst); err == nil && st.IsDir() {
				copySkelInto(src, dst, uid, gid)
				continue
			}
			if err := os.MkdirAll(dst, 0755); err != nil {
				logger.Warn("auth-daemon: mkdir %s: %v", dst, err)
				continue
			}
			if err := os.Chown(dst, uid, gid); err != nil {
				logger.Warn("auth-daemon: chown %s: %v", dst, err)
			}
			copySkelInto(src, dst, uid, gid)
			continue
		}
		if _, err := os.Stat(dst); err == nil {
			continue
		}
		data, err := os.ReadFile(src)
		if err != nil {
			logger.Warn("auth-daemon: read %s: %v", src, err)
			continue
		}
		if err := os.WriteFile(dst, data, 0644); err != nil {
			logger.Warn("auth-daemon: write %s: %v", dst, err)
			continue
		}
		if err := os.Chown(dst, uid, gid); err != nil {
			logger.Warn("auth-daemon: chown %s: %v", dst, err)
		}
	}
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

// desiredGroups returns the exact list of supplementary groups the user should have:
// meta.Groups plus the sudo group when meta.SudoMode is "full" (deduped).
func desiredGroups(meta ConnectionMetadata) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, g := range meta.Groups {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		if _, ok := seen[g]; ok {
			continue
		}
		seen[g] = struct{}{}
		out = append(out, g)
	}
	if meta.SudoMode == "full" {
		sg := sudoGroup()
		if _, ok := seen[sg]; !ok {
			out = append(out, sg)
		}
	}
	return out
}

// setUserGroups sets the user's supplementary groups to exactly groups (local mirrors metadata).
// When groups is empty, clears all supplementary groups (usermod -G "").
func setUserGroups(username string, groups []string) {
	list := strings.Join(groups, ",")
	cmd := exec.Command("usermod", "-G", list, username)
	if out, err := cmd.CombinedOutput(); err != nil {
		logger.Warn("auth-daemon: usermod -G %s: %v (output: %s)", list, err, string(out))
	} else {
		logger.Info("auth-daemon: set %s supplementary groups to %s", username, list)
	}
}

func createUser(username string, meta ConnectionMetadata) error {
	args := []string{"-s", "/bin/bash"}
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
	if meta.Homedir {
		if u, err := user.Lookup(username); err == nil && u.HomeDir != "" {
			uid, gid := mustAtoi(u.Uid), mustAtoi(u.Gid)
			copySkelInto(skelDir, u.HomeDir, uid, gid)
		}
	}
	setUserGroups(username, desiredGroups(meta))
	switch meta.SudoMode {
	case "full":
		if err := configurePasswordlessSudo(username); err != nil {
			logger.Warn("auth-daemon: configure passwordless sudo for %s: %v", username, err)
		}
	case "commands":
		if len(meta.SudoCommands) > 0 {
			if err := configureSudoCommands(username, meta.SudoCommands); err != nil {
				logger.Warn("auth-daemon: configure sudo commands for %s: %v", username, err)
			}
		}
	default:
		removeSudoers(username)
	}
	return nil
}

const sudoersFilePrefix = "90-pangolin-"

func sudoersPath(username string) string {
	return filepath.Join("/etc/sudoers.d", sudoersFilePrefix+username)
}

// writeSudoersFile writes content to the user's sudoers.d file and validates with visudo.
func writeSudoersFile(username, content string) error {
	sudoersFile := sudoersPath(username)
	tmpFile := sudoersFile + ".tmp"
	if err := os.WriteFile(tmpFile, []byte(content), 0440); err != nil {
		return fmt.Errorf("write temp sudoers file: %w", err)
	}
	cmd := exec.Command("visudo", "-c", "-f", tmpFile)
	if out, err := cmd.CombinedOutput(); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("visudo validation failed: %w (output: %s)", err, string(out))
	}
	if err := os.Rename(tmpFile, sudoersFile); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("move sudoers file: %w", err)
	}
	return nil
}

// configurePasswordlessSudo creates a sudoers.d file to allow passwordless sudo for the user.
func configurePasswordlessSudo(username string) error {
	content := fmt.Sprintf("# Created by Pangolin auth-daemon\n%s ALL=(ALL) NOPASSWD:ALL\n", username)
	if err := writeSudoersFile(username, content); err != nil {
		return err
	}
	logger.Info("auth-daemon: configured passwordless sudo for %s", username)
	return nil
}

// configureSudoCommands creates a sudoers.d file allowing only the listed commands (NOPASSWD).
// Each command should be a full path (e.g. /usr/bin/systemctl).
func configureSudoCommands(username string, commands []string) error {
	var b strings.Builder
	b.WriteString("# Created by Pangolin auth-daemon (restricted commands)\n")
	n := 0
	for _, c := range commands {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		fmt.Fprintf(&b, "%s ALL=(ALL) NOPASSWD: %s\n", username, c)
		n++
	}
	if n == 0 {
		return fmt.Errorf("no valid sudo commands")
	}
	if err := writeSudoersFile(username, b.String()); err != nil {
		return err
	}
	logger.Info("auth-daemon: configured restricted sudo for %s (%d commands)", username, len(commands))
	return nil
}

// removeSudoers removes the sudoers.d file for the user.
func removeSudoers(username string) {
	sudoersFile := sudoersPath(username)
	if err := os.Remove(sudoersFile); err != nil && !os.IsNotExist(err) {
		logger.Warn("auth-daemon: remove sudoers for %s: %v", username, err)
	} else if err == nil {
		logger.Info("auth-daemon: removed sudoers for %s", username)
	}
}

func mustAtoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func reconcileUser(u *user.User, meta ConnectionMetadata) error {
	setUserGroups(u.Username, desiredGroups(meta))
	switch meta.SudoMode {
	case "full":
		if err := configurePasswordlessSudo(u.Username); err != nil {
			logger.Warn("auth-daemon: configure passwordless sudo for %s: %v", u.Username, err)
		}
	case "commands":
		if len(meta.SudoCommands) > 0 {
			if err := configureSudoCommands(u.Username, meta.SudoCommands); err != nil {
				logger.Warn("auth-daemon: configure sudo commands for %s: %v", u.Username, err)
			}
		} else {
			removeSudoers(u.Username)
		}
	default:
		removeSudoers(u.Username)
	}
	if meta.Homedir && u.HomeDir != "" {
		uid, gid := mustAtoi(u.Uid), mustAtoi(u.Gid)
		if st, err := os.Stat(u.HomeDir); err != nil || !st.IsDir() {
			if err := os.MkdirAll(u.HomeDir, 0755); err != nil {
				logger.Warn("auth-daemon: mkdir %s: %v", u.HomeDir, err)
			} else {
				_ = os.Chown(u.HomeDir, uid, gid)
				copySkelInto(skelDir, u.HomeDir, uid, gid)
				logger.Info("auth-daemon: created home %s for %s", u.HomeDir, u.Username)
			}
		} else {
			// Ensure .bashrc etc. exist (e.g. home existed but was empty or skel was minimal)
			copySkelInto(skelDir, u.HomeDir, uid, gid)
		}
	}
	return nil
}
