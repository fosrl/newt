//go:build !windows

package nativessh

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"

	"github.com/creack/pty"
	"github.com/fosrl/newt/logger"
)

// NewPTYSessionAs spawns an interactive shell in a PTY running as the given
// system user.  The calling process must have sufficient privileges (typically
// root / CAP_SETUID) to switch to a different UID/GID.
func NewPTYSessionAs(username string) (*PTYSession, error) {
	u, err := user.Lookup(username)
	if err != nil {
		return nil, fmt.Errorf("user lookup %q: %w", username, err)
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("parse uid: %w", err)
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("parse gid: %w", err)
	}

	// Collect supplementary group IDs.
	groupIDs, err := u.GroupIds()
	if err != nil {
		groupIDs = []string{}
	}
	var groups []uint32
	for _, g := range groupIDs {
		gval, err := strconv.ParseUint(g, 10, 32)
		if err == nil {
			groups = append(groups, uint32(gval))
		}
	}

	shell := userShell(u)

	homeDir := userWorkDir(u.HomeDir, uint32(uid), uint32(gid), groups)

	cmd := exec.Command(shell, "--login")
	cmd.Env = []string{
		"TERM=xterm-256color",
		"HOME=" + u.HomeDir,
		"USER=" + username,
		"LOGNAME=" + username,
		"SHELL=" + shell,
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}
	cmd.Dir = homeDir
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid:    uint32(uid),
			Gid:    uint32(gid),
			Groups: groups,
		},
	}

	ptmx, err := pty.Start(cmd)
	if err != nil {
		return nil, fmt.Errorf("pty start: %w", err)
	}
	return &PTYSession{ptmx: ptmx, cmd: cmd}, nil
}

// userWorkDir returns the directory a process running as uid/gid/groups
// should start in: home if that user can enter it, otherwise "/". Like
// OpenSSH, an unusable home is not fatal: it may not exist (useradd without
// -m) or may belong to another UID (the account was recreated). Checking as
// the target user matters because the caller is root and can enter anything,
// while the child's chdir runs after the credential switch.
func userWorkDir(home string, uid, gid uint32, groups []uint32) string {
	resolved, err := filepath.EvalSymlinks(home)
	if err != nil || !filepath.IsAbs(resolved) {
		logger.Warn("nativessh: home directory %q unusable, starting in /: %v", home, err)
		return "/"
	}
	if info, err := os.Stat(resolved); err != nil || !info.IsDir() {
		logger.Warn("nativessh: home directory %q is not a directory, starting in /", home)
		return "/"
	}
	if uid == 0 {
		return home
	}
	// Every directory on the path must be searchable by the user.
	for dir := resolved; ; dir = filepath.Dir(dir) {
		info, err := os.Stat(dir)
		if err != nil || !canSearch(info, uid, gid, groups) {
			logger.Warn("nativessh: uid %d cannot enter home directory %q (no access to %q), starting in /", uid, home, dir)
			return "/"
		}
		if dir == filepath.Dir(dir) {
			return home
		}
	}
}

// canSearch reports whether the mode bits of info grant search (execute)
// permission to uid/gid/groups. ACLs are not considered.
func canSearch(info os.FileInfo, uid, gid uint32, groups []uint32) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return true
	}
	perm := info.Mode().Perm()
	switch {
	case st.Uid == uid:
		return perm&0o100 != 0
	case st.Gid == gid || slices.Contains(groups, st.Gid):
		return perm&0o010 != 0
	default:
		return perm&0o001 != 0
	}
}
