//go:build !windows

package nativessh

import (
	"fmt"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"

	"github.com/creack/pty"
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

	shell := findShell()
	cmd := exec.Command(shell, "--login")
	cmd.Env = []string{
		"TERM=xterm-256color",
		"HOME=" + u.HomeDir,
		"USER=" + username,
		"LOGNAME=" + username,
		"SHELL=" + shell,
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}
	cmd.Dir = u.HomeDir
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
