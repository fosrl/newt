//go:build !windows

package nativessh

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/creack/pty"
)

func TestPTYSessionInputHidden(t *testing.T) {
	tests := []struct {
		stty string
		want bool
	}{
		{"echo icanon", false},   // normal cooked mode
		{"-echo icanon", true},   // password prompt
		{"-echo -icanon", false}, // readline / full-screen programs
	}
	for _, tt := range tests {
		t.Run(tt.stty, func(t *testing.T) {
			cmd := exec.Command("/bin/sh", "-c", "stty "+tt.stty+" && echo ready && sleep 5")
			ptmx, err := pty.Start(cmd)
			if err != nil {
				t.Skipf("pty unavailable: %v", err)
			}
			sess := &PTYSession{ptmx: ptmx, cmd: cmd}
			defer sess.Close()
			defer cmd.Process.Kill() //nolint:errcheck

			// Wait until stty has applied the mode.
			buf := make([]byte, 64)
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				n, _ := ptmx.Read(buf)
				if n > 0 && containsReady(buf[:n]) {
					break
				}
			}

			if got := sess.InputHidden(); got != tt.want {
				t.Fatalf("InputHidden() = %v, want %v", got, tt.want)
			}
		})
	}
}

func containsReady(b []byte) bool {
	for i := 0; i+5 <= len(b); i++ {
		if string(b[i:i+5]) == "ready" {
			return true
		}
	}
	return false
}

// TestUserWorkDirFallsBackWhenHomeInaccessible covers a home directory owned
// by a different UID (e.g. the account was recreated), which root can stat
// but the target user cannot enter.
func TestUserWorkDirFallsBackWhenHomeInaccessible(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	owner := uint32(os.Getuid())
	if owner == 0 {
		t.Skip("ownership checks are bypassed for root")
	}

	if got := userWorkDir(home, owner, uint32(os.Getgid()), nil); got != home {
		t.Fatalf("owner: got %q, want %q", got, home)
	}
	if got := userWorkDir(home, owner+1, owner+1, nil); got != "/" {
		t.Fatalf("other uid: got %q, want /", got)
	}
	if got := userWorkDir(filepath.Join(home, "missing"), owner, uint32(os.Getgid()), nil); got != "/" {
		t.Fatalf("missing home: got %q, want /", got)
	}
}
