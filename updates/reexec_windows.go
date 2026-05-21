//go:build windows

package updates

import (
	"fmt"
	"os"
	"os/exec"
)

// reexec on Windows cannot use syscall.Exec (there is no exec syscall that
// replaces the process image).  Instead we start a new process and exit the
// current one.
func reexec(exePath string) error {
	cmd := exec.Command(exePath, os.Args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start updated binary: %w", err)
	}

	// Exit the current process so the new binary takes over.
	os.Exit(0)
	return nil // unreachable
}
