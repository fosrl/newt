//go:build windows

package newt

import (
	"fmt"
	"os"
	"os/exec"
)

// reexec spawns a new copy of the current process with the same arguments and
// environment, then exits the current process. On Windows, execve is not
// available, so we start a child process and exit. On success it never returns
// (os.Exit terminates the current process). On failure it returns an error.
func reexec() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Env = os.Environ()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start new process: %w", err)
	}
	os.Exit(0)
	return nil // unreachable
}
