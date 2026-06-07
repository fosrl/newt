//go:build !windows

package newt

import (
	"fmt"
	"os"
	"syscall"
)

// reexec replaces the current process image with a fresh copy of itself,
// preserving all arguments and environment variables. On success it never
// returns (execve replaces the process in-place). On failure it returns an
// error describing why the exec could not be performed.
func reexec() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	return syscall.Exec(exe, os.Args, os.Environ())
}
