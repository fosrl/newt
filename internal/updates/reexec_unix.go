//go:build !windows

package updates

import (
	"os"
	"syscall"
)

// reexec replaces the current process image with the binary at exePath,
// forwarding all original arguments and environment variables.
func reexec(exePath string) error {
	return syscall.Exec(exePath, os.Args, os.Environ())
}
