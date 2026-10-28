//go:build windows

package updates

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/fosrl/newt/logger"
	"golang.org/x/sys/windows/svc"
)

// reexec on Windows cannot use syscall.Exec (there is no exec syscall that
// replaces the process image).  Instead we start a new process and exit the
// current one.
//
// When running as a Windows service a detached child would be orphaned from
// the Service Control Manager, so callers should supply
// SelfUpdateConfig.Restart to restart through the SCM.  If they don't, we
// exit with a failure code and rely on the service's recovery actions to
// relaunch it from the (already replaced) binary.
func reexec(exePath string) error {
	if isService, err := svc.IsWindowsService(); err == nil && isService {
		logger.Info("Update installed; exiting so the service control manager restarts the service")
		os.Exit(1)
	}

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
