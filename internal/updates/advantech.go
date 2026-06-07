//go:build !windows

package updates

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/fosrl/newt/pkg/logger"
)

const advantechVersionFile = "/opt/newt/etc/version"

// postUpdateAdvantech performs Advantech Router App-specific post-update steps:
//   - Writes the new version string to /opt/newt/etc/version so that the
//     router firmware's package management reflects the installed version.
//   - Updates the PID file at pidFile (if non-empty) with the current process
//     PID, in case the re-exec lands with a new PID on platforms where
//     syscall.Exec behaviour differs.
func postUpdateAdvantech(newVersion, pidFile string) error {
	// --- Write version file ---
	versionDir := filepath.Dir(advantechVersionFile)
	if err := os.MkdirAll(versionDir, 0755); err != nil {
		return fmt.Errorf("advantech: failed to create version directory %s: %w", versionDir, err)
	}

	if err := os.WriteFile(advantechVersionFile, []byte(newVersion+"\n"), 0644); err != nil {
		return fmt.Errorf("advantech: failed to write version file %s: %w", advantechVersionFile, err)
	}
	logger.Debug("postUpdateAdvantech: wrote version %s to %s", newVersion, advantechVersionFile)

	// --- Update PID file ---
	// syscall.Exec replaces the process image in-place so the PID is preserved.
	// We update the PID file here anyway so that any race between the old and
	// new binary is covered (e.g. on platforms that fork before exec).
	if pidFile != "" {
		pid := fmt.Sprintf("%d\n", os.Getpid())
		if err := os.WriteFile(pidFile, []byte(pid), 0644); err != nil {
			// Non-fatal: log and continue so the update still proceeds.
			logger.Debug("postUpdateAdvantech: warning: failed to update PID file %s: %v", pidFile, err)
		} else {
			logger.Debug("postUpdateAdvantech: updated PID file %s with PID %d", pidFile, os.Getpid())
		}
	}

	return nil
}
