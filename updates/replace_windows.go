//go:build windows

package updates

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fosrl/newt/logger"
)

// oldBinaryPrefix returns the prefix used for previous binaries parked
// during an update.  Each update gets a unique suffix because a parked
// binary can stay locked for a long time (for example by a service host
// process that supervises the updated one), and a locked file cannot be
// renamed over.
func oldBinaryPrefix(exePath string) string {
	return exePath + ".old"
}

// replaceBinary swaps the binary at exePath for the one at newPath.
//
// Windows refuses to overwrite (or delete) an executable that is mapped by a
// running process, so renaming newPath directly over exePath fails with
// "Access is denied".  A running executable can however be renamed, so we
// first move it aside and then move the new binary into its place.  The
// parked copy is removed by removeStaleBinary once nothing is running it.
func replaceBinary(newPath, exePath string) error {
	oldPath := fmt.Sprintf("%s-%d", oldBinaryPrefix(exePath), time.Now().UnixNano())

	if err := os.Rename(exePath, oldPath); err != nil {
		return fmt.Errorf("failed to move running binary aside: %w", err)
	}

	if err := os.Rename(newPath, exePath); err != nil {
		// Put the original binary back so the next start still works.
		if rbErr := os.Rename(oldPath, exePath); rbErr != nil {
			return fmt.Errorf("failed to install new binary: %w (restoring previous binary also failed: %v)", err, rbErr)
		}
		return fmt.Errorf("failed to install new binary: %w", err)
	}

	return nil
}

// removeStaleBinary deletes previous binaries left behind by replaceBinary.
// A parked binary can only be deleted once every process running it has
// exited, so this is best effort and anything still locked is retried on the
// next check.
func removeStaleBinary(exePath string) {
	dir := filepath.Dir(exePath)
	prefix := filepath.Base(oldBinaryPrefix(exePath))

	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		oldPath := filepath.Join(dir, e.Name())
		if err := os.Remove(oldPath); err == nil {
			logger.Debug("checkAndSelfUpdate: removed previous binary %s", oldPath)
		}
	}
}
