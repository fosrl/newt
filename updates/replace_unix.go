//go:build !windows

package updates

import "os"

// replaceBinary swaps the binary at exePath for the one at newPath.  On Unix
// an atomic rename works even while the old file is being executed.
func replaceBinary(newPath, exePath string) error {
	return os.Rename(newPath, exePath)
}

// removeStaleBinary is a no-op on Unix; replaceBinary never leaves a copy of
// the previous binary behind.
func removeStaleBinary(exePath string) {}
