//go:build windows

package updates

// postUpdateAdvantech is not supported on Windows.
func postUpdateAdvantech(newVersion, pidFile string) error {
	return nil
}
