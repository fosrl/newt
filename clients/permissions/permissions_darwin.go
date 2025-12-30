//go:build darwin && !ios

package permissions

import (
	"fmt"
	"os"
)

// CheckNativeInterfacePermissions checks if the process has sufficient
// permissions to create a native TUN interface on macOS.
// This typically requires root privileges.
func CheckNativeInterfacePermissions() error {
	if os.Geteuid() == 0 {
		return nil
	}
	return fmt.Errorf("insufficient permissions: need root to create TUN interface on macOS")
}
