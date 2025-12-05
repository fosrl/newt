//go:build windows

package permissions

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// CheckNativeInterfacePermissions checks if the process has sufficient
// permissions to create a native TUN interface on Windows.
// This requires Administrator privileges.
func CheckNativeInterfacePermissions() error {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid)
	if err != nil {
		return fmt.Errorf("failed to initialize SID: %v", err)
	}
	defer windows.FreeSid(sid)

	token := windows.Token(0)
	member, err := token.IsMember(sid)
	if err != nil {
		return fmt.Errorf("failed to check admin group membership: %v", err)
	}

	if !member {
		return fmt.Errorf("insufficient permissions: need Administrator to create TUN interface on Windows")
	}
	return nil
}
