//go:build ios

package permissions

// CheckNativeInterfacePermissions always allows permission on iOS.
func CheckNativeInterfacePermissions() error {
	return nil
}