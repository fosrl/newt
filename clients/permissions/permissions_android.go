//go:build android

package permissions

// CheckNativeInterfacePermissions always allows permission on Android.
func CheckNativeInterfacePermissions() error {
	return nil
}