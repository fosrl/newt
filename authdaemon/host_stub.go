//go:build !linux

package authdaemon

import "fmt"

var errLinuxOnly = fmt.Errorf("auth-daemon PAM agent is only supported on Linux")

// writeCACertIfNotExists returns an error on non-Linux.
func writeCACertIfNotExists(path, contents string) error {
	return errLinuxOnly
}

// ensureSSHDTrustedUserCAKeys returns an error on non-Linux.
func ensureSSHDTrustedUserCAKeys(sshdConfigPath, caCertPath string) error {
	return errLinuxOnly
}

// reloadSSHD returns an error on non-Linux.
func reloadSSHD(reloadCmd string) error {
	return errLinuxOnly
}

// ensureUser returns an error on non-Linux.
func ensureUser(username string, meta ConnectionMetadata) error {
	return errLinuxOnly
}

// writePrincipals returns an error on non-Linux.
func writePrincipals(path, username, niceId string) error {
	return errLinuxOnly
}
