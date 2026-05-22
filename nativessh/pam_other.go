//go:build !linux

package nativessh

import "errors"

// VerifySystemPassword is not supported on non-Linux platforms; it always
// returns an error so that password authentication is never accepted.
func VerifySystemPassword(username, password string) error {
	return errors.New("password authentication not supported on this platform")
}
