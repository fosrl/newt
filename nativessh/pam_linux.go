//go:build linux

package nativessh

import (
	"fmt"

	"github.com/msteinert/pam/v2"
)

// verifySystemPassword authenticates username/password via PAM using the
// "sshd" service stack.  It returns nil on success and an error on failure.
// The caller must not reveal the error detail to the client.
func verifySystemPassword(username, password string) error {
	tx, err := pam.StartFunc("sshd", username, func(s pam.Style, msg string) (string, error) {
		switch s {
		case pam.PromptEchoOff, pam.PromptEchoOn:
			return password, nil
		default:
			return "", nil
		}
	})
	if err != nil {
		return fmt.Errorf("PAM start: %w", err)
	}

	if err := tx.Authenticate(0); err != nil {
		return fmt.Errorf("PAM authenticate: %w", err)
	}
	if err := tx.AcctMgmt(0); err != nil {
		return fmt.Errorf("PAM acct_mgmt: %w", err)
	}
	return nil
}
