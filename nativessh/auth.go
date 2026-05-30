package nativessh

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

// CheckAuthorizedKeys reports whether key matches any entry in the system
// user's ~/.ssh/authorized_keys file.  Returns false (not an error) when the
// user or file does not exist.
func CheckAuthorizedKeys(username string, key ssh.PublicKey) bool {
	u, err := user.Lookup(username)
	if err != nil {
		return false
	}
	f, err := os.Open(filepath.Join(u.HomeDir, ".ssh", "authorized_keys"))
	if err != nil {
		return false
	}
	defer f.Close()

	want := ssh.FingerprintSHA256(key)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			continue
		}
		if ssh.FingerprintSHA256(parsed) == want {
			return true
		}
	}
	return false
}

// SystemUserExists reports whether a user account with the given name exists
// on the host OS.
func SystemUserExists(username string) bool {
	_, err := user.Lookup(username)
	return err == nil
}

// Authenticate authenticates a user for a browser-based native SSH session.
// It tries, in order:
//  1. Private key — parses privateKeyPEM and checks it against the user's
//     ~/.ssh/authorized_keys.
//  2. Password — verifies password via the host OS PAM stack (Linux only).
//
// Returns nil on the first method that succeeds, or an error if all fail.
func Authenticate(username, password, privateKeyPEM string) error {
	log.Printf("nativessh: authenticating user %q (hasPassword=%v, hasPrivateKey=%v)", username, password != "", privateKeyPEM != "")
	if !SystemUserExists(username) {
		log.Printf("nativessh: user %q not found on system", username)
		return fmt.Errorf("user %q does not exist", username)
	}
	if privateKeyPEM != "" {
		signer, err := ssh.ParsePrivateKey([]byte(privateKeyPEM))
		if err != nil {
			log.Printf("nativessh: failed to parse private key for %q: %v", username, err)
		} else if CheckAuthorizedKeys(username, signer.PublicKey()) {
			log.Printf("nativessh: private key auth succeeded for %q", username)
			return nil
		} else {
			log.Printf("nativessh: private key not in authorized_keys for %q", username)
		}
	}
	if password != "" {
		if err := VerifySystemPassword(username, password); err != nil {
			log.Printf("nativessh: password auth failed for %q: %v", username, err)
		} else {
			log.Printf("nativessh: password auth succeeded for %q", username)
			return nil
		}
	} else {
		log.Printf("nativessh: no password provided for %q", username)
	}
	return fmt.Errorf("authentication failed for user %q", username)
}
