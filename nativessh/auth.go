package nativessh

import (
	"bufio"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

// checkAuthorizedKeys reports whether key matches any entry in the system
// user's ~/.ssh/authorized_keys file.  Returns false (not an error) when the
// user or file does not exist.
func checkAuthorizedKeys(username string, key ssh.PublicKey) bool {
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

// systemUserExists reports whether a user account with the given name exists
// on the host OS.
func systemUserExists(username string) bool {
	_, err := user.Lookup(username)
	return err == nil
}
