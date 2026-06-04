//go:build linux

package nativessh

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/fosrl/newt/logger"
	"github.com/go-crypt/crypt"
	"github.com/go-crypt/x/yescrypt"
)

// VerifySystemPassword authenticates username/password by reading /etc/shadow.
// Supports yescrypt ($y$), bcrypt ($2b$/$2a$/$2y$), SHA-512 ($6$), SHA-256
// ($5$), argon2, scrypt, and other schemes handled by go-crypt/crypt.
func VerifySystemPassword(username, password string) error {
	hash, err := readShadowHash(username)
	if err != nil {
		logger.Debug("nativessh/pam: readShadowHash for %q failed: %v", username, err)
		return fmt.Errorf("shadow: %w", err)
	}

	// Log the scheme prefix only (never the full hash).
	scheme := "unknown"
	for _, prefix := range []string{"$y$", "$2a$", "$2b$", "$2y$", "$6$", "$5$", "$1$"} {
		if strings.HasPrefix(hash, prefix) {
			scheme = prefix
			break
		}
	}
	logger.Debug("nativessh/pam: verifying password for %q using scheme %s", username, scheme)

	// Yescrypt ($y$) is not in go-crypt/crypt's default decoder; handle it directly.
	if strings.HasPrefix(hash, "$y$") {
		computed, err := yescrypt.Hash([]byte(password), []byte(hash))
		if err != nil {
			logger.Debug("nativessh/pam: yescrypt.Hash for %q failed: %v", username, err)
			return fmt.Errorf("yescrypt: %w", err)
		}
		if !bytes.Equal(computed, []byte(hash)) {
			logger.Debug("nativessh/pam: yescrypt mismatch for %q", username)
			return errors.New("authentication failed")
		}
		return nil
	}

	decoder, err := crypt.NewDefaultDecoder()
	if err != nil {
		return fmt.Errorf("crypt decoder: %w", err)
	}

	digest, err := decoder.Decode(hash)
	if err != nil {
		logger.Debug("nativessh/pam: failed to decode hash for %q: %v", username, err)
		return fmt.Errorf("unsupported password hash scheme %q: %w", scheme, err)
	}

	match, err := digest.MatchAdvanced(password)
	if err != nil {
		logger.Debug("nativessh/pam: MatchAdvanced for %q failed: %v", username, err)
		return err
	}
	if !match {
		logger.Debug("nativessh/pam: password mismatch for %q", username)
		return errors.New("authentication failed")
	}
	return nil
}

// readShadowHash reads /etc/shadow and returns the password hash for username.
func readShadowHash(username string) (string, error) {
	f, err := os.Open("/etc/shadow")
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.SplitN(scanner.Text(), ":", 3)
		if len(fields) < 2 || fields[0] != username {
			continue
		}
		h := fields[1]
		if h == "" || h == "*" || strings.HasPrefix(h, "!") || h == "x" {
			return "", errors.New("account locked or has no password")
		}
		return h, nil
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", errors.New("user not found in shadow database")
}
