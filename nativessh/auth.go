package nativessh

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/fosrl/newt/logger"
	"golang.org/x/crypto/ssh"
)

type staticConnMeta struct {
	user string
}

func (m staticConnMeta) User() string          { return m.user }
func (m staticConnMeta) SessionID() []byte     { return nil }
func (m staticConnMeta) ClientVersion() []byte { return nil }
func (m staticConnMeta) ServerVersion() []byte { return nil }
func (m staticConnMeta) RemoteAddr() net.Addr  { return nil }
func (m staticConnMeta) LocalAddr() net.Addr   { return nil }

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
	return AuthenticateWithCertificate(nil, username, password, privateKeyPEM, "")
}

// AuthenticateWithCertificate authenticates a user for a browser-based native
// SSH session using the same method ordering as the native SSH server:
//  1. Private key in host ~/.ssh/authorized_keys.
//  2. SSH certificate signed by the configured CA (when provided).
//  3. Password via host PAM stack.
func AuthenticateWithCertificate(store *CredentialStore, username, password, privateKeyPEM, certificate string) error {
	logger.Debug("nativessh: authenticating user %q (hasPassword=%v, hasPrivateKey=%v)", username, password != "", privateKeyPEM != "")
	if !SystemUserExists(username) {
		logger.Debug("nativessh: user %q not found on system", username)
		return fmt.Errorf("user %q does not exist", username)
	}

	var signer ssh.Signer
	if privateKeyPEM != "" {
		parsedSigner, err := ssh.ParsePrivateKey([]byte(privateKeyPEM))
		if err != nil {
			logger.Debug("nativessh: failed to parse private key for %q: %v", username, err)
		} else if CheckAuthorizedKeys(username, parsedSigner.PublicKey()) {
			logger.Debug("nativessh: private key auth succeeded for %q", username)
			return nil
		} else {
			signer = parsedSigner
			logger.Debug("nativessh: private key not in authorized_keys for %q", username)
		}
	}

	if store != nil && certificate != "" {
		if signer == nil {
			logger.Debug("nativessh: certificate provided for %q but no matching private key was provided", username)
		} else {
			pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certificate))
			if err != nil {
				logger.Debug("nativessh: failed to parse certificate for %q: %v", username, err)
			} else {
				cert, ok := pub.(*ssh.Certificate)
				if !ok {
					logger.Debug("nativessh: provided cert data for %q is not an SSH certificate", username)
				} else if ssh.FingerprintSHA256(cert.Key) != ssh.FingerprintSHA256(signer.PublicKey()) {
					logger.Debug("nativessh: certificate key mismatch for %q", username)
				} else {
					caKey, userPrincipals := store.get(username)
					if caKey == nil {
						logger.Debug("nativessh: CA key is not set for certificate auth user %q", username)
					} else if len(userPrincipals) == 0 {
						logger.Debug("nativessh: no allowed principals found for certificate auth user %q", username)
					} else {
						checker := &ssh.CertChecker{
							IsUserAuthority: func(auth ssh.PublicKey) bool {
								return ssh.FingerprintSHA256(auth) == ssh.FingerprintSHA256(caKey)
							},
						}

						var lastErr error
						for principal := range userPrincipals {
							_, authErr := checker.Authenticate(staticConnMeta{user: principal}, cert)
							if authErr == nil {
								logger.Debug("nativessh: certificate auth succeeded for %q (principal=%q)", username, principal)
								return nil
							}
							lastErr = authErr
						}
						if lastErr != nil {
							logger.Debug("nativessh: certificate auth failed for %q: %v", username, lastErr)
						}
					}
				}
			}
		}
	}

	if password != "" {
		if err := VerifySystemPassword(username, password); err != nil {
			logger.Debug("nativessh: password auth failed for %q: %v", username, err)
		} else {
			logger.Debug("nativessh: password auth succeeded for %q", username)
			return nil
		}
	} else {
		logger.Debug("nativessh: no password provided for %q", username)
	}
	return fmt.Errorf("authentication failed for user %q", username)
}
