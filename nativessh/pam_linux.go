//go:build linux

package nativessh

import (
	"bufio"
	"bytes"
	"crypto/sha512"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// VerifySystemPassword authenticates username/password by reading /etc/shadow
// and verifying the stored hash using pure-Go cryptography (no CGo required).
// Supported hash schemes: bcrypt ($2a$/$2b$/$2y$) and SHA-512 crypt ($6$).
func VerifySystemPassword(username, password string) error {
	hash, err := readShadowHash(username)
	if err != nil {
		return fmt.Errorf("shadow: %w", err)
	}
	return cryptVerify(password, hash)
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

// cryptVerify verifies password against a crypt(3) hash string.
func cryptVerify(password, hash string) error {
	switch {
	case strings.HasPrefix(hash, "$2a$"), strings.HasPrefix(hash, "$2b$"), strings.HasPrefix(hash, "$2y$"):
		return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	case strings.HasPrefix(hash, "$6$"):
		computed, err := sha512CryptHash([]byte(password), hash)
		if err != nil {
			return err
		}
		if computed != hash {
			return errors.New("authentication failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported password hash scheme")
	}
}

// --- SHA-512 crypt ($6$) ---
// Specification: https://www.akkadia.org/docs/sha-crypt.txt

const (
	sha512CryptMagic         = "$6$"
	sha512CryptRoundsDefault = 5000
	sha512CryptRoundsMin     = 1000
	sha512CryptRoundsMax     = 999999999
	sha512CryptSaltLenMax    = 16
	sha512CryptAlphabet      = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

var sha512CryptRoundsPrefix = []byte("rounds=")

// sha512CryptHash computes a SHA-512 crypt hash for key.  saltStr may be a
// full stored hash string (for verification) or just the salt parameters.
func sha512CryptHash(key []byte, saltStr string) (string, error) {
	salt := []byte(saltStr)

	if !bytes.HasPrefix(salt, []byte(sha512CryptMagic)) {
		return "", errors.New("sha512crypt: invalid prefix")
	}
	salt = salt[len(sha512CryptMagic):]

	rounds := sha512CryptRoundsDefault
	isRoundsDef := false

	if bytes.HasPrefix(salt, sha512CryptRoundsPrefix) {
		salt = salt[len(sha512CryptRoundsPrefix):]
		i := bytes.IndexByte(salt, '$')
		if i < 0 {
			return "", errors.New("sha512crypt: malformed rounds field")
		}
		r, err := strconv.Atoi(string(salt[:i]))
		if err != nil {
			return "", fmt.Errorf("sha512crypt: invalid rounds: %w", err)
		}
		salt = salt[i+1:]
		isRoundsDef = true
		rounds = r
		if rounds < sha512CryptRoundsMin {
			rounds = sha512CryptRoundsMin
		} else if rounds > sha512CryptRoundsMax {
			rounds = sha512CryptRoundsMax
		}
	}

	// When saltStr is a full hash, strip the stored hash after the last '$'.
	if i := bytes.IndexByte(salt, '$'); i >= 0 {
		salt = salt[:i]
	}
	if len(salt) > sha512CryptSaltLenMax {
		salt = salt[:sha512CryptSaltLenMax]
	}

	// Alternate = SHA512(key + salt + key)
	altH := sha512.New()
	altH.Write(key)
	altH.Write(salt)
	altH.Write(key)
	altSum := altH.Sum(nil)

	// Digest A = SHA512(key + salt + altSum-cycling-to-len(key) + bit-pattern)
	aH := sha512.New()
	aH.Write(key)
	aH.Write(salt)
	for i := len(key); i > 0; i -= 64 {
		if i > 64 {
			aH.Write(altSum)
		} else {
			aH.Write(altSum[:i])
		}
	}
	for i := len(key); i > 0; i >>= 1 {
		if i&1 != 0 {
			aH.Write(altSum)
		} else {
			aH.Write(key)
		}
	}
	aSum := aH.Sum(nil)

	// P-sequence: SHA512(key×len(key)) cycled to len(key) bytes
	pH := sha512.New()
	for i := 0; i < len(key); i++ {
		pH.Write(key)
	}
	pSeq := sha512CryptCycle(pH.Sum(nil), len(key))

	// S-sequence: SHA512(salt×(16+aSum[0])) cycled to len(salt) bytes
	sH := sha512.New()
	for i := 0; i < 16+int(aSum[0]); i++ {
		sH.Write(salt)
	}
	sSeq := sha512CryptCycle(sH.Sum(nil), len(salt))

	// Iterative hashing rounds
	cSum := aSum
	for i := 0; i < rounds; i++ {
		c := sha512.New()
		if i&1 != 0 {
			c.Write(pSeq)
		} else {
			c.Write(cSum)
		}
		if i%3 != 0 {
			c.Write(sSeq)
		}
		if i%7 != 0 {
			c.Write(pSeq)
		}
		if i&1 != 0 {
			c.Write(cSum)
		} else {
			c.Write(pSeq)
		}
		cSum = c.Sum(nil)
	}

	// Build the output string
	out := []byte(sha512CryptMagic)
	if isRoundsDef {
		out = append(out, fmt.Sprintf("rounds=%d$", rounds)...)
	}
	out = append(out, salt...)
	out = append(out, '$')
	out = append(out, sha512CryptEncode(cSum)...)
	return string(out), nil
}

// sha512CryptCycle returns exactly n bytes by cycling the 64-byte src slice.
func sha512CryptCycle(src []byte, n int) []byte {
	dst := make([]byte, 0, n)
	for i := n; i > 64; i -= 64 {
		dst = append(dst, src...)
	}
	if rem := n % 64; rem == 0 && n > 0 {
		dst = append(dst, src...)
	} else if rem > 0 {
		dst = append(dst, src[:rem]...)
	}
	return dst
}

// sha512CryptEncode applies the sha512crypt byte permutation and encodes the
// result with the crypt(3) base-64 alphabet (86 output characters for 64 input bytes).
func sha512CryptEncode(sum []byte) []byte {
	perm := []byte{
		sum[42], sum[21], sum[0],
		sum[1], sum[43], sum[22],
		sum[23], sum[2], sum[44],
		sum[45], sum[24], sum[3],
		sum[4], sum[46], sum[25],
		sum[26], sum[5], sum[47],
		sum[48], sum[27], sum[6],
		sum[7], sum[49], sum[28],
		sum[29], sum[8], sum[50],
		sum[51], sum[30], sum[9],
		sum[10], sum[52], sum[31],
		sum[32], sum[11], sum[53],
		sum[54], sum[33], sum[12],
		sum[13], sum[55], sum[34],
		sum[35], sum[14], sum[56],
		sum[57], sum[36], sum[15],
		sum[16], sum[58], sum[37],
		sum[38], sum[17], sum[59],
		sum[60], sum[39], sum[18],
		sum[19], sum[61], sum[40],
		sum[41], sum[20], sum[62],
		sum[63],
	}
	src := perm
	out := make([]byte, 0, 86)
	for len(src) > 0 {
		switch len(src) {
		default:
			out = append(out,
				sha512CryptAlphabet[src[0]&0x3f],
				sha512CryptAlphabet[((src[0]>>6)|(src[1]<<2))&0x3f],
				sha512CryptAlphabet[((src[1]>>4)|(src[2]<<4))&0x3f],
				sha512CryptAlphabet[(src[2]>>2)&0x3f],
			)
			src = src[3:]
		case 2:
			out = append(out,
				sha512CryptAlphabet[src[0]&0x3f],
				sha512CryptAlphabet[((src[0]>>6)|(src[1]<<2))&0x3f],
				sha512CryptAlphabet[(src[1]>>4)&0x3f],
			)
			src = src[2:]
		case 1:
			out = append(out,
				sha512CryptAlphabet[src[0]&0x3f],
				sha512CryptAlphabet[(src[0]>>6)&0x3f],
			)
			src = src[1:]
		}
	}
	return out
}
