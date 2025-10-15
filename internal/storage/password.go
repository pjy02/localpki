package storage

import (
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

const (
	passwordSaltSize   = 16
	passwordKeyLength  = 32
	passwordIterations = 120000
)

// HashPassword derives a salted PBKDF2-SHA256 hash for the provided password.
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", fmt.Errorf("password cannot be empty")
	}
	salt := make([]byte, passwordSaltSize)
	if _, err := crand.Read(salt); err != nil {
		return "", err
	}
	key := pbkdf2SHA256([]byte(password), salt, passwordIterations, passwordKeyLength)
	hash := base64.RawStdEncoding.EncodeToString(key)
	encodedSalt := base64.RawStdEncoding.EncodeToString(salt)
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", passwordIterations, encodedSalt, hash), nil
}

// VerifyPassword validates that the password matches the stored PBKDF2 hash.
func VerifyPassword(hash, password string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter <= 0 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	derived := pbkdf2SHA256([]byte(password), salt, iter, len(expected))
	if len(derived) != len(expected) {
		return false
	}
	var diff byte
	for i := range derived {
		diff |= derived[i] ^ expected[i]
	}
	return diff == 0
}

func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	if iter <= 0 || keyLen <= 0 {
		return nil
	}
	hashLen := sha256.Size
	blocks := (keyLen + hashLen - 1) / hashLen
	output := make([]byte, blocks*hashLen)
	block := make([]byte, len(salt)+4)
	copy(block, salt)
	for i := 1; i <= blocks; i++ {
		block[len(salt)] = byte(i >> 24)
		block[len(salt)+1] = byte(i >> 16)
		block[len(salt)+2] = byte(i >> 8)
		block[len(salt)+3] = byte(i)

		h := hmac.New(sha256.New, password)
		h.Write(block)
		u := h.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)

		for j := 1; j < iter; j++ {
			h = hmac.New(sha256.New, password)
			h.Write(u)
			u = h.Sum(nil)
			for k := range t {
				t[k] ^= u[k]
			}
		}

		copy(output[(i-1)*hashLen:], t)
	}
	return output[:keyLen]
}
