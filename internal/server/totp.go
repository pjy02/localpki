package server

import (
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"fmt"
	"math"
	"strings"
	"time"
)

const (
	totpPeriod = 30
	totpDigits = 6
)

func generateTOTPSecret() (string, error) {
	buf := make([]byte, 20)
	if _, err := crand.Read(buf); err != nil {
		return "", err
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	return enc.EncodeToString(buf), nil
}

// GenerateTOTPSecret exposes the secret generator for bootstrapping.
func GenerateTOTPSecret() (string, error) {
	return generateTOTPSecret()
}

func totpValidate(secret, code string, now time.Time) bool {
	if len(code) != totpDigits {
		return false
	}
	if secret == "" {
		return false
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	key, err := enc.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return false
	}
	steps := []int{-1, 0, 1}
	for _, s := range steps {
		counter := uint64(math.Floor(float64(now.Unix())/totpPeriod)) + uint64(s)
		if hotp(key, counter) == code {
			return true
		}
	}
	return false
}

func hotp(key []byte, counter uint64) string {
	msg := make([]byte, 8)
	for i := uint(0); i < 8; i++ {
		msg[7-i] = byte(counter & 0xff)
		counter >>= 8
	}
	mac := hmac.New(sha1.New, key)
	mac.Write(msg)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	truncated := (int(sum[offset])&0x7f)<<24 | (int(sum[offset+1])&0xff)<<16 | (int(sum[offset+2])&0xff)<<8 | (int(sum[offset+3]) & 0xff)
	value := truncated % int(math.Pow10(totpDigits))
	return fmt.Sprintf("%0*d", totpDigits, value)
}

func totpProvisioningURL(secret, account string) string {
	issuer := "LocalPKI"
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&period=%d", issuer, account, secret, issuer, totpPeriod)
}
