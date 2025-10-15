package server

import (
	"encoding/base32"
	"testing"
	"time"
)

func TestTOTPValidateRFCVector(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	tests := []struct {
		unix int64
		code string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	}
	for _, tt := range tests {
		if !totpValidate(secret, tt.code, time.Unix(tt.unix, 0).UTC()) {
			t.Errorf("time %d code %s invalid", tt.unix, tt.code)
		}
	}
}

func TestTOTPValidateNormalization(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	now := time.Unix(1700000000, 0)
	code := hotpMust(secret, uint64(now.Unix()/totpPeriod))
	if !totpValidate(secret, code, now) {
		t.Fatalf("expected plain code to validate")
	}
	if !totpValidate(secret, code[:3]+" "+code[3:], now) {
		t.Fatalf("expected code with space to validate")
	}
	if !totpValidate(secret, code[:3]+"-"+code[3:], now) {
		t.Fatalf("expected code with dash to validate")
	}
}

func TestTOTPValidateWindow(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	base := time.Unix(1700000000, 0)
	// two-step skew should still succeed
	offset := 2 * totpPeriod
	code := hotpMust(secret, uint64((base.Unix()+int64(offset))/totpPeriod))
	if !totpValidate(secret, code, base) {
		t.Fatalf("expected code with 2-period skew to validate")
	}
}

func hotpMust(secret string, counter uint64) string {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	key, err := enc.DecodeString(secret)
	if err != nil {
		panic(err)
	}
	return hotp(key, counter)
}
