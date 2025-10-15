package server

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"testing"
)

func TestParseAttestationNone(t *testing.T) {
	att := []byte{
		0xa2,                // map(2)
		0x63, 'f', 'm', 't', // "fmt"
		0x64, 'n', 'o', 'n', 'e', // "none"
		0x68, 'a', 'u', 't', 'h', 'D', 'a', 't', 'a', // "authData"
		0x42, 0x01, 0x02, // byte string of length 2
	}
	obj, err := parseAttestation(att)
	if err != nil {
		t.Fatalf("parseAttestation error: %v", err)
	}
	if obj.Format != "none" {
		t.Fatalf("unexpected format %q", obj.Format)
	}
	if !bytes.Equal(obj.AuthData, []byte{0x01, 0x02}) {
		t.Fatalf("unexpected auth data %x", obj.AuthData)
	}
}

func TestParseAttestationUnsupported(t *testing.T) {
	att := []byte{
		0xa2,
		0x63, 'f', 'm', 't',
		0x66, 'p', 'a', 'c', 'k', 'e', 'd',
		0x68, 'a', 'u', 't', 'h', 'D', 'a', 't', 'a',
		0x42, 0x01, 0x02,
	}
	if _, err := parseAttestation(att); err == nil {
		t.Fatalf("expected unsupported format error")
	}
}

func TestParseAuthData(t *testing.T) {
	var data []byte
	data = append(data, bytes.Repeat([]byte{0x11}, 32)...) // rpIDHash
	data = append(data, flagUserPresent|flagAttestedData)  // flags
	count := make([]byte, 4)
	binary.BigEndian.PutUint32(count, 5)
	data = append(data, count...)
	data = append(data, make([]byte, 16)...)
	data = append(data, 0x00, 0x03)
	data = append(data, 0xaa, 0xbb, 0xcc)
	cose := []byte{
		0xa5,
		0x01, 0x02,
		0x03, 0x26,
		0x20, 0x01,
		0x21, 0x58, 0x20,
	}
	cose = append(cose, bytes.Repeat([]byte{0x01}, 32)...)
	cose = append(cose, 0x22, 0x58, 0x20)
	cose = append(cose, bytes.Repeat([]byte{0x02}, 32)...)
	data = append(data, cose...)
	auth, err := parseAuthData(data)
	if err != nil {
		t.Fatalf("parseAuthData error: %v", err)
	}
	if auth.signCount != 5 {
		t.Fatalf("unexpected signCount %d", auth.signCount)
	}
	if !bytes.Equal(auth.credentialID, []byte{0xaa, 0xbb, 0xcc}) {
		t.Fatalf("unexpected credential id %x", auth.credentialID)
	}
	expectedX := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, 32))
	expectedY := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x02}, 32))
	if auth.publicKey.X != expectedX || auth.publicKey.Y != expectedY {
		t.Fatalf("unexpected public key %+v", auth.publicKey)
	}
}

func TestParseAuthDataMissingAttested(t *testing.T) {
	data := make([]byte, 37)
	data[32] = flagUserPresent
	if _, err := parseAuthData(data); err == nil {
		t.Fatalf("expected error for missing attested data")
	}
}
