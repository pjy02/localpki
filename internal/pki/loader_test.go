package pki

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPrivateKey_ECDSA(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "ec.key")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	signer, err := LoadPrivateKey(path, "")
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	if _, ok := signer.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("expected ecdsa key, got %T", signer)
	}
}

func TestLoadPrivateKey_RSA(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(priv)
	dir := t.TempDir()
	path := filepath.Join(dir, "rsa.key")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	signer, err := LoadPrivateKey(path, "")
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	if _, ok := signer.(*rsa.PrivateKey); !ok {
		t.Fatalf("expected rsa key, got %T", signer)
	}
}

func TestLoadPrivateKey_PKCS8Ed25519(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "ed25519.key")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	signer, err := LoadPrivateKey(path, "")
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	if _, ok := signer.(ed25519.PrivateKey); !ok {
		t.Fatalf("expected ed25519 key, got %T", signer)
	}
}

func TestLoadPrivateKey_Encrypted(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	block, err := x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", der, []byte("secret"), x509.PEMCipherAES256)
	if err != nil {
		t.Fatalf("encrypt pem: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "encrypted.key")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if _, err := LoadPrivateKey(path, ""); err == nil {
		t.Fatalf("expected error when password missing")
	}
	signer, err := LoadPrivateKey(path, "secret")
	if err != nil {
		t.Fatalf("LoadPrivateKey with password: %v", err)
	}
	if _, ok := signer.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("expected ecdsa key, got %T", signer)
	}
}
