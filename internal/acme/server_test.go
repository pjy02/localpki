package acme

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"localpki/internal/storage"
)

func registerNonce(nm *NonceManager, nonce string, ttl time.Duration) {
	nm.mu.Lock()
	nm.nonces[nonce] = time.Now().Add(ttl)
	nm.mu.Unlock()
}

func TestParseJWS_ES256(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	nm := NewNonceManager(time.Minute)
	nonce := "test-nonce"
	registerNonce(nm, nonce, time.Minute)

	x := priv.X.FillBytes(make([]byte, 32))
	y := priv.Y.FillBytes(make([]byte, 32))
	jwk := map[string]string{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(x),
		"y":   base64.RawURLEncoding.EncodeToString(y),
	}
	protectedMap := map[string]interface{}{
		"alg":   "ES256",
		"nonce": nonce,
		"url":   "/acme/new-account",
		"jwk":   jwk,
	}
	protectedJSON, err := json.Marshal(protectedMap)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	payload := []byte("{\"contact\":[\"mailto:admin@example.com\"]}")
	protected := base64.RawURLEncoding.EncodeToString(protectedJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := []byte(protected + "." + payloadB64)
	hash := sha256.Sum256(signingInput)
	r, s, err := ecdsa.Sign(rand.Reader, priv, hash[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	msg := map[string]string{
		"protected": protected,
		"payload":   payloadB64,
		"signature": base64.RawURLEncoding.EncodeToString(sig),
	}
	body, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal message: %v", err)
	}
	req := httptest.NewRequest("POST", "/acme/new-account", bytes.NewReader(body))

	srv := &Server{Nonces: nm}
	gotPayload, header, err := srv.parseJWS(req)
	if err != nil {
		t.Fatalf("parseJWS: %v", err)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Fatalf("payload mismatch")
	}
	if header.Alg != "ES256" || header.KID != "" {
		t.Fatalf("unexpected header %+v", header)
	}
	if header.JWK["kty"] != "EC" {
		t.Fatalf("expected JWK to be preserved")
	}
	if srv.Nonces.Consume(nonce) {
		t.Fatalf("nonce should have been consumed")
	}
}

func TestParseJWS_RS256WithKID(t *testing.T) {
	nm := NewNonceManager(time.Minute)
	nonce := "kid-nonce"
	registerNonce(nm, nonce, time.Minute)

	dir := t.TempDir()
	store, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa: %v", err)
	}
	jwkMap := map[string]string{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(priv.PublicKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(bigIntBytes(int64(priv.PublicKey.E))),
	}
	jwkBytes, err := json.Marshal(jwkMap)
	if err != nil {
		t.Fatalf("marshal jwk: %v", err)
	}
	acct, err := store.CreateACMEAccount(context.Background(), storage.ACMEAccount{JWK: jwkBytes})
	if err != nil {
		t.Fatalf("create account: %v", err)
	}

	protectedMap := map[string]interface{}{
		"alg":   "RS256",
		"nonce": nonce,
		"kid":   acct.KID,
		"url":   "/acme/new-order",
	}
	protectedJSON, err := json.Marshal(protectedMap)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	payload := []byte("{\"resource\":\"order\"}")
	protected := base64.RawURLEncoding.EncodeToString(protectedJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := []byte(protected + "." + payloadB64)
	hash := sha256.Sum256(signingInput)
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatalf("rsa sign: %v", err)
	}
	msg := map[string]string{
		"protected": protected,
		"payload":   payloadB64,
		"signature": base64.RawURLEncoding.EncodeToString(sig),
	}
	body, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal message: %v", err)
	}
	req := httptest.NewRequest("POST", "/acme/new-order", bytes.NewReader(body))

	srv := &Server{Nonces: nm, Store: store}
	gotPayload, header, err := srv.parseJWS(req)
	if err != nil {
		t.Fatalf("parseJWS: %v", err)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Fatalf("payload mismatch")
	}
	if header.KID != acct.KID {
		t.Fatalf("unexpected kid %s", header.KID)
	}
	if !bytes.Equal(header.JWKRaw, jwkBytes) {
		t.Fatalf("expected stored jwk")
	}
}

func TestParseJWSBadNonce(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	nm := NewNonceManager(time.Minute)
	jwk := map[string]string{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(priv.X.FillBytes(make([]byte, 32))),
		"y":   base64.RawURLEncoding.EncodeToString(priv.Y.FillBytes(make([]byte, 32))),
	}
	protectedMap := map[string]interface{}{
		"alg":   "ES256",
		"nonce": "missing",
		"url":   "/acme/new-account",
		"jwk":   jwk,
	}
	protectedJSON, _ := json.Marshal(protectedMap)
	payload := []byte("{\"test\":true}")
	protected := base64.RawURLEncoding.EncodeToString(protectedJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := []byte(protected + "." + payloadB64)
	hash := sha256.Sum256(signingInput)
	r, s, err := ecdsa.Sign(rand.Reader, priv, hash[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	msg := map[string]string{
		"protected": protected,
		"payload":   payloadB64,
		"signature": base64.RawURLEncoding.EncodeToString(sig),
	}
	body, _ := json.Marshal(msg)
	req := httptest.NewRequest("POST", "/acme/new-account", bytes.NewReader(body))

	srv := &Server{Nonces: nm}
	if _, _, err := srv.parseJWS(req); err == nil {
		t.Fatalf("expected nonce error")
	}
}

func bigIntBytes(v int64) []byte {
	b := make([]byte, 0)
	for v > 0 {
		b = append([]byte{byte(v & 0xff)}, b...)
		v >>= 8
	}
	if len(b) == 0 {
		return []byte{0}
	}
	return b
}
