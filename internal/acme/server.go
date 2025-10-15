package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"localpki/internal/pki"
	"localpki/internal/storage"
)

type Server struct {
	Signer         *pki.Signer
	Profiles       map[string]pki.Profile
	DefaultProfile string
	Store          *storage.Store
	BasePath       string
	Nonces         *NonceManager
	Audit          func(ctx context.Context, entry storage.AuditEntry) error
}

type NonceManager struct {
	mu     sync.Mutex
	nonces map[string]time.Time
	ttl    time.Duration
}

func NewNonceManager(ttl time.Duration) *NonceManager {
	return &NonceManager{nonces: make(map[string]time.Time), ttl: ttl}
}

func (n *NonceManager) Generate() string {
	token := randomToken(32)
	n.mu.Lock()
	n.nonces[token] = time.Now().Add(n.ttl)
	n.mu.Unlock()
	return token
}

func (n *NonceManager) Consume(token string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	expiry, ok := n.nonces[token]
	if !ok {
		return false
	}
	delete(n.nonces, token)
	if time.Now().After(expiry) {
		return false
	}
	return true
}

func (s *Server) directoryURL(r *http.Request) string {
	return s.absoluteURL(r, s.BasePath+"/directory")
}

func (s *Server) absoluteURL(r *http.Request, p string) string {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	host := r.Host
	if strings.HasPrefix(p, "http") {
		return p
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return fmt.Sprintf("%s://%s%s", scheme, host, p)
}

func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc(path.Join(s.BasePath, "/directory"), s.handleDirectory)
	mux.HandleFunc(path.Join(s.BasePath, "/new-nonce"), s.handleNewNonce)
	mux.HandleFunc(path.Join(s.BasePath, "/new-account"), s.handleNewAccount)
	mux.HandleFunc(path.Join(s.BasePath, "/new-order"), s.handleNewOrder)
	mux.HandleFunc(path.Join(s.BasePath, "/account/"), s.handleAccount)
	mux.HandleFunc(path.Join(s.BasePath, "/order/"), s.handleOrder)
}

func (s *Server) setReplayNonce(w http.ResponseWriter) {
	nonce := s.Nonces.Generate()
	w.Header().Set("Replay-Nonce", nonce)
}

func (s *Server) handleDirectory(w http.ResponseWriter, r *http.Request) {
	s.setReplayNonce(w)
	base := s.absoluteURL(r, s.BasePath)
	payload := map[string]interface{}{
		"newNonce":   base + "/new-nonce",
		"newAccount": base + "/new-account",
		"newOrder":   base + "/new-order",
		"revokeCert": base + "/revoke-cert",
		"keyChange":  base + "/key-change",
		"meta": map[string]interface{}{
			"termsOfService": "https://example.invalid/terms",
		},
	}
	respondJSON(w, payload)
}

func (s *Server) handleNewNonce(w http.ResponseWriter, r *http.Request) {
	s.setReplayNonce(w)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleNewAccount(w http.ResponseWriter, r *http.Request) {
	s.setReplayNonce(w)
	payload, header, err := s.parseJWS(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if header.KID != "" {
		http.Error(w, "account already exists", http.StatusBadRequest)
		return
	}
	var req struct {
		Contact []string `json:"contact"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}
	account := storage.ACMEAccount{
		Contact: req.Contact,
		JWK:     header.JWKRaw,
	}
	account, err = s.Store.CreateACMEAccount(r.Context(), account)
	if err != nil {
		http.Error(w, "unable to persist account", http.StatusInternalServerError)
		return
	}
	accountURL := s.absoluteURL(r, path.Join(s.BasePath, "account", account.ID))
	account.KID = accountURL
	if err := s.Store.UpdateACMEAccount(r.Context(), account); err != nil {
		http.Error(w, "unable to persist account", http.StatusInternalServerError)
		return
	}
	response := map[string]interface{}{
		"status":  account.Status,
		"contact": account.Contact,
		"orders":  s.absoluteURL(r, path.Join(s.BasePath, "account", account.ID, "orders")),
	}
	w.Header().Set("Location", accountURL)
	respondJSONWithStatus(w, response, http.StatusCreated)
	if s.Audit != nil {
		s.Audit(r.Context(), storage.AuditEntry{Actor: account.KID, Action: "acme_new_account", Target: accountURL, IP: r.RemoteAddr, Payload: response})
	}
}

func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	s.setReplayNonce(w)
	segments := strings.Split(strings.TrimPrefix(r.URL.Path, s.BasePath+"/account/"), "/")
	if len(segments) == 0 || segments[0] == "" {
		http.NotFound(w, r)
		return
	}
	id := segments[0]
	acct, ok, err := s.Store.GetACMEAccount(r.Context(), "acct-"+id)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	payload := map[string]interface{}{
		"status":  acct.Status,
		"contact": acct.Contact,
	}
	respondJSON(w, payload)
}

func (s *Server) handleNewOrder(w http.ResponseWriter, r *http.Request) {
	s.setReplayNonce(w)
	payload, header, err := s.parseJWS(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	account, err := s.lookupAccount(r.Context(), header)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	var req struct {
		Identifiers []storage.ACMEIdentifier `json:"identifiers"`
		Profile     string                   `json:"profile"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}
	profile := req.Profile
	if profile == "" {
		profile = s.DefaultProfile
	}
	if _, ok := s.Profiles[profile]; !ok {
		http.Error(w, "unknown profile", http.StatusBadRequest)
		return
	}
	order := storage.ACMEOrder{
		AccountID:   account.ID,
		Identifiers: req.Identifiers,
		Profile:     profile,
	}
	order, err = s.Store.CreateACMEOrder(r.Context(), order)
	if err != nil {
		http.Error(w, "unable to persist order", http.StatusInternalServerError)
		return
	}
	order.FinalizeURL = s.absoluteURL(r, path.Join(s.BasePath, "order", order.ID, "finalize"))
	order.CertificateURL = s.absoluteURL(r, path.Join(s.BasePath, "order", order.ID, "certificate"))
	order.Status = "ready"
	if err := s.Store.UpdateACMEOrder(r.Context(), order); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	resp := map[string]interface{}{
		"status":         "ready",
		"expires":        order.ExpiresAt.Format(time.RFC3339),
		"identifiers":    order.Identifiers,
		"finalize":       order.FinalizeURL,
		"authorizations": []string{},
	}
	respondJSONWithStatus(w, resp, http.StatusCreated)
	if s.Audit != nil {
		s.Audit(r.Context(), storage.AuditEntry{Actor: account.KID, Action: "acme_new_order", Target: order.ID, IP: r.RemoteAddr, Payload: resp})
	}
}

func (s *Server) handleOrder(w http.ResponseWriter, r *http.Request) {
	s.setReplayNonce(w)
	segments := strings.Split(strings.TrimPrefix(r.URL.Path, s.BasePath+"/order/"), "/")
	if len(segments) == 0 || segments[0] == "" {
		http.NotFound(w, r)
		return
	}
	id := segments[0]
	order, ok, err := s.Store.GetACMEOrder(r.Context(), id)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	switch {
	case len(segments) == 2 && segments[1] == "finalize" && r.Method == http.MethodPost:
		s.handleFinalize(w, r, order)
	case len(segments) == 2 && segments[1] == "certificate" && r.Method == http.MethodGet:
		s.handleCertificate(w, r, order)
	case len(segments) == 1 && r.Method == http.MethodGet:
		resp := map[string]interface{}{
			"status":      order.Status,
			"expires":     order.ExpiresAt.Format(time.RFC3339),
			"identifiers": order.Identifiers,
			"finalize":    order.FinalizeURL,
		}
		if order.CertificateURL != "" && order.Status == "valid" {
			resp["certificate"] = order.CertificateURL
		}
		respondJSON(w, resp)
	default:
		http.Error(w, "unsupported", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleFinalize(w http.ResponseWriter, r *http.Request, order storage.ACMEOrder) {
	payload, header, err := s.parseJWS(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := s.lookupAccount(r.Context(), header); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	var req struct {
		CSR string `json:"csr"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}
	csrDER, err := base64.RawURLEncoding.DecodeString(req.CSR)
	if err != nil {
		http.Error(w, "invalid csr encoding", http.StatusBadRequest)
		return
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		http.Error(w, "invalid csr", http.StatusBadRequest)
		return
	}
	if err := csr.CheckSignature(); err != nil {
		http.Error(w, "csr signature invalid", http.StatusBadRequest)
		return
	}
	if err := s.validateIdentifiers(order, csr); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	profile := s.Profiles[order.Profile]
	certDER, chain, err := s.Signer.SignCSR(csr, profile)
	if err != nil {
		http.Error(w, "signing failed", http.StatusInternalServerError)
		return
	}
	certPEM := string(pki.ChainToPEM([][]byte{certDER}))
	order.Certificate = string(pki.ChainToPEM(chain))
	order.Status = "valid"
	if err := s.Store.UpdateACMEOrder(r.Context(), order); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	leaf, _ := x509.ParseCertificate(certDER)
	record := storage.CertificateRecord{
		Serial:    serialToString(leaf.SerialNumber),
		Subject:   leaf.Subject.String(),
		SAN:       pki.InspectSANs(csr),
		Profile:   order.Profile,
		NotBefore: leaf.NotBefore,
		NotAfter:  leaf.NotAfter,
		PEM:       certPEM,
		CreatedAt: time.Now().UTC(),
		Status:    "issued",
	}
	_ = s.Store.InsertCertificate(r.Context(), record)
	resp := map[string]interface{}{
		"status":      "valid",
		"certificate": order.CertificateURL,
	}
	respondJSON(w, resp)
	if s.Audit != nil {
		s.Audit(r.Context(), storage.AuditEntry{Actor: header.KID, Action: "acme_finalize", Target: order.ID, IP: r.RemoteAddr, Payload: resp})
	}
}

func (s *Server) handleCertificate(w http.ResponseWriter, r *http.Request, order storage.ACMEOrder) {
	if order.Status != "valid" || order.Certificate == "" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.Write([]byte(order.Certificate))
}

func (s *Server) validateIdentifiers(order storage.ACMEOrder, csr *x509.CertificateRequest) error {
	identifiers := make(map[string]struct{})
	for _, id := range order.Identifiers {
		if id.Type == "dns" {
			identifiers[strings.ToLower(id.Value)] = struct{}{}
		}
	}
	for _, dns := range csr.DNSNames {
		delete(identifiers, strings.ToLower(dns))
	}
	if len(identifiers) > 0 {
		return errors.New("csr identifiers mismatch")
	}
	return nil
}

func (s *Server) lookupAccount(ctx context.Context, header jwsHeader) (storage.ACMEAccount, error) {
	if header.KID == "" {
		return storage.ACMEAccount{}, errors.New("kid required")
	}
	acct, ok, err := s.Store.GetACMEAccount(ctx, header.KID)
	if err != nil {
		return storage.ACMEAccount{}, errors.New("account lookup failed")
	}
	if !ok {
		return storage.ACMEAccount{}, errors.New("account not found")
	}
	return acct, nil
}

type jwsMessage struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type jwsHeader struct {
	Alg    string            `json:"alg"`
	Nonce  string            `json:"nonce"`
	URL    string            `json:"url"`
	KID    string            `json:"kid"`
	JWK    map[string]string `json:"jwk"`
	JWKRaw json.RawMessage   `json:"-"`
}

func (s *Server) parseJWS(r *http.Request) ([]byte, jwsHeader, error) {
	var msg jwsMessage
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		return nil, jwsHeader{}, errors.New("invalid jws")
	}
	protectedBytes, err := base64.RawURLEncoding.DecodeString(msg.Protected)
	if err != nil {
		return nil, jwsHeader{}, errors.New("invalid protected header")
	}
	var header jwsHeader
	if err := json.Unmarshal(protectedBytes, &header); err != nil {
		return nil, jwsHeader{}, errors.New("invalid header")
	}
	if header.URL != "" && !strings.HasSuffix(r.URL.Path, header.URL[strings.LastIndex(header.URL, "/"):]) {
		// ignore mismatch but still note
	}
	if !s.Nonces.Consume(header.Nonce) {
		return nil, jwsHeader{}, errors.New("bad replay nonce")
	}
	payload, err := base64.RawURLEncoding.DecodeString(msg.Payload)
	if err != nil {
		return nil, jwsHeader{}, errors.New("invalid payload encoding")
	}
	sig, err := base64.RawURLEncoding.DecodeString(msg.Signature)
	if err != nil {
		return nil, jwsHeader{}, errors.New("invalid signature encoding")
	}
	var pub interface{}
	if header.KID != "" {
		acct, ok, err := s.Store.GetACMEAccount(r.Context(), header.KID)
		if err != nil || !ok {
			return nil, jwsHeader{}, errors.New("account not found")
		}
		header.JWKRaw = acct.JWK
		pub, err = parseJWK(acct.JWK)
		if err != nil {
			return nil, jwsHeader{}, err
		}
	} else {
		if len(header.JWK) == 0 {
			return nil, jwsHeader{}, errors.New("jwk required")
		}
		keyBytes, err := json.Marshal(header.JWK)
		if err != nil {
			return nil, jwsHeader{}, err
		}
		header.JWKRaw = keyBytes
		pub, err = parseJWK(keyBytes)
		if err != nil {
			return nil, jwsHeader{}, err
		}
	}
	signingInput := []byte(msg.Protected + "." + msg.Payload)
	if err := verifyJWS(header.Alg, pub, signingInput, sig); err != nil {
		return nil, jwsHeader{}, err
	}
	return payload, header, nil
}

func parseJWK(data []byte) (interface{}, error) {
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	switch m["kty"] {
	case "EC":
		if m["crv"] != "P-256" {
			return nil, errors.New("unsupported curve")
		}
		xBytes, err := base64.RawURLEncoding.DecodeString(m["x"])
		if err != nil {
			return nil, err
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(m["y"])
		if err != nil {
			return nil, err
		}
		x := new(big.Int).SetBytes(xBytes)
		y := new(big.Int).SetBytes(yBytes)
		return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
	case "RSA":
		nBytes, err := base64.RawURLEncoding.DecodeString(m["n"])
		if err != nil {
			return nil, err
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(m["e"])
		if err != nil {
			return nil, err
		}
		e := big.NewInt(0).SetBytes(eBytes).Int64()
		if e == 0 {
			e = 65537
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(e)}
		return pub, nil
	default:
		return nil, errors.New("unsupported jwk")
	}
}

func verifyJWS(alg string, pub interface{}, signingInput, sig []byte) error {
	switch alg {
	case "ES256":
		key, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("invalid key type")
		}
		return verifyES256(key, signingInput, sig)
	case "RS256":
		key, ok := pub.(*rsa.PublicKey)
		if !ok {
			return errors.New("invalid key type")
		}
		hash := sha256.Sum256(signingInput)
		if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], sig); err != nil {
			return errors.New("invalid signature")
		}
		return nil
	default:
		return errors.New("unsupported algorithm")
	}
}

func verifyES256(pub *ecdsa.PublicKey, signingInput, sig []byte) error {
	if len(sig) != 64 {
		return errors.New("invalid es256 signature")
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	hash := sha256.Sum256(signingInput)
	if !ecdsa.Verify(pub, hash[:], r, s) {
		return errors.New("invalid signature")
	}
	return nil
}

func respondJSON(w http.ResponseWriter, v interface{}) {
	respondJSONWithStatus(w, v, http.StatusOK)
}

func respondJSONWithStatus(w http.ResponseWriter, v interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func serialToString(n *big.Int) string {
	if n == nil {
		return ""
	}
	return strings.ToUpper(n.Text(16))
}

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := crand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
