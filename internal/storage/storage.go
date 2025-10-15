package storage

import (
	"bufio"
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Store struct {
	certPath        string
	revocationPath  string
	userPath        string
	passkeyPath     string
	auditPath       string
	acmeAccountPath string
	acmeOrderPath   string
	crlStatePath    string

	mu           sync.RWMutex
	certificates map[string]CertificateRecord
	revocations  map[string]RevocationRecord
	users        map[string]*UserRecord
	passkeys     map[string][]WebAuthnCredential
	acmeAccounts map[string]ACMEAccount
	acmeOrders   map[string]ACMEOrder
	auditLog     []AuditRecord
	auditHash    []byte
	crlNumber    uint64
}

type CertificateRecord struct {
	Serial           string     `json:"serial"`
	Subject          string     `json:"subject"`
	SAN              string     `json:"san"`
	Profile          string     `json:"profile"`
	NotBefore        time.Time  `json:"not_before"`
	NotAfter         time.Time  `json:"not_after"`
	PEM              string     `json:"pem"`
	CreatedAt        time.Time  `json:"created_at"`
	Status           string     `json:"status"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	RevocationReason int        `json:"revocation_reason,omitempty"`
}

type RevocationRecord struct {
	Serial    string    `json:"serial"`
	Reason    int       `json:"reason"`
	RevokedAt time.Time `json:"revoked_at"`
}

type AuditEntry struct {
	Actor   string
	Action  string
	Target  string
	IP      string
	Payload interface{}
}

type AuditRecord struct {
	Timestamp time.Time       `json:"timestamp"`
	Actor     string          `json:"actor"`
	Action    string          `json:"action"`
	Target    string          `json:"target"`
	IP        string          `json:"ip"`
	Payload   json.RawMessage `json:"payload,omitempty"`
	PrevHash  string          `json:"prev_hash"`
	Hash      string          `json:"hash"`
}

type UserRecord struct {
	Username    string    `json:"username"`
	DisplayName string    `json:"display_name"`
	Role        string    `json:"role"`
	TOTPSecret  string    `json:"totp_secret"`
	CreatedAt   time.Time `json:"created_at"`
}

type WebAuthnCredential struct {
	ID        string    `json:"id"`
	PublicKey PublicKey `json:"public_key"`
	SignCount uint32    `json:"sign_count"`
	CreatedAt time.Time `json:"created_at"`
}

type PublicKey struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type ACMEAccount struct {
	ID        string          `json:"id"`
	KID       string          `json:"kid"`
	JWK       json.RawMessage `json:"jwk"`
	Contact   []string        `json:"contact"`
	Status    string          `json:"status"`
	CreatedAt time.Time       `json:"created_at"`
}

type ACMEOrder struct {
	ID             string           `json:"id"`
	AccountID      string           `json:"account_id"`
	Status         string           `json:"status"`
	Profile        string           `json:"profile"`
	Identifiers    []ACMEIdentifier `json:"identifiers"`
	CSR            string           `json:"csr"`
	Certificate    string           `json:"certificate"`
	FinalizeURL    string           `json:"finalize_url"`
	CertificateURL string           `json:"certificate_url"`
	CreatedAt      time.Time        `json:"created_at"`
	ExpiresAt      time.Time        `json:"expires_at"`
	NotBefore      *time.Time       `json:"not_before,omitempty"`
	NotAfter       *time.Time       `json:"not_after,omitempty"`
}

type ACMEIdentifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

func Open(path string) (*Store, error) {
	paths, err := derivePaths(path)
	if err != nil {
		return nil, err
	}
	for _, p := range []string{paths.certificates, paths.revocations, paths.users, paths.passkeys, paths.audit, paths.acmeAccounts, paths.acmeOrders, paths.crlState} {
		if err := ensureFile(p); err != nil {
			return nil, err
		}
	}
	s := &Store{
		certPath:        paths.certificates,
		revocationPath:  paths.revocations,
		userPath:        paths.users,
		passkeyPath:     paths.passkeys,
		auditPath:       paths.audit,
		acmeAccountPath: paths.acmeAccounts,
		acmeOrderPath:   paths.acmeOrders,
		crlStatePath:    paths.crlState,
		certificates:    make(map[string]CertificateRecord),
		revocations:     make(map[string]RevocationRecord),
		users:           make(map[string]*UserRecord),
		passkeys:        make(map[string][]WebAuthnCredential),
		acmeAccounts:    make(map[string]ACMEAccount),
		acmeOrders:      make(map[string]ACMEOrder),
	}
	if err := s.loadAll(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return nil }

func (s *Store) loadAll() error {
	if err := readJSONFile(s.certPath, &s.certificates); err != nil {
		return err
	}
	if err := readJSONFile(s.revocationPath, &s.revocations); err != nil {
		return err
	}
	if err := readJSONFile(s.userPath, &s.users); err != nil {
		return err
	}
	if err := readJSONFile(s.passkeyPath, &s.passkeys); err != nil {
		return err
	}
	if err := readJSONFile(s.acmeAccountPath, &s.acmeAccounts); err != nil {
		return err
	}
	if err := readJSONFile(s.acmeOrderPath, &s.acmeOrders); err != nil {
		return err
	}
	if err := s.loadAudit(); err != nil {
		return err
	}
	var crlState struct {
		Last uint64 `json:"last"`
	}
	if err := readJSONFile(s.crlStatePath, &crlState); err != nil {
		return err
	}
	s.crlNumber = crlState.Last
	if s.certificates == nil {
		s.certificates = make(map[string]CertificateRecord)
	}
	if s.revocations == nil {
		s.revocations = make(map[string]RevocationRecord)
	}
	if s.users == nil {
		s.users = make(map[string]*UserRecord)
	}
	if s.passkeys == nil {
		s.passkeys = make(map[string][]WebAuthnCredential)
	}
	if s.acmeAccounts == nil {
		s.acmeAccounts = make(map[string]ACMEAccount)
	}
	if s.acmeOrders == nil {
		s.acmeOrders = make(map[string]ACMEOrder)
	}
	return nil
}

func readJSONFile(path string, v interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("parse %s: %w", filepath.Base(path), err)
	}
	return nil
}

func ensureFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	return f.Close()
}

func derivePaths(path string) (struct {
	certificates string
	revocations  string
	users        string
	passkeys     string
	audit        string
	acmeAccounts string
	acmeOrders   string
	crlState     string
}, error) {
	if path == "" {
		return struct {
			certificates string
			revocations  string
			users        string
			passkeys     string
			audit        string
			acmeAccounts string
			acmeOrders   string
			crlState     string
		}{}, errors.New("storage path must be set")
	}
	info := struct {
		certificates string
		revocations  string
		users        string
		passkeys     string
		audit        string
		acmeAccounts string
		acmeOrders   string
		crlState     string
	}{}
	baseDir := path
	name := "store"
	if filepath.Ext(path) != "" {
		baseDir = filepath.Dir(path)
		base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		if base != "" {
			name = base
		}
	}
	if err := os.MkdirAll(baseDir, 0o700); err != nil {
		return info, err
	}
	info.certificates = filepath.Join(baseDir, name+"_certificates.json")
	info.revocations = filepath.Join(baseDir, name+"_revocations.json")
	info.users = filepath.Join(baseDir, name+"_users.json")
	info.passkeys = filepath.Join(baseDir, name+"_passkeys.json")
	info.audit = filepath.Join(baseDir, name+"_audit.jsonl")
	info.acmeAccounts = filepath.Join(baseDir, name+"_acme_accounts.json")
	info.acmeOrders = filepath.Join(baseDir, name+"_acme_orders.json")
	info.crlState = filepath.Join(baseDir, name+"_crl_state.json")
	return info, nil
}

func (s *Store) saveCertificatesLocked() error {
	return writeJSONFile(s.certPath, s.certificates)
}

func (s *Store) saveRevocationsLocked() error {
	return writeJSONFile(s.revocationPath, s.revocations)
}

func (s *Store) saveUsersLocked() error {
	return writeJSONFile(s.userPath, s.users)
}

func (s *Store) savePasskeysLocked() error {
	return writeJSONFile(s.passkeyPath, s.passkeys)
}

func (s *Store) saveAccountsLocked() error {
	return writeJSONFile(s.acmeAccountPath, s.acmeAccounts)
}

func (s *Store) saveOrdersLocked() error {
	return writeJSONFile(s.acmeOrderPath, s.acmeOrders)
}

func (s *Store) saveCRLStateLocked() error {
	state := struct {
		Last uint64 `json:"last"`
	}{Last: s.crlNumber}
	return writeJSONFile(s.crlStatePath, state)
}

func writeJSONFile(path string, v interface{}) error {
	tmp := path + ".tmp"
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *Store) InsertCertificate(ctx context.Context, cert CertificateRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.certificates[cert.Serial] = cert
	delete(s.revocations, cert.Serial)
	if err := s.saveCertificatesLocked(); err != nil {
		return err
	}
	if err := s.saveRevocationsLocked(); err != nil {
		return err
	}
	return nil
}

func (s *Store) ListCertificates(ctx context.Context) ([]CertificateRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]CertificateRecord, 0, len(s.certificates))
	for _, cert := range s.certificates {
		out = append(out, cert)
	}
	return out, nil
}

func (s *Store) GetCertificate(ctx context.Context, serial string) (CertificateRecord, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cert, ok := s.certificates[serial]
	return cert, ok, nil
}

func (s *Store) RevokeCertificate(ctx context.Context, serial string, reason int, revokedAt time.Time) (CertificateRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cert, ok := s.certificates[serial]
	if !ok {
		return CertificateRecord{}, fmt.Errorf("certificate %s not found", serial)
	}
	if cert.Status == "revoked" {
		return cert, nil
	}
	cert.Status = "revoked"
	cert.RevocationReason = reason
	cert.RevokedAt = &revokedAt
	s.certificates[serial] = cert
	s.revocations[serial] = RevocationRecord{Serial: serial, Reason: reason, RevokedAt: revokedAt}
	if err := s.saveCertificatesLocked(); err != nil {
		return CertificateRecord{}, err
	}
	if err := s.saveRevocationsLocked(); err != nil {
		return CertificateRecord{}, err
	}
	return cert, nil
}

func (s *Store) ListRevocations(ctx context.Context) ([]RevocationRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]RevocationRecord, 0, len(s.revocations))
	for _, rev := range s.revocations {
		out = append(out, rev)
	}
	return out, nil
}

func (s *Store) AppendAudit(ctx context.Context, entry AuditEntry) error {
	payloadBytes, err := json.Marshal(entry.Payload)
	if err != nil {
		return err
	}
	if string(payloadBytes) == "null" {
		payloadBytes = nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.appendAuditLocked(entry, payloadBytes)
}

func (s *Store) appendAuditLocked(entry AuditEntry, payload []byte) error {
	ts := time.Now().UTC()
	prev := s.auditHash
	if prev == nil {
		prev = make([]byte, 32)
	}
	hasher := sha256.New()
	hasher.Write(prev)
	hasher.Write([]byte(ts.Format(time.RFC3339Nano)))
	hasher.Write([]byte(entry.Actor))
	hasher.Write([]byte(entry.Action))
	hasher.Write([]byte(entry.Target))
	hasher.Write([]byte(entry.IP))
	hasher.Write(payload)
	hash := hasher.Sum(nil)
	record := AuditRecord{
		Timestamp: ts,
		Actor:     entry.Actor,
		Action:    entry.Action,
		Target:    entry.Target,
		IP:        entry.IP,
		Payload:   json.RawMessage(payload),
		PrevHash:  hex.EncodeToString(prev),
		Hash:      hex.EncodeToString(hash),
	}
	if err := s.writeAuditRecord(record); err != nil {
		return err
	}
	s.auditHash = hash
	s.auditLog = append(s.auditLog, record)
	return nil
}

func (s *Store) writeAuditRecord(record AuditRecord) error {
	f, err := os.OpenFile(s.auditPath, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	if err := enc.Encode(&record); err != nil {
		return err
	}
	return nil
}

func (s *Store) loadAudit() error {
	file, err := os.OpenFile(s.auditPath, os.O_RDONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	var lastHash []byte
	prev := make([]byte, 32)
	for scanner.Scan() {
		line := scanner.Bytes()
		var record AuditRecord
		if err := json.Unmarshal(line, &record); err != nil {
			return fmt.Errorf("parse audit log: %w", err)
		}
		if record.Hash == "" {
			return errors.New("audit log entry missing hash")
		}
		hashBytes, err := hex.DecodeString(record.Hash)
		if err != nil {
			return fmt.Errorf("decode audit hash: %w", err)
		}
		if record.PrevHash != "" {
			prev, err = hex.DecodeString(record.PrevHash)
			if err != nil {
				return fmt.Errorf("decode audit prev hash: %w", err)
			}
		}
		expected := computeAuditHash(prev, record)
		if !equalBytes(expected, hashBytes) {
			return errors.New("audit log integrity check failed")
		}
		lastHash = hashBytes
		copy(prev, hashBytes)
		s.auditLog = append(s.auditLog, record)
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if lastHash != nil {
		s.auditHash = lastHash
	}
	return nil
}

func computeAuditHash(prev []byte, record AuditRecord) []byte {
	hasher := sha256.New()
	if prev != nil {
		hasher.Write(prev)
	}
	hasher.Write([]byte(record.Timestamp.Format(time.RFC3339Nano)))
	hasher.Write([]byte(record.Actor))
	hasher.Write([]byte(record.Action))
	hasher.Write([]byte(record.Target))
	hasher.Write([]byte(record.IP))
	if record.Payload != nil {
		hasher.Write(record.Payload)
	}
	return hasher.Sum(nil)
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var res byte
	for i := range a {
		res |= a[i] ^ b[i]
	}
	return res == 0
}

func (s *Store) ListAudit(ctx context.Context, limit int) ([]AuditRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > len(s.auditLog) {
		limit = len(s.auditLog)
	}
	start := len(s.auditLog) - limit
	if start < 0 {
		start = 0
	}
	out := make([]AuditRecord, limit)
	copy(out, s.auditLog[start:])
	return out, nil
}

func (s *Store) EnsureAdminUser(ctx context.Context, secretGenerator func() (string, error)) (*UserRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if user, ok := s.users["admin"]; ok {
		return user, false, nil
	}
	secret, err := secretGenerator()
	if err != nil {
		return nil, false, err
	}
	user := &UserRecord{
		Username:    "admin",
		DisplayName: "Administrator",
		Role:        "admin",
		TOTPSecret:  secret,
		CreatedAt:   time.Now().UTC(),
	}
	s.users[user.Username] = user
	if err := s.saveUsersLocked(); err != nil {
		return nil, false, err
	}
	return user, true, nil
}

func (s *Store) GetUser(ctx context.Context, username string) (*UserRecord, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, ok := s.users[username]
	if !ok {
		return nil, false, nil
	}
	clone := *user
	return &clone, true, nil
}

func (s *Store) UpdateTOTPSecret(ctx context.Context, username, secret string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[username]
	if !ok {
		return fmt.Errorf("user %s not found", username)
	}
	user.TOTPSecret = secret
	return s.saveUsersLocked()
}

func (s *Store) AddWebAuthnCredential(ctx context.Context, username string, cred WebAuthnCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[username]; !ok {
		return fmt.Errorf("user %s not found", username)
	}
	creds := s.passkeys[username]
	for _, existing := range creds {
		if existing.ID == cred.ID {
			return errors.New("credential already registered")
		}
	}
	cred.CreatedAt = time.Now().UTC()
	s.passkeys[username] = append(creds, cred)
	return s.savePasskeysLocked()
}

func (s *Store) ListWebAuthnCredentials(ctx context.Context, username string) ([]WebAuthnCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	creds := s.passkeys[username]
	dup := make([]WebAuthnCredential, len(creds))
	copy(dup, creds)
	return dup, nil
}

func (s *Store) GetWebAuthnCredential(ctx context.Context, username, credentialID string) (WebAuthnCredential, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	creds := s.passkeys[username]
	for _, c := range creds {
		if c.ID == credentialID {
			return c, true, nil
		}
	}
	return WebAuthnCredential{}, false, nil
}

func (s *Store) UpdateWebAuthnCredential(ctx context.Context, username string, cred WebAuthnCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	creds := s.passkeys[username]
	for i, c := range creds {
		if c.ID == cred.ID {
			cred.CreatedAt = c.CreatedAt
			s.passkeys[username][i] = cred
			return s.savePasskeysLocked()
		}
	}
	return fmt.Errorf("credential %s not found", cred.ID)
}

func (s *Store) CreateACMEAccount(ctx context.Context, account ACMEAccount) (ACMEAccount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if account.ID == "" {
		account.ID = randomID()
	}
	if account.KID == "" {
		account.KID = "acct-" + account.ID
	}
	if account.CreatedAt.IsZero() {
		account.CreatedAt = time.Now().UTC()
	}
	account.Status = "valid"
	s.acmeAccounts[account.ID] = account
	if err := s.saveAccountsLocked(); err != nil {
		return ACMEAccount{}, err
	}
	return account, nil
}

func (s *Store) GetACMEAccount(ctx context.Context, kid string) (ACMEAccount, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if acct, ok := s.acmeAccounts[kid]; ok {
		return acct, true, nil
	}
	for _, acct := range s.acmeAccounts {
		if acct.KID == kid {
			return acct, true, nil
		}
	}
	return ACMEAccount{}, false, nil
}

func (s *Store) CreateACMEOrder(ctx context.Context, order ACMEOrder) (ACMEOrder, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if order.ID == "" {
		order.ID = randomID()
	}
	if order.CreatedAt.IsZero() {
		order.CreatedAt = time.Now().UTC()
	}
	if order.ExpiresAt.IsZero() {
		order.ExpiresAt = order.CreatedAt.Add(24 * time.Hour)
	}
	order.Status = "pending"
	s.acmeOrders[order.ID] = order
	if err := s.saveOrdersLocked(); err != nil {
		return ACMEOrder{}, err
	}
	return order, nil
}

func (s *Store) UpdateACMEOrder(ctx context.Context, order ACMEOrder) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.acmeOrders[order.ID]; !ok {
		return fmt.Errorf("order %s not found", order.ID)
	}
	s.acmeOrders[order.ID] = order
	return s.saveOrdersLocked()
}

func (s *Store) GetACMEOrder(ctx context.Context, id string) (ACMEOrder, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	order, ok := s.acmeOrders[id]
	return order, ok, nil
}

func (s *Store) ListACMEOrdersByAccount(ctx context.Context, accountID string) ([]ACMEOrder, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []ACMEOrder
	for _, order := range s.acmeOrders {
		if order.AccountID == accountID {
			out = append(out, order)
		}
	}
	return out, nil
}

func (s *Store) UpdateACMEAccount(ctx context.Context, account ACMEAccount) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if account.ID == "" {
		return errors.New("account id required")
	}
	s.acmeAccounts[account.ID] = account
	return s.saveAccountsLocked()
}

func randomID() string {
	b := make([]byte, 18)
	if _, err := crand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Store) DeleteAuditLog(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.WriteFile(s.auditPath, nil, 0o600); err != nil {
		return err
	}
	s.auditHash = nil
	s.auditLog = nil
	return nil
}

func (s *Store) RemoveACMEOrder(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.acmeOrders, id)
	return s.saveOrdersLocked()
}

func (s *Store) NextCRLNumber(ctx context.Context) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.crlNumber++
	if err := s.saveCRLStateLocked(); err != nil {
		return 0, err
	}
	return s.crlNumber, nil
}
