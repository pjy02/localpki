package server

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/big"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"localpki/internal/acme"
	"localpki/internal/pki"
	"localpki/internal/storage"
)

const (
	sessionCookie   = "localpki_session"
	loginCSRFCookie = "localpki_login_csrf"
)

type contextKey string

// API bundles dependencies required to serve HTTP requests.
type API struct {
	Signer            *pki.Signer
	Profiles          map[string]pki.Profile
	DefaultProfile    string
	Store             *storage.Store
	Sessions          *SessionManager
	Templates         *template.Template
	RP                RelyingPartyConfig
	SessionDuration   time.Duration
	ACME              *acme.Server
	bootstrapPassword string
	loginChallenges   map[string]webAuthnChallenge
	loginMu           sync.Mutex
}

// RelyingPartyConfig describes WebAuthn Relying Party properties.
type RelyingPartyConfig struct {
	ID      string
	Name    string
	Origins []string
}

// NewAPI constructs an API with generated secrets.
func NewAPI() *API {
	return &API{
		Sessions:        NewSessionManager(),
		loginChallenges: make(map[string]webAuthnChallenge),
	}
}

// Register attaches handlers to the provided mux.
func (a *API) Register(mux *http.ServeMux) {
	mux.HandleFunc("/", a.handleIndex)
	mux.HandleFunc("/login", a.handleLogin)
	mux.HandleFunc("/logout", a.requireAuth(a.handleLogout))
	mux.HandleFunc("/ui", a.requireAuth(a.handleDashboard))
	mux.HandleFunc("/ui/certificates", a.requireAuth(a.handleCertificates))
	mux.HandleFunc("/ui/certificates/sign", a.requireAuth(a.handleSignUI))
	mux.HandleFunc("/ui/certificates/revoke", a.requireAuth(a.handleRevokeUI))
	mux.HandleFunc("/ui/audit", a.requireAuth(a.handleAudit))
	mux.HandleFunc("/ui/password", a.requireAuth(a.handlePassword))
	mux.HandleFunc("/ui/passkey", a.requireAuth(a.handlePasskey))
	mux.HandleFunc("/auth/webauthn/begin-register", a.requireAuth(a.handleBeginRegister))
	mux.HandleFunc("/auth/webauthn/finish-register", a.requireAuth(a.handleFinishRegister))
	mux.HandleFunc("/auth/webauthn/begin-login", a.handleBeginLogin)
	mux.HandleFunc("/auth/webauthn/finish-login", a.handleFinishLogin)
	mux.HandleFunc("/api/v1/health", a.handleHealth)
	mux.HandleFunc("/api/v1/certificates/sign", a.requireAuth(a.handleSign))
	mux.HandleFunc("/api/v1/certificates/revoke", a.requireAuth(a.handleRevokeAPI))
	mux.HandleFunc("/crl", a.handleCRL)
	mux.HandleFunc("/ocsp", a.handleOCSP)
	if a.ACME != nil {
		a.ACME.Register(mux)
	}
}

func (a *API) handleIndex(w http.ResponseWriter, r *http.Request) {
	if sess, _ := a.sessionFromRequest(r); sess != nil {
		http.Redirect(w, r, "/ui", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (a *API) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (a *API) handleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		token := randomToken(16)
		http.SetCookie(w, &http.Cookie{
			Name:     loginCSRFCookie,
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})
		data := map[string]interface{}{
			"CSRF": token,
		}
		if a.bootstrapPassword != "" {
			data["BootstrapPassword"] = a.bootstrapPassword
		}
		a.render(w, "login", data)
	case http.MethodPost:
		if !a.verifyLoginCSRF(r) {
			a.renderLoginError(w, "CSRF 验证失败")
			return
		}
		if err := r.ParseForm(); err != nil {
			a.renderLoginError(w, "请求无效")
			return
		}
		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")
		if username == "" || password == "" {
			a.renderLoginError(w, "请输入用户名与密码")
			return
		}
		user, ok, err := a.Store.GetUser(r.Context(), username)
		if err != nil || !ok {
			time.Sleep(500 * time.Millisecond)
			a.renderLoginError(w, "认证失败")
			return
		}
		if !storage.VerifyPassword(user.PasswordHash, password) {
			time.Sleep(500 * time.Millisecond)
			a.renderLoginError(w, "用户名或密码错误")
			return
		}
		a.bootstrapPassword = ""
		token, sess := a.Sessions.Create(username, a.SessionDuration)
		csrf := randomToken(16)
		sess.Values["csrf"] = []byte(csrf)
		a.setSessionCookie(w, token, sess.Expires)
		a.audit(r, username, "login_password", "", nil)
		http.Redirect(w, r, "/ui", http.StatusFound)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
func (a *API) verifyLoginCSRF(r *http.Request) bool {
	c, err := r.Cookie(loginCSRFCookie)
	if err != nil {
		return false
	}
	form := r.FormValue("csrf")
	return hmac.Equal([]byte(c.Value), []byte(form))
}

func (a *API) renderLoginError(w http.ResponseWriter, msg string) {
	data := map[string]interface{}{
		"Flash": msg,
	}
	a.render(w, "login", data)
}

func (a *API) setSessionCookie(w http.ResponseWriter, token string, expiry time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  expiry,
	})
}

func (a *API) handleLogout(w http.ResponseWriter, r *http.Request) {
	token := a.sessionToken(r)
	if token != "" {
		a.Sessions.Destroy(token)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (a *API) handleDashboard(w http.ResponseWriter, r *http.Request) {
	sess := r.Context().Value(contextKey("session")).(*session)
	csrf := a.ensureSessionCSRF(sess)
	data := map[string]interface{}{
		"CSRF":          csrf,
		"Profiles":      a.profileNames(),
		"ACMEDirectory": a.acmeDirectory(r),
	}
	a.render(w, "dashboard", data)
}

func (a *API) handleCertificates(w http.ResponseWriter, r *http.Request) {
	sess := r.Context().Value(contextKey("session")).(*session)
	csrf := a.ensureSessionCSRF(sess)
	certs, err := a.Store.ListCertificates(r.Context())
	if err != nil {
		http.Error(w, "无法读取证书记录", http.StatusInternalServerError)
		return
	}
	data := map[string]interface{}{
		"Certificates": certs,
		"CSRF":         csrf,
	}
	a.render(w, "certificates", data)
}

func (a *API) handleAudit(w http.ResponseWriter, r *http.Request) {
	audit, err := a.Store.ListAudit(r.Context(), 50)
	if err != nil {
		http.Error(w, "无法读取审计日志", http.StatusInternalServerError)
		return
	}
	data := map[string]interface{}{"Audit": audit}
	a.render(w, "audit", data)
}
func (a *API) handleSignUI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sess := r.Context().Value(contextKey("session")).(*session)
	if !a.verifyCSRF(r, sess) {
		http.Error(w, "csrf invalid", http.StatusBadRequest)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求无效", http.StatusBadRequest)
		return
	}
	profile := r.FormValue("profile")
	csrPEM := r.FormValue("csr")
	csr, err := pki.ParseCSR([]byte(csrPEM))
	if err != nil {
		a.renderSnippet(w, fmt.Sprintf("<div class='text-red-300'>CSR 无效: %v</div>", err))
		return
	}
	prof := a.profileForRequest(profile)
	certDER, chain, err := a.Signer.SignCSR(csr, prof)
	if err != nil {
		a.renderSnippet(w, fmt.Sprintf("<div class='text-red-300'>签发失败: %v</div>", err))
		return
	}
	leaf, _ := x509.ParseCertificate(certDER)
	certPEM := string(pki.ChainToPEM([][]byte{certDER}))
	record := storage.CertificateRecord{
		Serial:    serialToString(leaf.SerialNumber),
		Subject:   leaf.Subject.String(),
		SAN:       pki.InspectSANs(csr),
		Profile:   nameOrDefault(profile, a.DefaultProfile),
		NotBefore: leaf.NotBefore,
		NotAfter:  leaf.NotAfter,
		PEM:       certPEM,
		CreatedAt: time.Now().UTC(),
		Status:    "issued",
	}
	if err := a.Store.InsertCertificate(r.Context(), record); err != nil {
		log.Printf("store certificate: %v", err)
	}
	a.audit(r, sess.Username, "sign_ui", record.Serial, record)
	chainPEM := string(pki.ChainToPEM(chain))
	snippet := fmt.Sprintf("<div class='text-emerald-300 space-y-2'><p>签发成功。序列号 %s</p><textarea class='w-full bg-slate-950 border border-slate-800 rounded-md p-2 text-xs' rows='8'>%s\n%s</textarea></div>", record.Serial, certPEM, chainPEM)
	a.renderSnippet(w, snippet)
}

func (a *API) handleRevokeUI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sess := r.Context().Value(contextKey("session")).(*session)
	if !a.verifyCSRF(r, sess) {
		http.Error(w, "csrf invalid", http.StatusBadRequest)
		return
	}
	serial := r.FormValue("serial")
	if serial == "" {
		http.Error(w, "serial required", http.StatusBadRequest)
		return
	}
	record, err := a.revokeCertificate(r.Context(), serial)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	a.audit(r, sess.Username, "revoke", serial, record)
	a.handleCertificates(w, r)
}
func (a *API) handleSign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sess := r.Context().Value(contextKey("session")).(*session)
	if !a.verifyCSRF(r, sess) {
		http.Error(w, "csrf invalid", http.StatusBadRequest)
		return
	}
	var req struct {
		CSRPEM  string `json:"csr_pem"`
		Profile string `json:"profile"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	csr, err := pki.ParseCSR([]byte(req.CSRPEM))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	profile := a.profileForRequest(req.Profile)
	certDER, chain, err := a.Signer.SignCSR(csr, profile)
	if err != nil {
		http.Error(w, "signing failed", http.StatusInternalServerError)
		return
	}
	leaf, _ := x509.ParseCertificate(certDER)
	certPEM := string(pki.ChainToPEM([][]byte{certDER}))
	record := storage.CertificateRecord{
		Serial:    serialToString(leaf.SerialNumber),
		Subject:   leaf.Subject.String(),
		SAN:       pki.InspectSANs(csr),
		Profile:   nameOrDefault(req.Profile, a.DefaultProfile),
		NotBefore: leaf.NotBefore,
		NotAfter:  leaf.NotAfter,
		PEM:       certPEM,
		CreatedAt: time.Now().UTC(),
		Status:    "issued",
	}
	_ = a.Store.InsertCertificate(r.Context(), record)
	a.audit(r, sess.Username, "sign_api", record.Serial, record)
	resp := map[string]string{
		"certificate_pem": certPEM,
		"chain_pem":       string(pki.ChainToPEM(chain)),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (a *API) handleRevokeAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sess := r.Context().Value(contextKey("session")).(*session)
	if !a.verifyCSRF(r, sess) {
		http.Error(w, "csrf invalid", http.StatusBadRequest)
		return
	}
	var req struct {
		Serial string `json:"serial"`
		Reason int    `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	record, err := a.revokeCertificate(r.Context(), req.Serial)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	a.audit(r, sess.Username, "revoke_api", req.Serial, record)
	w.WriteHeader(http.StatusNoContent)
}
func (a *API) revokeCertificate(ctx context.Context, serial string) (storage.CertificateRecord, error) {
	record, ok, err := a.Store.GetCertificate(ctx, strings.ToLower(serial))
	if err != nil {
		return storage.CertificateRecord{}, err
	}
	if !ok {
		return storage.CertificateRecord{}, fmt.Errorf("证书不存在")
	}
	now := time.Now().UTC()
	updated, err := a.Store.RevokeCertificate(ctx, record.Serial, 0, now)
	if err != nil {
		return storage.CertificateRecord{}, err
	}
	return updated, nil
}

func (a *API) handlePassword(w http.ResponseWriter, r *http.Request) {
	sess := r.Context().Value(contextKey("session")).(*session)
	switch r.Method {
	case http.MethodGet:
		data := map[string]interface{}{
			"CSRF": a.ensureSessionCSRF(sess),
		}
		a.render(w, "password", data)
	case http.MethodPost:
		if !a.verifyCSRF(r, sess) {
			http.Error(w, "csrf invalid", http.StatusBadRequest)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "请求无效", http.StatusBadRequest)
			return
		}
		current := r.FormValue("current_password")
		newPassword := r.FormValue("new_password")
		confirm := r.FormValue("confirm_password")
		if current == "" || newPassword == "" {
			http.Error(w, "密码不能为空", http.StatusBadRequest)
			return
		}
		if len(newPassword) < 12 {
			http.Error(w, "新密码至少需要 12 位", http.StatusBadRequest)
			return
		}
		if newPassword != confirm {
			http.Error(w, "两次输入的密码不一致", http.StatusBadRequest)
			return
		}
		user, ok, err := a.Store.GetUser(r.Context(), sess.Username)
		if err != nil || !ok {
			http.Error(w, "用户不存在", http.StatusInternalServerError)
			return
		}
		if !storage.VerifyPassword(user.PasswordHash, current) {
			http.Error(w, "当前密码不正确", http.StatusBadRequest)
			return
		}
		hash, err := storage.HashPassword(newPassword)
		if err != nil {
			http.Error(w, "无法更新密码", http.StatusInternalServerError)
			return
		}
		if err := a.Store.UpdatePasswordHash(r.Context(), sess.Username, hash); err != nil {
			http.Error(w, "无法更新密码", http.StatusInternalServerError)
			return
		}
		a.SetBootstrapPassword("")
		a.audit(r, sess.Username, "password_rotate", "", nil)
		http.Redirect(w, r, "/ui", http.StatusFound)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *API) handlePasskey(w http.ResponseWriter, r *http.Request) {
	sess := r.Context().Value(contextKey("session")).(*session)
	creds, err := a.Store.ListWebAuthnCredentials(r.Context(), sess.Username)
	if err != nil {
		http.Error(w, "无法读取凭据", http.StatusInternalServerError)
		return
	}
	data := map[string]interface{}{
		"Username":    sess.Username,
		"Credentials": creds,
		"CSRF":        a.ensureSessionCSRF(sess),
	}
	a.render(w, "passkey", data)
}
func (a *API) handleBeginRegister(w http.ResponseWriter, r *http.Request) {
	sess := r.Context().Value(contextKey("session")).(*session)
	challenge, err := generateChallenge()
	if err != nil {
		http.Error(w, "challenge error", http.StatusInternalServerError)
		return
	}
	sess.Values["register_challenge"] = challenge
	payload := map[string]interface{}{
		"mode": "register",
		"publicKey": map[string]interface{}{
			"challenge": base64.RawURLEncoding.EncodeToString(challenge),
			"rp":        map[string]string{"name": a.RP.Name, "id": a.RP.ID},
			"user": map[string]interface{}{
				"id":          base64.RawURLEncoding.EncodeToString([]byte(sess.Username)),
				"name":        sess.Username,
				"displayName": sess.Username,
			},
			"pubKeyCredParams":       []map[string]interface{}{{"type": "public-key", "alg": -7}},
			"timeout":                60000,
			"attestation":            "none",
			"authenticatorSelection": map[string]string{"userVerification": "preferred"},
		},
	}
	respondJSON(w, payload)
}

func (a *API) handleFinishRegister(w http.ResponseWriter, r *http.Request) {
	sess := r.Context().Value(contextKey("session")).(*session)
	rawChallenge, ok := sess.Values["register_challenge"]
	if !ok {
		http.Error(w, "challenge expired", http.StatusBadRequest)
		return
	}
	challengeBytes := rawChallenge
	delete(sess.Values, "register_challenge")
	var req struct {
		ID       string `json:"id"`
		RawID    string `json:"rawId"`
		Type     string `json:"type"`
		Response struct {
			AttestationObject string `json:"attestationObject"`
			ClientDataJSON    string `json:"clientDataJSON"`
		} `json:"response"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}
	attBytes, err := base64.RawURLEncoding.DecodeString(req.Response.AttestationObject)
	if err != nil {
		http.Error(w, "invalid attestation", http.StatusBadRequest)
		return
	}
	clientDataBytes, err := base64.RawURLEncoding.DecodeString(req.Response.ClientDataJSON)
	if err != nil {
		http.Error(w, "invalid client data", http.StatusBadRequest)
		return
	}
	att, err := parseAttestation(attBytes)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	auth, err := parseAuthData(att.AuthData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	expectedChallenge := parseChallenge(challengeBytes)
	if _, err := verifyClientData(clientDataBytes, expectedChallenge, "webauthn.create", a.RP.Origins); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rpHash := sha256.Sum256([]byte(a.RP.ID))
	if !hmac.Equal(auth.rpIDHash, rpHash[:]) {
		http.Error(w, "rp id mismatch", http.StatusBadRequest)
		return
	}
	cred := storage.WebAuthnCredential{
		ID:        encodeCredentialID(auth.credentialID),
		PublicKey: auth.publicKey,
		SignCount: auth.signCount,
	}
	if err := a.Store.AddWebAuthnCredential(r.Context(), sess.Username, cred); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	a.audit(r, sess.Username, "passkey_register", cred.ID, nil)
	w.WriteHeader(http.StatusNoContent)
}
func (a *API) handleBeginLogin(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(loginCSRFCookie)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	creds, err := a.Store.ListWebAuthnCredentials(r.Context(), req.Username)
	if err != nil || len(creds) == 0 {
		http.Error(w, "no credentials", http.StatusBadRequest)
		return
	}
	challenge, err := generateChallenge()
	if err != nil {
		http.Error(w, "challenge error", http.StatusInternalServerError)
		return
	}
	a.loginMu.Lock()
	a.loginChallenges[c.Value] = webAuthnChallenge{Mode: "login", Username: req.Username, Expires: time.Now().Add(5 * time.Minute), Value: challenge}
	a.loginMu.Unlock()
	allow := make([]map[string]interface{}, 0, len(creds))
	for _, cred := range creds {
		allow = append(allow, map[string]interface{}{"type": "public-key", "id": cred.ID})
	}
	payload := map[string]interface{}{
		"mode": "authenticate",
		"publicKey": map[string]interface{}{
			"challenge":        base64.RawURLEncoding.EncodeToString(challenge),
			"rpId":             a.RP.ID,
			"allowCredentials": allow,
			"timeout":          60000,
			"userVerification": "preferred",
		},
	}
	respondJSON(w, payload)
}

func (a *API) handleFinishLogin(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(loginCSRFCookie)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	a.loginMu.Lock()
	challenge, ok := a.loginChallenges[c.Value]
	if ok && challenge.Expires.Before(time.Now()) {
		ok = false
	}
	delete(a.loginChallenges, c.Value)
	a.loginMu.Unlock()
	if !ok {
		http.Error(w, "challenge expired", http.StatusBadRequest)
		return
	}
	var req struct {
		ID       string `json:"id"`
		RawID    string `json:"rawId"`
		Type     string `json:"type"`
		Response struct {
			AuthenticatorData string `json:"authenticatorData"`
			ClientDataJSON    string `json:"clientDataJSON"`
			Signature         string `json:"signature"`
		} `json:"response"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	clientDataBytes, err := base64.RawURLEncoding.DecodeString(req.Response.ClientDataJSON)
	if err != nil {
		http.Error(w, "invalid client data", http.StatusBadRequest)
		return
	}
	authDataBytes, err := base64.RawURLEncoding.DecodeString(req.Response.AuthenticatorData)
	if err != nil {
		http.Error(w, "invalid authenticator data", http.StatusBadRequest)
		return
	}
	signatureBytes, err := base64.RawURLEncoding.DecodeString(req.Response.Signature)
	if err != nil {
		http.Error(w, "invalid signature", http.StatusBadRequest)
		return
	}
	expectedChallenge := parseChallenge(challenge.Value)
	if _, err := verifyClientData(clientDataBytes, expectedChallenge, "webauthn.get", a.RP.Origins); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	flags, signCount, err := parseAssertionAuthData(authDataBytes)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if flags&flagUserPresent == 0 {
		http.Error(w, "user not present", http.StatusBadRequest)
		return
	}
	credential, ok, err := a.Store.GetWebAuthnCredential(r.Context(), challenge.Username, req.ID)
	if err != nil || !ok {
		http.Error(w, "credential not found", http.StatusBadRequest)
		return
	}
	pub, err := buildECDSAPublicKey(credential.PublicKey)
	if err != nil {
		http.Error(w, "invalid key", http.StatusBadRequest)
		return
	}
	clientHash := computeClientDataHash(clientDataBytes)
	if err := verifyAssertionSignature(pub, authDataBytes, clientHash, signatureBytes); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if signCount > credential.SignCount {
		credential.SignCount = signCount
		_ = a.Store.UpdateWebAuthnCredential(r.Context(), challenge.Username, credential)
	}
	token, sess := a.Sessions.Create(challenge.Username, a.SessionDuration)
	csrf := randomToken(16)
	sess.Values["csrf"] = []byte(csrf)
	a.setSessionCookie(w, token, sess.Expires)
	a.audit(r, challenge.Username, "login_passkey", "", nil)
	w.WriteHeader(http.StatusNoContent)
}
func (a *API) ensureSessionCSRF(sess *session) string {
	if token, ok := sess.Values["csrf"]; ok {
		return string(token)
	}
	token := randomToken(16)
	sess.Values["csrf"] = []byte(token)
	return token
}

func (a *API) verifyCSRF(r *http.Request, sess *session) bool {
	want := string(sess.Values["csrf"])
	if want == "" {
		return false
	}
	if header := r.Header.Get("X-CSRF-Token"); header != "" {
		return hmac.Equal([]byte(want), []byte(header))
	}
	if err := r.ParseForm(); err == nil {
		return hmac.Equal([]byte(want), []byte(r.FormValue("csrf")))
	}
	return false
}

func (a *API) profileNames() []string {
	names := make([]string, 0, len(a.Profiles))
	for name := range a.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (a *API) profileForRequest(name string) pki.Profile {
	resolved := nameOrDefault(name, a.DefaultProfile)
	if prof, ok := a.Profiles[resolved]; ok {
		return prof
	}
	return pki.Profile{}
}

func (a *API) sessionFromRequest(r *http.Request) (*session, string) {
	token := a.sessionToken(r)
	if token == "" {
		return nil, ""
	}
	sess, ok := a.Sessions.Get(token)
	if !ok {
		return nil, ""
	}
	return sess, token
}

func (a *API) sessionToken(r *http.Request) string {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return ""
	}
	return c.Value
}

func (a *API) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, token := a.sessionFromRequest(r)
		if sess == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		a.Sessions.Touch(token, a.SessionDuration)
		ctx := context.WithValue(r.Context(), contextKey("session"), sess)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func (a *API) render(w http.ResponseWriter, name string, data interface{}) {
	if err := a.Templates.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("render template %s: %v", name, err)
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

func (a *API) renderSnippet(w http.ResponseWriter, html string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	io.WriteString(w, html)
}

func (a *API) audit(r *http.Request, actor, action, target string, payload interface{}) {
	entry := storage.AuditEntry{Actor: actor, Action: action, Target: target, IP: r.RemoteAddr, Payload: payload}
	if err := a.Store.AppendAudit(r.Context(), entry); err != nil {
		log.Printf("audit append: %v", err)
	}
}

func (a *API) acmeDirectory(r *http.Request) string {
	if a.ACME == nil {
		return "未启用"
	}
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s%s/directory", scheme, r.Host, a.ACME.BasePath)
}
func (a *API) handleCRL(w http.ResponseWriter, r *http.Request) {
	revocations, err := a.Store.ListRevocations(r.Context())
	if err != nil {
		http.Error(w, "无法生成 CRL", http.StatusInternalServerError)
		return
	}
	var revoked []pkix.RevokedCertificate
	for _, rec := range revocations {
		serial, ok := new(big.Int).SetString(rec.Serial, 16)
		if !ok {
			continue
		}
		rc := pkix.RevokedCertificate{
			SerialNumber:   serial,
			RevocationTime: rec.RevokedAt,
		}
		if rec.Reason != 0 {
			reasonBytes, _ := asn1.Marshal(asn1.Enumerated(rec.Reason))
			rc.Extensions = append(rc.Extensions, pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 21}, Value: reasonBytes})
		}
		revoked = append(revoked, rc)
	}
	number, err := a.Store.NextCRLNumber(r.Context())
	if err != nil {
		http.Error(w, "无法分配 CRL 编号", http.StatusInternalServerError)
		return
	}
	now := time.Now().UTC()
	next := now.Add(24 * time.Hour)
	der, err := a.Signer.GenerateCRL(revoked, new(big.Int).SetUint64(number), now, next)
	if err != nil {
		http.Error(w, "生成 CRL 失败", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Write(der)
}

func (a *API) handleOCSP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	req, err := parseOCSPRequest(body)
	if err != nil {
		http.Error(w, "invalid ocsp request", http.StatusBadRequest)
		return
	}
	record, ok, err := a.Store.GetCertificate(r.Context(), strings.ToLower(req.Serial.String()))
	if err != nil || !ok {
		resp := buildOCSPResponse(a.Signer, req, nil)
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.Write(resp)
		return
	}
	status := &ocspStatus{Serial: req.Serial, Status: "good"}
	if record.Status == "revoked" && record.RevokedAt != nil {
		status.Status = "revoked"
		status.RevokedAt = *record.RevokedAt
		status.Reason = record.RevocationReason
	}
	resp := buildOCSPResponse(a.Signer, req, status)
	w.Header().Set("Content-Type", "application/ocsp-response")
	w.Write(resp)
}

func serialToString(s *big.Int) string {
	if s == nil {
		return ""
	}
	return strings.ToLower(s.Text(16))
}

func nameOrDefault(name, def string) string {
	if name != "" {
		return name
	}
	return def
}

// Shutdown gracefully closes the underlying store.
func (a *API) Shutdown(ctx context.Context) error {
	return a.Store.Close()
}

// SetBootstrapPassword records the initial password for UI display.
func (a *API) SetBootstrapPassword(password string) {
	a.bootstrapPassword = password
}
func respondJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

type ocspRequest struct {
	Serial         *big.Int
	IssuerNameHash []byte
	IssuerKeyHash  []byte
}

type ocspStatus struct {
	Serial    *big.Int
	Status    string
	RevokedAt time.Time
	Reason    int
}

func parseOCSPRequest(data []byte) (*ocspRequest, error) {
	var req struct {
		TBSRequest struct {
			Version     int `asn1:"explicit,tag:0,optional,default:0"`
			RequestList []struct {
				CertID struct {
					HashAlgorithm pkix.AlgorithmIdentifier
					NameHash      []byte
					KeyHash       []byte
					SerialNumber  *big.Int
				}
			}
		}
	}
	if _, err := asn1.Unmarshal(data, &req); err != nil {
		return nil, err
	}
	if len(req.TBSRequest.RequestList) == 0 {
		return nil, errors.New("empty ocsp request")
	}
	cert := req.TBSRequest.RequestList[0].CertID
	return &ocspRequest{
		Serial:         cert.SerialNumber,
		IssuerNameHash: cert.NameHash,
		IssuerKeyHash:  cert.KeyHash,
	}, nil
}

func buildOCSPResponse(signer *pki.Signer, req *ocspRequest, status *ocspStatus) []byte {
	issuer := signer.CACertificate()
	var responses []singleResponse
	certStatus := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0}
	thisUpdate := time.Now().UTC()
	nextUpdate := thisUpdate.Add(4 * time.Hour)
	if status != nil && status.Status == "revoked" {
		revoked := revokedInfo{RevocationTime: status.RevokedAt}
		if status.Reason != 0 {
			reason := asn1.Enumerated(status.Reason)
			revoked.RevocationReason = &reason
		}
		revokedBytes, _ := asn1.Marshal(revoked)
		certStatus = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: revokedBytes}
	}
	responses = append(responses, singleResponse{
		CertID:     buildCertID(issuer, req),
		CertStatus: certStatus,
		ThisUpdate: thisUpdate,
		NextUpdate: nextUpdate,
	})
	responder := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: issuer.RawSubject}
	tbs := responseData{
		Version:       0,
		ResponderName: responder,
		ProducedAt:    thisUpdate,
		Responses:     responses,
	}
	tbsDER, _ := asn1.Marshal(tbs)
	algOID, hashFunc := signatureInfo(signer.CAKey())
	digest := hashFunc.New()
	digest.Write(tbsDER)
	sigBytes, _ := signResponse(signer.CAKey(), hashFunc, digest.Sum(nil))
	basic := basicOCSPResponse{
		TBSResponseData:    tbs,
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: algOID, Parameters: asn1.RawValue{Tag: 5}},
		Signature:          asn1.BitString{Bytes: sigBytes, BitLength: len(sigBytes) * 8},
	}
	basicDER, _ := asn1.Marshal(basic)
	outer := ocspResponse{
		Status: asn1.Enumerated(0),
		ResponseBytes: responseBytes{
			ResponseType: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1},
			Response:     asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagOctetString, Bytes: basicDER},
		},
	}
	final, _ := asn1.Marshal(outer)
	return final
}

func buildCertID(issuer *x509.Certificate, req *ocspRequest) certID {
	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &spki)
	nameHash := sha1.Sum(issuer.RawSubject)
	keyHash := sha1.Sum(spki.SubjectPublicKey.Bytes)
	return certID{
		HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}},
		NameHash:      nameHash[:],
		KeyHash:       keyHash[:],
		SerialNumber:  req.Serial,
	}
}

func signatureInfo(key crypto.Signer) (asn1.ObjectIdentifier, crypto.Hash) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}, crypto.SHA256
	case *ecdsa.PrivateKey:
		switch k.Curve.Params().Name {
		case "P-256":
			return asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}, crypto.SHA256
		case "P-384":
			return asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}, crypto.SHA384
		}
	}
	return asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}, crypto.SHA256
}

func signResponse(key crypto.Signer, hash crypto.Hash, digest []byte) ([]byte, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return rsa.SignPKCS1v15(rand.Reader, k, hash, digest)
	case *ecdsa.PrivateKey:
		return ecdsa.SignASN1(rand.Reader, k, digest)
	default:
		return nil, fmt.Errorf("unsupported key type")
	}
}

// ASN.1 helpers for OCSP encoding
type ocspResponse struct {
	Status        asn1.Enumerated
	ResponseBytes responseBytes `asn1:"explicit,tag:0"`
}

type responseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     asn1.RawValue
}

type basicOCSPResponse struct {
	TBSResponseData    responseData
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
}

type responseData struct {
	Version       int           `asn1:"explicit,tag:0,optional"`
	ResponderName asn1.RawValue `asn1:"explicit,tag:1"`
	ProducedAt    time.Time     `asn1:"generalized"`
	Responses     []singleResponse
}

type singleResponse struct {
	CertID     certID
	CertStatus asn1.RawValue
	ThisUpdate time.Time `asn1:"generalized"`
	NextUpdate time.Time `asn1:"explicit,tag:0,optional,generalized"`
}

type certID struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	NameHash      []byte
	KeyHash       []byte
	SerialNumber  *big.Int
}

type revokedInfo struct {
	RevocationTime   time.Time        `asn1:"generalized"`
	RevocationReason *asn1.Enumerated `asn1:"explicit,tag:0,optional"`
}
