package server

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log"
	"math/big"
	"net/http"
	"time"

	"localpki/internal/pki"
	"localpki/internal/storage"
)

// API bundles dependencies required to serve HTTP requests.
type API struct {
	Signer         *pki.Signer
	Profiles       map[string]pki.Profile
	DefaultProfile string
	Store          *storage.Store
}

// Register attaches handlers to the provided mux.
func (a *API) Register(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/health", a.handleHealth)
	mux.HandleFunc("/api/v1/certificates/sign", a.handleSign)
}

func (a *API) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (a *API) handleSign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req signRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	csr, err := pki.ParseCSR([]byte(req.CSRPEM))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	profile := a.profilesForRequest(req.Profile)
	certDER, chain, err := a.Signer.SignCSR(csr, profile)
	if err != nil {
		log.Printf("sign csr failed: %v", err)
		http.Error(w, "signing failed", http.StatusInternalServerError)
		return
	}
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		log.Printf("parse signed cert: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	certPEM := string(pki.ChainToPEM([][]byte{certDER}))
	chainPEM := string(pki.ChainToPEM(chain))
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
	if err := a.Store.InsertCertificate(r.Context(), record); err != nil {
		log.Printf("store certificate: %v", err)
	}
	resp := signResponse{
		CertificatePEM: certPEM,
		ChainPEM:       chainPEM,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (a *API) profilesForRequest(name string) pki.Profile {
	resolved := nameOrDefault(name, a.DefaultProfile)
	if prof, ok := a.Profiles[resolved]; ok {
		return prof
	}
	return pki.Profile{}
}

func nameOrDefault(name, def string) string {
	if name != "" {
		return name
	}
	return def
}

type signRequest struct {
	CSRPEM  string `json:"csr_pem"`
	Profile string `json:"profile"`
}

type signResponse struct {
	CertificatePEM string `json:"certificate_pem"`
	ChainPEM       string `json:"chain_pem"`
}

// Shutdown gracefully closes the underlying store.
func (a *API) Shutdown(ctx context.Context) error {
	return a.Store.Close()
}

func serialToString(s *big.Int) string {
	if s == nil {
		return ""
	}
	return s.Text(16)
}

// EncodePEM is exported for testing to ensure deterministic PEM encoding.
func EncodePEM(certDER []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
}
