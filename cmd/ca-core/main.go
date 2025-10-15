package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"localpki/internal/acme"
	"localpki/internal/config"
	"localpki/internal/pki"
	"localpki/internal/server"
	"localpki/internal/storage"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to configuration file")
	generateTLS := flag.Bool("generate-ui-cert", false, "generate ephemeral TLS certificate for localhost")
	demoMode := flag.Bool("demo", false, "start with an auto-generated demo CA (no config file needed)")
	flag.Parse()

	var (
		cfg      *config.Config
		demoInfo *demoEnvironment
		err      error
	)
	if *demoMode {
		if *generateTLS {
			log.Println("--generate-ui-cert is ignored in demo mode; demo certificates are created automatically")
		}
		cfg, demoInfo, err = setupDemoEnvironment()
		if err != nil {
			log.Fatalf("setup demo: %v", err)
		}
		log.Printf("demo mode: temporary data stored in %s", demoInfo.baseDir)
		log.Printf("demo mode: trust the root certificate at %s", demoInfo.rootCertPath)
	} else {
		cfg, err = config.Load(*configPath)
		if err != nil {
			log.Fatalf("load config: %v", err)
		}
	}

	if *generateTLS {
		if err := ensureTLSCertificates(cfg); err != nil {
			log.Fatalf("setup tls: %v", err)
		}
	}

	intermediateCert, err := pki.LoadCertificate(cfg.Intermediate.CertPath)
	if err != nil {
		log.Fatalf("load intermediate cert: %v", err)
	}
	intermediateKey, err := pki.LoadPrivateKey(cfg.Intermediate.KeyPath, cfg.Intermediate.KeyPassword)
	if err != nil {
		log.Fatalf("load intermediate key: %v", err)
	}
	var chain [][]byte
	if cfg.Intermediate.ChainPath != "" {
		chain, err = loadPEMChain(cfg.Intermediate.ChainPath)
		if err != nil {
			log.Fatalf("load chain: %v", err)
		}
	} else {
		chain = append(chain, intermediateCert.Raw)
	}
	signer := pki.NewSigner(intermediateCert, intermediateKey, chain)

	store, err := storage.Open(cfg.Database.Path)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}

	templates, err := server.LoadTemplates()
	if err != nil {
		log.Fatalf("load templates: %v", err)
	}

	api := server.NewAPI()
	api.Signer = signer
	api.Profiles = toPKIProfiles(cfg)
	api.DefaultProfile = cfg.Intermediate.DefaultProfile
	api.Store = store
	api.Templates = templates
	api.SessionDuration = time.Duration(cfg.Security.SessionMinutes) * time.Minute
	api.RP = server.RelyingPartyConfig{
		ID:      cfg.Security.RPID,
		Name:    cfg.Security.RPName,
		Origins: cfg.Security.RPOrigins,
	}

	if _, created, password, err := store.EnsureAdminUser(context.Background(), server.GenerateBootstrapPassword); err == nil {
		if created {
			api.SetBootstrapPassword(password)
			log.Printf("bootstrap admin password: %s", password)
		}
	} else {
		log.Fatalf("ensure admin user: %v", err)
	}

	if cfg.ACME.Enabled {
		acmeSrv := &acme.Server{
			Signer:         signer,
			Profiles:       api.Profiles,
			DefaultProfile: cfg.ACME.DefaultProfile,
			Store:          store,
			BasePath:       cfg.ACME.BasePath,
			Nonces:         acme.NewNonceManager(time.Minute),
		}
		acmeSrv.Audit = func(ctx context.Context, entry storage.AuditEntry) error {
			return api.Store.AppendAudit(ctx, entry)
		}
		api.ACME = acmeSrv
	}

	mux := http.NewServeMux()
	api.Register(mux)

	srv := &http.Server{
		Addr:    cfg.BindAddress,
		Handler: securityHeaders(mux),
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	shutdownCtx, stop := signal.NotifyContext(context.Background(), shutdownSignals()...)
	defer stop()

	go func() {
		<-shutdownCtx.Done()
		log.Println("shutting down...")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("server shutdown: %v", err)
		}
		if err := api.Shutdown(ctx); err != nil {
			log.Printf("store shutdown: %v", err)
		}
	}()

	log.Printf("starting ca-core on https://%s", cfg.BindAddress)
	if err := srv.ListenAndServeTLS(cfg.TLS.CertPath, cfg.TLS.KeyPath); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}

func toPKIProfiles(cfg *config.Config) map[string]pki.Profile {
	profiles := make(map[string]pki.Profile)
	for name, p := range cfg.Profiles {
		profiles[name] = pki.Profile{
			ValidityDays: p.ValidityDays,
			KeyUsage:     p.KeyUsage,
			ExtKeyUsage:  p.ExtKeyUsage,
		}
	}
	return profiles
}

func ensureTLSCertificates(cfg *config.Config) error {
	if cfg.TLS.CertPath == "" || cfg.TLS.KeyPath == "" {
		return fmt.Errorf("tls cert_path and key_path must be set")
	}
	if _, err := os.Stat(cfg.TLS.CertPath); err == nil {
		if _, err := os.Stat(cfg.TLS.KeyPath); err == nil {
			return nil
		}
	}
	log.Printf("generating temporary UI certificate for localhost")
	cert, key, err := generateLocalhostCert()
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(cfg.TLS.CertPath, cert, 0600); err != nil {
		return err
	}
	if err := ioutil.WriteFile(cfg.TLS.KeyPath, key, 0600); err != nil {
		return err
	}
	return nil
}

func generateLocalhostCert() ([]byte, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      pkix.Name{CommonName: "LocalPKI UI"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return certPEM, keyPEM, nil
}

func randomSerial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return big.NewInt(time.Now().UnixNano())
	}
	if n.Sign() == 0 {
		n = big.NewInt(1)
	}
	return n
}

func loadPEMChain(path string) ([][]byte, error) {
	pemBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var chain [][]byte
	for {
		block, rest := pem.Decode(pemBytes)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			chain = append(chain, block.Bytes)
		}
		pemBytes = rest
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("no certificates in chain file")
	}
	return chain, nil
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}
