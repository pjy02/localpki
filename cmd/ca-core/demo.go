package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"localpki/internal/config"
)

type demoEnvironment struct {
	baseDir      string
	rootCertPath string
	chainPath    string
}

func setupDemoEnvironment() (*config.Config, *demoEnvironment, error) {
	baseDir, err := os.MkdirTemp("", "localpki-demo-")
	if err != nil {
		return nil, nil, fmt.Errorf("create temp dir: %w", err)
	}
	secretsDir := filepath.Join(baseDir, "secrets")
	stateDir := filepath.Join(baseDir, "state")
	if err := os.MkdirAll(secretsDir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("create secrets dir: %w", err)
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("create state dir: %w", err)
	}

	rootKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate root key: %w", err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject: pkix.Name{
			CommonName:   "LocalPKI Demo Root",
			Organization: []string{"LocalPKI"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	if ski, err := subjectKeyID(&rootKey.PublicKey); err == nil {
		rootTemplate.SubjectKeyId = ski
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create root certificate: %w", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse root certificate: %w", err)
	}

	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate intermediate key: %w", err)
	}
	intermediateTemplate := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject: pkix.Name{
			CommonName:   "LocalPKI Demo Intermediate",
			Organization: []string{"LocalPKI"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(3, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	if ski, err := subjectKeyID(&intermediateKey.PublicKey); err == nil {
		intermediateTemplate.SubjectKeyId = ski
	}
	intermediateTemplate.AuthorityKeyId = rootCert.SubjectKeyId

	intermediateDER, err := x509.CreateCertificate(rand.Reader, intermediateTemplate, rootCert, &intermediateKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create intermediate certificate: %w", err)
	}

	rootPath := filepath.Join(secretsDir, "demo-root-ca.pem")
	if err := os.WriteFile(rootPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), 0o600); err != nil {
		return nil, nil, fmt.Errorf("write root cert: %w", err)
	}

	intermediateCertPath := filepath.Join(secretsDir, "demo-intermediate-ca.pem")
	if err := os.WriteFile(intermediateCertPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intermediateDER}), 0o600); err != nil {
		return nil, nil, fmt.Errorf("write intermediate cert: %w", err)
	}

	intermediateKeyBytes, err := x509.MarshalECPrivateKey(intermediateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal intermediate key: %w", err)
	}
	intermediateKeyPath := filepath.Join(secretsDir, "demo-intermediate-key.pem")
	if err := os.WriteFile(intermediateKeyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: intermediateKeyBytes}), 0o600); err != nil {
		return nil, nil, fmt.Errorf("write intermediate key: %w", err)
	}

	chainPath := filepath.Join(secretsDir, "demo-chain.pem")
	chainPEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intermediateDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})...)
	if err := os.WriteFile(chainPath, chainPEM, 0o600); err != nil {
		return nil, nil, fmt.Errorf("write chain: %w", err)
	}

	uiCert, uiKey, err := generateLocalhostCert()
	if err != nil {
		return nil, nil, fmt.Errorf("generate ui cert: %w", err)
	}
	uiCertPath := filepath.Join(secretsDir, "demo-ui-cert.pem")
	uiKeyPath := filepath.Join(secretsDir, "demo-ui-key.pem")
	if err := os.WriteFile(uiCertPath, uiCert, 0o600); err != nil {
		return nil, nil, fmt.Errorf("write ui cert: %w", err)
	}
	if err := os.WriteFile(uiKeyPath, uiKey, 0o600); err != nil {
		return nil, nil, fmt.Errorf("write ui key: %w", err)
	}

	cfg := &config.Config{
		BindAddress: "127.0.0.1:8443",
		TLS: config.TLSConfig{
			CertPath: uiCertPath,
			KeyPath:  uiKeyPath,
		},
		Database: config.Database{
			Path: filepath.Join(stateDir, "store.json"),
		},
		Intermediate: config.Intermediate{
			CertPath:       intermediateCertPath,
			KeyPath:        intermediateKeyPath,
			ChainPath:      chainPath,
			DefaultProfile: "server-tls",
		},
		Profiles: map[string]config.Profile{
			"server-tls": {
				Name:         "server-tls",
				ValidityDays: 90,
				KeyUsage:     []string{"digitalSignature"},
				ExtKeyUsage:  []string{"serverAuth"},
			},
			"client-mtls": {
				Name:            "client-mtls",
				ValidityDays:    180,
				KeyUsage:        []string{"digitalSignature"},
				ExtKeyUsage:     []string{"clientAuth"},
				AllowClientAuth: true,
			},
		},
		Security: config.Security{
			RPName:         "LocalPKI Demo",
			RPID:           "localhost",
			RPOrigins:      []string{"https://127.0.0.1:8443", "https://localhost:8443"},
			SessionMinutes: 30,
		},
		ACME: config.ACMEConfig{},
	}

	info := &demoEnvironment{
		baseDir:      baseDir,
		rootCertPath: rootPath,
		chainPath:    chainPath,
	}

	return cfg, info, nil
}

func subjectKeyID(pub interface{}) ([]byte, error) {
	pkixBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	sum := sha1.Sum(pkixBytes)
	return sum[:], nil
}
