package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"
)

// LoadCertificate loads a PEM encoded certificate from disk.
func LoadCertificate(path string) (*x509.Certificate, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read cert: %w", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("invalid certificate pem")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return cert, nil
}

// LoadPrivateKey loads a PEM encoded private key, supporting EC, RSA and Ed25519 keys in PKCS#1/SEC1/PKCS#8 formats.
// If the PEM block is encrypted a password must be supplied.
func LoadPrivateKey(path, password string) (crypto.Signer, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("invalid key pem")
	}
	der := block.Bytes
	if x509.IsEncryptedPEMBlock(block) {
		if password == "" {
			return nil, errors.New("key is encrypted but no password provided")
		}
		der, err = x509.DecryptPEMBlock(block, []byte(password))
		if err != nil {
			return nil, fmt.Errorf("decrypt key: %w", err)
		}
	}
	return parsePrivateKey(block.Type, der)
}

func parsePrivateKey(blockType string, der []byte) (crypto.Signer, error) {
	switch blockType {
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(der)
		if err != nil {
			return nil, fmt.Errorf("parse ec private key: %w", err)
		}
		return key, nil
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(der)
		if err != nil {
			return nil, fmt.Errorf("parse rsa private key: %w", err)
		}
		return key, nil
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return nil, fmt.Errorf("parse pkcs8 private key: %w", err)
		}
		switch k := key.(type) {
		case *ecdsa.PrivateKey:
			return k, nil
		case *rsa.PrivateKey:
			return k, nil
		case ed25519.PrivateKey:
			return k, nil
		default:
			return nil, fmt.Errorf("unsupported pkcs8 key type %T", key)
		}
	default:
		// Some tools emit encrypted blocks with the generic type even for EC/RSA keys.
		// Try PKCS#8 as a sensible default fallback.
		key, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return nil, fmt.Errorf("unsupported key type %q: %w", blockType, err)
		}
		switch k := key.(type) {
		case *ecdsa.PrivateKey:
			return k, nil
		case *rsa.PrivateKey:
			return k, nil
		case ed25519.PrivateKey:
			return k, nil
		default:
			return nil, fmt.Errorf("unsupported key type %T", key)
		}
	}
}

// Signer issues certificates using an intermediate CA.
type Signer struct {
	caCert *x509.Certificate
	caKey  crypto.Signer
	chain  [][]byte
}

// NewSigner creates a signer using the intermediate certificate, private key, and optional chain.
func NewSigner(caCert *x509.Certificate, caKey crypto.Signer, chain [][]byte) *Signer {
	return &Signer{caCert: caCert, caKey: caKey, chain: chain}
}

// SignCSR validates and signs a CSR according to the supplied profile.
func (s *Signer) SignCSR(csr *x509.CertificateRequest, profile Profile) ([]byte, [][]byte, error) {
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("csr signature invalid: %w", err)
	}
	if len(csr.DNSNames)+len(csr.IPAddresses) == 0 {
		return nil, nil, errors.New("CSR must include at least one DNS or IP SAN entry")
	}
	serial, err := randomSerialNumber()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC()
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
		EmailAddresses:        csr.EmailAddresses,
		URIs:                  csr.URIs,
		PublicKeyAlgorithm:    csr.PublicKeyAlgorithm,
		PublicKey:             csr.PublicKey,
		SignatureAlgorithm:    csr.SignatureAlgorithm,
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(profile.Validity()),
		BasicConstraintsValid: true,
		ExtKeyUsage:           profile.ExtKeyUsageIDs(),
		KeyUsage:              profile.KeyUsageBits(),
		SubjectKeyId:          generateSubjectKeyID(csr.RawSubjectPublicKeyInfo),
		AuthorityKeyId:        s.caCert.SubjectKeyId,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tpl, s.caCert, csr.PublicKey, s.caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("sign certificate: %w", err)
	}
	chain := append([][]byte{certDER}, s.chain...)
	return certDER, chain, nil
}

func randomSerialNumber() (*big.Int, error) {
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, fmt.Errorf("serial: %w", err)
	}
	serial.Abs(serial)
	if serial.Sign() == 0 {
		serial = serial.Add(serial, big.NewInt(1))
	}
	return serial, nil
}

func generateSubjectKeyID(raw []byte) []byte {
	h := sha1.Sum(raw)
	return h[:]
}

// Profile describes signing behaviour for certificates.
type Profile struct {
	ValidityDays int
	KeyUsage     []string
	ExtKeyUsage  []string
}

// Validity returns the duration for which certificates should be issued.
func (p Profile) Validity() time.Duration {
	days := p.ValidityDays
	if days <= 0 {
		days = 90
	}
	return time.Duration(days) * 24 * time.Hour
}

// KeyUsageBits converts the textual key usage list into bit flags.
func (p Profile) KeyUsageBits() x509.KeyUsage {
	var ku x509.KeyUsage
	for _, v := range p.KeyUsage {
		switch v {
		case "digitalSignature":
			ku |= x509.KeyUsageDigitalSignature
		case "keyEncipherment":
			ku |= x509.KeyUsageKeyEncipherment
		case "keyAgreement":
			ku |= x509.KeyUsageKeyAgreement
		case "dataEncipherment":
			ku |= x509.KeyUsageDataEncipherment
		case "keyCertSign":
			ku |= x509.KeyUsageCertSign
		case "cRLSign":
			ku |= x509.KeyUsageCRLSign
		case "contentCommitment":
			ku |= x509.KeyUsageContentCommitment
		}
	}
	if ku == 0 {
		ku = x509.KeyUsageDigitalSignature
	}
	return ku
}

// ExtKeyUsageIDs returns the extended key usage OIDs for a profile.
func (p Profile) ExtKeyUsageIDs() []x509.ExtKeyUsage {
	var eku []x509.ExtKeyUsage
	for _, v := range p.ExtKeyUsage {
		switch v {
		case "serverAuth":
			eku = append(eku, x509.ExtKeyUsageServerAuth)
		case "clientAuth":
			eku = append(eku, x509.ExtKeyUsageClientAuth)
		case "codeSigning":
			eku = append(eku, x509.ExtKeyUsageCodeSigning)
		case "emailProtection":
			eku = append(eku, x509.ExtKeyUsageEmailProtection)
		}
	}
	if len(eku) == 0 {
		eku = append(eku, x509.ExtKeyUsageServerAuth)
	}
	return eku
}

// ParseCSR parses a PEM encoded certificate signing request.
func ParseCSR(pemBytes []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("invalid csr pem")
	}
	if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("unexpected PEM block type: %s", block.Type)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse csr: %w", err)
	}
	return csr, nil
}

// ChainToPEM encodes a DER certificate chain into PEM blocks.
func ChainToPEM(chain [][]byte) []byte {
	var out []byte
	for _, der := range chain {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return out
}

// InspectSANs renders a human readable SAN summary.
func InspectSANs(csr *x509.CertificateRequest) string {
	var parts []string
	for _, dns := range csr.DNSNames {
		parts = append(parts, "DNS:"+dns)
	}
	for _, ip := range csr.IPAddresses {
		parts = append(parts, "IP:"+ip.String())
	}
	for _, uri := range csr.URIs {
		parts = append(parts, "URI:"+uri.String())
	}
	for _, email := range csr.EmailAddresses {
		parts = append(parts, "EMAIL:"+email)
	}
	return strings.Join(parts, ", ")
}
