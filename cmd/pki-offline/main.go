package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	cmd := os.Args[1]
	switch cmd {
	case "init-root":
		initRoot(os.Args[2:])
	case "sign-ica":
		signIntermediate(os.Args[2:])
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "localpki-offline commands:\n")
	fmt.Fprintf(os.Stderr, "  init-root --subject \"CN=Local Root CA\" --cert root.crt --key root.key\n")
	fmt.Fprintf(os.Stderr, "  sign-ica --csr ica.csr --root-cert root.crt --root-key root.key --out ica.crt\n")
}

func initRoot(args []string) {
	fs := flag.NewFlagSet("init-root", flag.ExitOnError)
	subject := fs.String("subject", "CN=Local Root CA", "subject distinguished name")
	certPath := fs.String("cert", "root.crt", "output certificate path")
	keyPath := fs.String("key", "root.key", "output private key path")
	validYears := fs.Int("years", 12, "validity period in years")
	fs.Parse(args)

	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		exitErr(fmt.Errorf("generate key: %w", err))
	}
	subjectName := parseSubject(*subject)
	tpl := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               subjectName,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(*validYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	tpl.SubjectKeyId = subjectKeyID(&priv.PublicKey)
	certDER, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		exitErr(fmt.Errorf("create certificate: %w", err))
	}
	if err := writePEM(*certPath, "CERTIFICATE", certDER); err != nil {
		exitErr(err)
	}
	b, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		exitErr(fmt.Errorf("marshal key: %w", err))
	}
	if err := writePEM(*keyPath, "EC PRIVATE KEY", b); err != nil {
		exitErr(err)
	}
	fmt.Printf("root CA written to %s and %s\n", *certPath, *keyPath)
}

func signIntermediate(args []string) {
	fs := flag.NewFlagSet("sign-ica", flag.ExitOnError)
	csrPath := fs.String("csr", "ica.csr", "intermediate CSR path")
	rootCertPath := fs.String("root-cert", "root.crt", "root certificate path")
	rootKeyPath := fs.String("root-key", "root.key", "root private key path")
	outPath := fs.String("out", "ica.crt", "output certificate path")
	years := fs.Int("years", 5, "validity period in years")
	fs.Parse(args)

	csrBytes, err := ioutil.ReadFile(*csrPath)
	if err != nil {
		exitErr(fmt.Errorf("read csr: %w", err))
	}
	csrBlock, _ := pem.Decode(csrBytes)
	if csrBlock == nil {
		exitErr(fmt.Errorf("invalid csr pem"))
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		exitErr(fmt.Errorf("parse csr: %w", err))
	}
	rootCert, rootKey := mustLoadCertAndKey(*rootCertPath, *rootKeyPath)
	tpl := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               csr.Subject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(*years, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}
	tpl.SubjectKeyId = subjectKeyID(csr.PublicKey)
	tpl.AuthorityKeyId = rootCert.SubjectKeyId
	certDER, err := x509.CreateCertificate(rand.Reader, tpl, rootCert, csr.PublicKey, rootKey)
	if err != nil {
		exitErr(fmt.Errorf("sign certificate: %w", err))
	}
	if err := writePEM(*outPath, "CERTIFICATE", certDER); err != nil {
		exitErr(err)
	}
	fmt.Printf("intermediate certificate written to %s\n", *outPath)
}

func randomSerial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		exitErr(fmt.Errorf("serial: %w", err))
	}
	if n.Sign() == 0 {
		n = big.NewInt(1)
	}
	return n
}

func subjectKeyID(pub interface{}) []byte {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil
	}
	sum := sha1.Sum(der)
	return sum[:]
}

func mustLoadCertAndKey(certPath, keyPath string) (*x509.Certificate, *ecdsa.PrivateKey) {
	certPEM, err := ioutil.ReadFile(certPath)
	if err != nil {
		exitErr(fmt.Errorf("read cert: %w", err))
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		exitErr(fmt.Errorf("invalid certificate pem"))
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		exitErr(fmt.Errorf("parse certificate: %w", err))
	}
	keyPEM, err := ioutil.ReadFile(keyPath)
	if err != nil {
		exitErr(fmt.Errorf("read key: %w", err))
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		exitErr(fmt.Errorf("invalid key pem"))
	}
	priv, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		exitErr(fmt.Errorf("parse key: %w", err))
	}
	return cert, priv
}

func parseSubject(subject string) pkix.Name {
	name := pkix.Name{}
	name.CommonName = subject
	return name
}

func writePEM(path, typ string, der []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: typ, Bytes: der}); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func exitErr(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
