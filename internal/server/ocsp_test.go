package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"localpki/internal/pki"
)

func newTestSigner(t *testing.T) *pki.Signer {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{1, 2, 3},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return pki.NewSigner(cert, priv, nil)
}

func TestParseOCSPRequest(t *testing.T) {
	serial := big.NewInt(42)
	reqStruct := struct {
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
	}{}
	reqStruct.TBSRequest.RequestList = []struct {
		CertID struct {
			HashAlgorithm pkix.AlgorithmIdentifier
			NameHash      []byte
			KeyHash       []byte
			SerialNumber  *big.Int
		}
	}{{}}
	reqStruct.TBSRequest.RequestList[0].CertID = struct {
		HashAlgorithm pkix.AlgorithmIdentifier
		NameHash      []byte
		KeyHash       []byte
		SerialNumber  *big.Int
	}{
		HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}},
		NameHash:      []byte{0x01},
		KeyHash:       []byte{0x02},
		SerialNumber:  serial,
	}
	encoded, err := asn1.Marshal(reqStruct)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	parsed, err := parseOCSPRequest(encoded)
	if err != nil {
		t.Fatalf("parseOCSPRequest: %v", err)
	}
	if parsed.Serial.Cmp(serial) != 0 {
		t.Fatalf("unexpected serial %v", parsed.Serial)
	}
	if len(parsed.IssuerNameHash) != 1 || parsed.IssuerNameHash[0] != 0x01 {
		t.Fatalf("unexpected name hash")
	}
}

func TestParseOCSPRequestEmpty(t *testing.T) {
	reqStruct := struct {
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
	}{}
	encoded, err := asn1.Marshal(reqStruct)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := parseOCSPRequest(encoded); err == nil {
		t.Fatalf("expected error for empty request")
	}
}

func TestBuildOCSPResponseStatuses(t *testing.T) {
	signer := newTestSigner(t)
	req := &ocspRequest{Serial: big.NewInt(7)}

	der := buildOCSPResponse(signer, req, nil)
	var outer ocspResponse
	if _, err := asn1.Unmarshal(der, &outer); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if int(outer.Status) != 0 {
		t.Fatalf("expected successful status, got %d", outer.Status)
	}
	var basic basicOCSPResponse
	if _, err := asn1.Unmarshal(outer.ResponseBytes.Response.Bytes, &basic); err != nil {
		t.Fatalf("unmarshal basic response: %v", err)
	}
	if len(basic.TBSResponseData.Responses) != 1 {
		t.Fatalf("expected single response")
	}
	good := basic.TBSResponseData.Responses[0]
	if good.CertStatus.Tag != 0 {
		t.Fatalf("expected good status tag, got %d", good.CertStatus.Tag)
	}
	if good.CertID.SerialNumber.Cmp(req.Serial) != 0 {
		t.Fatalf("serial mismatch")
	}

	revokedAt := time.Now().UTC().Truncate(time.Second)
	status := &ocspStatus{Serial: req.Serial, Status: "revoked", RevokedAt: revokedAt}
	der = buildOCSPResponse(signer, req, status)
	if _, err := asn1.Unmarshal(der, &outer); err != nil {
		t.Fatalf("unmarshal revoked response: %v", err)
	}
	if int(outer.Status) != 0 {
		t.Fatalf("expected success outer status, got %d", outer.Status)
	}
	if _, err := asn1.Unmarshal(outer.ResponseBytes.Response.Bytes, &basic); err != nil {
		t.Fatalf("unmarshal revoked basic: %v", err)
	}
	if len(basic.TBSResponseData.Responses) != 1 {
		t.Fatalf("expected single revoked response")
	}
	revoked := basic.TBSResponseData.Responses[0]
	if revoked.CertStatus.Tag != 1 {
		t.Fatalf("expected revoked tag, got %d", revoked.CertStatus.Tag)
	}
	var info revokedInfo
	if _, err := asn1.Unmarshal(revoked.CertStatus.Bytes, &info); err != nil {
		t.Fatalf("unmarshal revoked info: %v", err)
	}
	if !info.RevocationTime.Equal(revokedAt) {
		t.Fatalf("unexpected revokedAt %v", info.RevocationTime)
	}
}
