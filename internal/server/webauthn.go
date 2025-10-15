package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	"localpki/internal/storage"
)

type webAuthnChallenge struct {
	Mode     string
	Username string
	Expires  time.Time
	Value    []byte
}

type clientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
}

type attestationObject struct {
	Format   string
	AuthData []byte
}

type authData struct {
	rpIDHash     []byte
	flags        byte
	signCount    uint32
	credentialID []byte
	publicKey    storage.PublicKey
}

const (
	flagUserPresent  = 0x01
	flagUserVerified = 0x04
	flagAttestedData = 0x40
)

func generateChallenge() ([]byte, error) {
	buf := make([]byte, 32)
	if _, err := crand.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func verifyOrigin(origin string, allowed []string) bool {
	if origin == "" {
		return false
	}
	for _, allowedOrigin := range allowed {
		if origin == allowedOrigin {
			return true
		}
	}
	return false
}

func parseAttestation(attObj []byte) (attestationObject, error) {
	val, _, err := decodeCBOR(attObj)
	if err != nil {
		return attestationObject{}, err
	}
	m, ok := val.(map[string]interface{})
	if !ok {
		return attestationObject{}, errors.New("attestation object is not a map")
	}
	fmtVal, ok := m["fmt"].(string)
	if !ok {
		return attestationObject{}, errors.New("attestation fmt missing")
	}
	if fmtVal != "none" {
		return attestationObject{}, fmt.Errorf("unsupported attestation format %s", fmtVal)
	}
	auth, ok := m["authData"].([]byte)
	if !ok {
		return attestationObject{}, errors.New("authData missing")
	}
	return attestationObject{Format: fmtVal, AuthData: auth}, nil
}

func parseAuthData(data []byte) (authData, error) {
	if len(data) < 37 {
		return authData{}, errors.New("authenticator data too short")
	}
	ad := authData{}
	ad.rpIDHash = append([]byte(nil), data[:32]...)
	ad.flags = data[32]
	ad.signCount = binary.BigEndian.Uint32(data[33:37])
	offset := 37
	if ad.flags&flagAttestedData == 0 {
		return authData{}, errors.New("attestation data missing public key")
	}
	if len(data) < offset+16+2 {
		return authData{}, errors.New("attested credential data truncated")
	}
	offset += 16 // skip AAGUID
	credLen := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	if len(data) < offset+int(credLen) {
		return authData{}, errors.New("credential id truncated")
	}
	ad.credentialID = append([]byte(nil), data[offset:offset+int(credLen)]...)
	offset += int(credLen)
	val, consumed, err := decodeCBOR(data[offset:])
	if err != nil {
		return authData{}, err
	}
	offset += consumed
	pkMap, ok := val.(map[int]interface{})
	if !ok {
		return authData{}, errors.New("credential public key invalid")
	}
	pk, err := parseCOSEPublicKey(pkMap)
	if err != nil {
		return authData{}, err
	}
	ad.publicKey = pk
	if int(offset) != len(data) {
		// ignore extensions
	}
	return ad, nil
}

func parseCOSEPublicKey(m map[int]interface{}) (storage.PublicKey, error) {
	kty, _ := asInt(m[1])
	alg, _ := asInt(m[3])
	crv, _ := asInt(m[-1])
	xBytes, _ := m[-2].([]byte)
	yBytes, _ := m[-3].([]byte)
	if kty != 2 || alg != -7 {
		return storage.PublicKey{}, errors.New("unsupported key type")
	}
	if crv != 1 {
		return storage.PublicKey{}, errors.New("unsupported curve")
	}
	if len(xBytes) != 32 || len(yBytes) != 32 {
		return storage.PublicKey{}, errors.New("invalid key length")
	}
	return storage.PublicKey{
		Kty: "EC2",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(xBytes),
		Y:   base64.RawURLEncoding.EncodeToString(yBytes),
	}, nil
}

func asInt(v interface{}) (int, bool) {
	switch val := v.(type) {
	case int:
		return val, true
	case int64:
		return int(val), true
	case uint64:
		return int(val), true
	default:
		return 0, false
	}
}

type cborDecoder struct {
	data []byte
	pos  int
}

func decodeCBOR(data []byte) (interface{}, int, error) {
	dec := &cborDecoder{data: data}
	val, err := dec.decode()
	return val, dec.pos, err
}

func (d *cborDecoder) decode() (interface{}, error) {
	if d.pos >= len(d.data) {
		return nil, errors.New("unexpected eof")
	}
	b := d.data[d.pos]
	d.pos++
	major := b >> 5
	addInfo := b & 0x1f
	switch major {
	case 0:
		u, err := d.readUint(addInfo)
		if err != nil {
			return nil, err
		}
		return int(u), nil
	case 1:
		u, err := d.readUint(addInfo)
		if err != nil {
			return nil, err
		}
		return -1 - int(u), nil
	case 2:
		l, err := d.readUint(addInfo)
		if err != nil {
			return nil, err
		}
		if d.pos+int(l) > len(d.data) {
			return nil, errors.New("cbor bytes truncated")
		}
		val := d.data[d.pos : d.pos+int(l)]
		d.pos += int(l)
		return append([]byte(nil), val...), nil
	case 3:
		l, err := d.readUint(addInfo)
		if err != nil {
			return nil, err
		}
		if d.pos+int(l) > len(d.data) {
			return nil, errors.New("cbor string truncated")
		}
		val := string(d.data[d.pos : d.pos+int(l)])
		d.pos += int(l)
		return val, nil
	case 4:
		l, err := d.readUint(addInfo)
		if err != nil {
			return nil, err
		}
		arr := make([]interface{}, 0, l)
		for i := 0; i < int(l); i++ {
			v, err := d.decode()
			if err != nil {
				return nil, err
			}
			arr = append(arr, v)
		}
		return arr, nil
	case 5:
		l, err := d.readUint(addInfo)
		if err != nil {
			return nil, err
		}
		if l > 1<<20 {
			return nil, errors.New("cbor map too large")
		}
		if l == 0 {
			return map[string]interface{}{}, nil
		}
		m := make(map[string]interface{}, l)
		im := make(map[int]interface{}, l)
		for i := 0; i < int(l); i++ {
			key, err := d.decode()
			if err != nil {
				return nil, err
			}
			value, err := d.decode()
			if err != nil {
				return nil, err
			}
			switch k := key.(type) {
			case string:
				m[k] = value
			case int:
				im[k] = value
			default:
				// ignore unsupported key type
			}
		}
		if len(im) > 0 {
			return im, nil
		}
		return m, nil
	case 6:
		// tags - skip and decode next value
		_, err := d.readUint(addInfo)
		if err != nil {
			return nil, err
		}
		return d.decode()
	case 7:
		switch addInfo {
		case 20:
			return false, nil
		case 21:
			return true, nil
		case 22:
			return nil, nil
		default:
			return nil, errors.New("unsupported cbor simple type")
		}
	default:
		return nil, errors.New("unsupported cbor major type")
	}
}

func (d *cborDecoder) readUint(info byte) (uint64, error) {
	switch info {
	case 24:
		if d.pos >= len(d.data) {
			return 0, errors.New("cbor uint truncated")
		}
		val := d.data[d.pos]
		d.pos++
		return uint64(val), nil
	case 25:
		if d.pos+2 > len(d.data) {
			return 0, errors.New("cbor uint16 truncated")
		}
		val := binary.BigEndian.Uint16(d.data[d.pos : d.pos+2])
		d.pos += 2
		return uint64(val), nil
	case 26:
		if d.pos+4 > len(d.data) {
			return 0, errors.New("cbor uint32 truncated")
		}
		val := binary.BigEndian.Uint32(d.data[d.pos : d.pos+4])
		d.pos += 4
		return uint64(val), nil
	case 27:
		if d.pos+8 > len(d.data) {
			return 0, errors.New("cbor uint64 truncated")
		}
		val := binary.BigEndian.Uint64(d.data[d.pos : d.pos+8])
		d.pos += 8
		return val, nil
	default:
		if info < 24 {
			return uint64(info), nil
		}
		return 0, errors.New("unsupported additional info")
	}
}

func buildECDSAPublicKey(pk storage.PublicKey) (*ecdsa.PublicKey, error) {
	if pk.Crv != "P-256" {
		return nil, errors.New("unsupported curve")
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(pk.X)
	if err != nil {
		return nil, err
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(pk.Y)
	if err != nil {
		return nil, err
	}
	curve := elliptic.P256()
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("point not on curve")
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func verifyClientData(data []byte, expectedChallenge string, expectedType string, allowedOrigins []string) (*clientData, error) {
	var cd clientData
	if err := json.Unmarshal(data, &cd); err != nil {
		return nil, err
	}
	if cd.Type != expectedType {
		return nil, errors.New("unexpected client data type")
	}
	if cd.Challenge != expectedChallenge {
		return nil, errors.New("challenge mismatch")
	}
	if !verifyOrigin(cd.Origin, allowedOrigins) {
		return nil, errors.New("origin not allowed")
	}
	return &cd, nil
}

func computeClientDataHash(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func parseChallenge(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeCredentialID(id string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(id)
}

func encodeCredentialID(raw []byte) string {
	return base64.RawURLEncoding.EncodeToString(raw)
}

func isRPIDValid(rpID string, origin string) bool {
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	host := u.Hostname()
	return host == rpID || strings.HasSuffix(host, "."+rpID)
}

func verifyAssertionSignature(pub *ecdsa.PublicKey, authenticatorData, clientHash, signature []byte) error {
	payload := make([]byte, len(authenticatorData)+len(clientHash))
	copy(payload, authenticatorData)
	copy(payload[len(authenticatorData):], clientHash)
	if ecdsa.VerifyASN1(pub, payload, signature) {
		return nil
	}
	return errors.New("invalid signature")
}

func parseAssertionAuthData(data []byte) (byte, uint32, error) {
	if len(data) < 37 {
		return 0, 0, errors.New("authenticator data too short")
	}
	flags := data[32]
	signCount := binary.BigEndian.Uint32(data[33:37])
	return flags, signCount, nil
}
