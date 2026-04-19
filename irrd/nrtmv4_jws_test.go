package irrd

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
)

func makeTestEdDSAJWS(t *testing.T, payload []byte, privKey ed25519.PrivateKey) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA"}`))
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := []byte(header + "." + payloadB64)
	sig := ed25519.Sign(privKey, signingInput)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return header + "." + payloadB64 + "." + sigB64
}

func makeTestES256JWS(t *testing.T, payload []byte, privKey *ecdsa.PrivateKey) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`))
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := []byte(header + "." + payloadB64)

	hash := sha256.Sum256(signingInput)
	r, s, err := ecdsa.Sign(rand.Reader, privKey, hash[:])
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	// JWS ES256 signature is R||S, each padded to 32 bytes
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	sig := make([]byte, 64)
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)

	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return header + "." + payloadB64 + "." + sigB64
}

func TestVerifyNotificationFile_EdDSA_Valid(t *testing.T) {
	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey)

	nf := NotificationFile{
		NRTMVersion: 4,
		Type:        "notification",
		Source:      "TEST",
		SessionID:   "test-session",
		Version:     100,
	}
	payload, _ := json.Marshal(nf)
	jws := makeTestEdDSAJWS(t, payload, privKey)

	result, err := VerifyNotificationFile(jws, pubKeyB64)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed NotificationFile
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if parsed.Source != "TEST" {
		t.Errorf("got source %q, want TEST", parsed.Source)
	}
	if parsed.Version != 100 {
		t.Errorf("got version %d, want 100", parsed.Version)
	}
}

func TestVerifyNotificationFile_EdDSA_Tampered(t *testing.T) {
	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey)

	payload := []byte(`{"nrtm_version":4}`)
	jws := makeTestEdDSAJWS(t, payload, privKey)

	tampered := jws[:len(jws)-2] + "XX"

	_, err := VerifyNotificationFile(tampered, pubKeyB64)
	if err == nil {
		t.Fatal("expected error for tampered signature")
	}
	if _, ok := err.(*SignatureError); !ok {
		t.Fatalf("expected SignatureError, got %T: %v", err, err)
	}
}

func TestVerifyNotificationFile_ES256_Valid(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	// Encode public key as raw X||Y (64 bytes)
	xBytes := privKey.PublicKey.X.Bytes()
	yBytes := privKey.PublicKey.Y.Bytes()
	rawPub := make([]byte, 64)
	copy(rawPub[32-len(xBytes):32], xBytes)
	copy(rawPub[64-len(yBytes):64], yBytes)
	pubKeyB64 := base64.StdEncoding.EncodeToString(rawPub)

	payload := []byte(`{"source":"ES256TEST","nrtm_version":4}`)
	jws := makeTestES256JWS(t, payload, privKey)

	result, err := VerifyNotificationFile(jws, pubKeyB64)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed["source"] != "ES256TEST" {
		t.Errorf("got source %q, want ES256TEST", parsed["source"])
	}
}

func TestVerifyNotificationFile_ES256_Tampered(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	xBytes := privKey.PublicKey.X.Bytes()
	yBytes := privKey.PublicKey.Y.Bytes()
	rawPub := make([]byte, 64)
	copy(rawPub[32-len(xBytes):32], xBytes)
	copy(rawPub[64-len(yBytes):64], yBytes)
	pubKeyB64 := base64.StdEncoding.EncodeToString(rawPub)

	payload := []byte(`{"nrtm_version":4}`)
	jws := makeTestES256JWS(t, payload, privKey)

	tampered := jws[:len(jws)-2] + "XX"
	_, err := VerifyNotificationFile(tampered, pubKeyB64)
	if err == nil {
		t.Fatal("expected error for tampered ES256 signature")
	}
}

func TestVerifyNotificationFile_ES256_UncompressedKey(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Encode as uncompressed point (0x04 || X || Y) = 65 bytes
	rawPub := make([]byte, 65)
	rawPub[0] = 0x04
	xBytes := privKey.PublicKey.X.Bytes()
	yBytes := privKey.PublicKey.Y.Bytes()
	copy(rawPub[1+32-len(xBytes):33], xBytes)
	copy(rawPub[33+32-len(yBytes):65], yBytes)
	pubKeyB64 := base64.StdEncoding.EncodeToString(rawPub)

	payload := []byte(`{"source":"UNCOMPRESSED"}`)
	jws := makeTestES256JWS(t, payload, privKey)

	result, err := VerifyNotificationFile(jws, pubKeyB64)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed map[string]interface{}
	json.Unmarshal(result, &parsed)
	if parsed["source"] != "UNCOMPRESSED" {
		t.Errorf("got source %q, want UNCOMPRESSED", parsed["source"])
	}
}

func TestVerifyNotificationFile_EmptyKeySkipsVerification(t *testing.T) {
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)

	payload := []byte(`{"source":"NOKEY"}`)
	jws := makeTestEdDSAJWS(t, payload, privKey)

	result, err := VerifyNotificationFile(jws, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed map[string]string
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed["source"] != "NOKEY" {
		t.Errorf("got source %q, want NOKEY", parsed["source"])
	}
}

func TestVerifyNotificationFile_InvalidFormat(t *testing.T) {
	_, err := VerifyNotificationFile("only.two", "")
	if err == nil {
		t.Fatal("expected error for invalid format")
	}
}

func TestVerifyNotificationFile_UnsupportedAlgorithm(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(`{}`))
	sigB64 := base64.RawURLEncoding.EncodeToString([]byte("fakesig"))
	jws := header + "." + payloadB64 + "." + sigB64

	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey)

	_, err := VerifyNotificationFile(jws, pubKeyB64)
	if err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
}

func TestParseNotificationFileJSON(t *testing.T) {
	data := []byte(`{
		"nrtm_version": 4,
		"type": "notification",
		"source": "RIPE",
		"session_id": "abc-123",
		"version": 42,
		"timestamp": "2024-01-01T00:00:00Z",
		"snapshot": {"version": 40, "url": "https://example.com/snap.json", "hash": "abc123"},
		"deltas": [
			{"version": 41, "url": "https://example.com/d41.json", "hash": "def456"},
			{"version": 42, "url": "https://example.com/d42.json", "hash": "ghi789"}
		]
	}`)

	nf, err := ParseNotificationFileJSON(data, "RIPE")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if nf.Source != "RIPE" {
		t.Errorf("source = %q, want RIPE", nf.Source)
	}
	if nf.SessionID != "abc-123" {
		t.Errorf("session_id = %q, want abc-123", nf.SessionID)
	}
	if nf.Version != 42 {
		t.Errorf("version = %d, want 42", nf.Version)
	}
	if len(nf.Deltas) != 2 {
		t.Errorf("got %d deltas, want 2", len(nf.Deltas))
	}
	if nf.Snapshot.Version != 40 {
		t.Errorf("snapshot version = %d, want 40", nf.Snapshot.Version)
	}
}

func TestDecodeEd25519PublicKey(t *testing.T) {
	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
	b64 := base64.StdEncoding.EncodeToString(pubKey)

	decoded, err := decodeEd25519PublicKey(b64)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !pubKey.Equal(decoded) {
		t.Error("decoded key does not match original")
	}
}

func TestDecodeEd25519PublicKey_InvalidSize(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString([]byte("tooshort"))
	_, err := decodeEd25519PublicKey(b64)
	if err == nil {
		t.Fatal("expected error for invalid key size")
	}
}

func TestDecodeES256PublicKey_RawXY(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rawPub := make([]byte, 64)
	xBytes := privKey.PublicKey.X.Bytes()
	yBytes := privKey.PublicKey.Y.Bytes()
	copy(rawPub[32-len(xBytes):32], xBytes)
	copy(rawPub[64-len(yBytes):64], yBytes)

	decoded, err := decodeES256PublicKey(base64.StdEncoding.EncodeToString(rawPub))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decoded.X.Cmp(privKey.PublicKey.X) != 0 || decoded.Y.Cmp(privKey.PublicKey.Y) != 0 {
		t.Error("decoded key does not match")
	}
}

func TestVerifyNotificationFile_InvalidBase64Header(t *testing.T) {
	_, err := VerifyNotificationFile("!!!.payload.sig", "")
	if err == nil {
		t.Fatal("expected error for invalid base64 header")
	}
}

func TestVerifyNotificationFile_InvalidJSONHeader(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{notjson`))
	_, err := VerifyNotificationFile(header+".payload.sig", "")
	if err == nil {
		t.Fatal("expected error for invalid JSON header")
	}
}

func TestVerifyNotificationFile_InvalidBase64Payload(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA"}`))
	_, err := VerifyNotificationFile(header+".!!!.sig", "")
	if err == nil {
		t.Fatal("expected error for invalid base64 payload")
	}
}

func TestVerifyNotificationFile_InvalidBase64Sig(t *testing.T) {
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey)

	jws := makeTestEdDSAJWS(t, []byte(`{}`), privKey)
	parts := splitJWS(jws)
	_, err := VerifyNotificationFile(parts[0]+"."+parts[1]+".!!!", pubKeyB64)
	if err == nil {
		t.Fatal("expected error for invalid base64 signature")
	}
}

func TestVerifyEdDSA_BadPublicKey(t *testing.T) {
	err := verifyEdDSA([]byte("input"), []byte("sig"), "not-valid-base64!!!")
	if err == nil {
		t.Fatal("expected error for bad public key")
	}
}

func TestVerifyES256_WrongLengthSig(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	xBytes := privKey.PublicKey.X.Bytes()
	yBytes := privKey.PublicKey.Y.Bytes()
	rawPub := make([]byte, 64)
	copy(rawPub[32-len(xBytes):32], xBytes)
	copy(rawPub[64-len(yBytes):64], yBytes)
	pubKeyB64 := base64.StdEncoding.EncodeToString(rawPub)

	err := verifyES256([]byte("input"), []byte("tooshort"), pubKeyB64)
	if err == nil {
		t.Fatal("expected error for wrong-length signature")
	}
}

func TestVerifyES256_BadPublicKey(t *testing.T) {
	err := verifyES256([]byte("input"), make([]byte, 64), "not-valid-base64!!!")
	if err == nil {
		t.Fatal("expected error for bad public key")
	}
}

func TestDecodeEd25519PublicKey_InvalidBase64(t *testing.T) {
	_, err := decodeEd25519PublicKey("not-valid-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestDecodeES256PublicKey_InvalidBase64(t *testing.T) {
	_, err := decodeES256PublicKey("not-valid-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestDecodeES256PublicKey_BadPrefix65(t *testing.T) {
	bad := make([]byte, 65)
	bad[0] = 0x03 // not 0x04
	_, err := decodeES256PublicKey(base64.StdEncoding.EncodeToString(bad))
	if err == nil {
		t.Fatal("expected error for bad 65-byte prefix")
	}
}

func TestDecodeES256PublicKey_DER(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	derBytes, _ := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	b64 := base64.StdEncoding.EncodeToString(derBytes)

	decoded, err := decodeES256PublicKey(b64)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decoded.X.Cmp(privKey.PublicKey.X) != 0 || decoded.Y.Cmp(privKey.PublicKey.Y) != 0 {
		t.Error("decoded DER key does not match")
	}
}

func TestDecodeES256PublicKey_DER_Invalid(t *testing.T) {
	// 100 bytes of garbage that isn't valid PKIX
	garbage := make([]byte, 100)
	_, err := decodeES256PublicKey(base64.StdEncoding.EncodeToString(garbage))
	if err == nil {
		t.Fatal("expected error for invalid DER")
	}
}

func TestDecodeES256PublicKey_NonECDSA(t *testing.T) {
	// Ed25519 key marshaled as PKIX will not type-assert to *ecdsa.PublicKey
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	derBytes, _ := x509.MarshalPKIXPublicKey(edPub)
	b64 := base64.StdEncoding.EncodeToString(derBytes)

	_, err := decodeES256PublicKey(b64)
	if err == nil {
		t.Fatal("expected error for non-ECDSA key")
	}
}

func TestDecodeES256PublicKey_WrongCurve(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	derBytes, _ := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	b64 := base64.StdEncoding.EncodeToString(derBytes)

	_, err := decodeES256PublicKey(b64)
	if err == nil {
		t.Fatal("expected error for wrong curve (P-384)")
	}
}

func TestParseNotificationFileJSON_InvalidJSON(t *testing.T) {
	_, err := ParseNotificationFileJSON([]byte("{invalid json}"), "TEST")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// splitJWS splits a compact JWS into its three parts.
func splitJWS(jws string) []string {
	var parts []string
	start := 0
	dots := 0
	for i, c := range jws {
		if c == '.' {
			parts = append(parts, jws[start:i])
			start = i + 1
			dots++
			if dots == 2 {
				parts = append(parts, jws[start:])
				break
			}
		}
	}
	return parts
}

func TestMarshalES256Sig_Padding(t *testing.T) {
	// r with high bit set → needs leading zero
	r := new(big.Int).SetBytes([]byte{0x80, 0x01})
	// s without high bit set
	s := new(big.Int).SetBytes([]byte{0x01})
	der := marshalES256Sig(r, s)
	if len(der) < 4 || der[0] != 0x30 {
		t.Fatalf("expected ASN.1 SEQUENCE, got %x", der)
	}
}

func TestMarshalES256Sig_PaddingBoth(t *testing.T) {
	// both r and s with high bit set
	r := new(big.Int).SetBytes([]byte{0x80, 0x01})
	s := new(big.Int).SetBytes([]byte{0xFF, 0x02})
	der := marshalES256Sig(r, s)
	if len(der) < 4 || der[0] != 0x30 {
		t.Fatalf("expected ASN.1 SEQUENCE, got %x", der)
	}
}

// Suppress unused import warning for sha256
var _ = sha256.New
