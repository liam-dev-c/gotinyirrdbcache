package irrd

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
)

// jwsHeader represents the parsed JWS JOSE header.
type jwsHeader struct {
	Alg string `json:"alg"`
}

// VerifyNotificationFile verifies a JWS compact serialization and returns the
// decoded payload. Supports EdDSA (Ed25519) and ES256 (ECDSA P-256).
// If pubKeyB64 is empty, verification is skipped.
func VerifyNotificationFile(jwsCompact string, pubKeyB64 string) ([]byte, error) {
	parts := strings.SplitN(jwsCompact, ".", 3)
	if len(parts) != 3 {
		return nil, &SignatureError{Message: "invalid JWS: expected 3 parts"}
	}

	headerB64, payloadB64, sigB64 := parts[0], parts[1], parts[2]

	// Decode and validate header
	headerBytes, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		return nil, &SignatureError{Message: fmt.Sprintf("decoding JWS header: %v", err)}
	}

	var header jwsHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, &SignatureError{Message: fmt.Sprintf("parsing JWS header: %v", err)}
	}

	// Decode payload
	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, &SignatureError{Message: fmt.Sprintf("decoding JWS payload: %v", err)}
	}

	// Verify signature if key is provided
	if pubKeyB64 != "" {
		sig, err := base64.RawURLEncoding.DecodeString(sigB64)
		if err != nil {
			return nil, &SignatureError{Message: fmt.Sprintf("decoding JWS signature: %v", err)}
		}

		signingInput := []byte(headerB64 + "." + payloadB64)

		switch header.Alg {
		case "EdDSA":
			if err := verifyEdDSA(signingInput, sig, pubKeyB64); err != nil {
				return nil, err
			}
		case "ES256":
			if err := verifyES256(signingInput, sig, pubKeyB64); err != nil {
				return nil, err
			}
		default:
			return nil, &SignatureError{Message: fmt.Sprintf("unsupported JWS algorithm: %s", header.Alg)}
		}
	}

	return payload, nil
}

// verifyEdDSA verifies an Ed25519 signature.
func verifyEdDSA(signingInput, sig []byte, pubKeyB64 string) error {
	pubKey, err := decodeEd25519PublicKey(pubKeyB64)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pubKey, signingInput, sig) {
		return &SignatureError{Message: "EdDSA signature verification failed"}
	}
	return nil
}

// verifyES256 verifies an ECDSA P-256 (ES256) signature.
// The signature is the raw R||S concatenation (each 32 bytes) per JWS spec.
func verifyES256(signingInput, sig []byte, pubKeyB64 string) error {
	pubKey, err := decodeES256PublicKey(pubKeyB64)
	if err != nil {
		return err
	}

	if len(sig) != 64 {
		return &SignatureError{Message: fmt.Sprintf("invalid ES256 signature length: %d (expected 64)", len(sig))}
	}

	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])

	if !ecdsa.VerifyASN1(pubKey, sha256Hash(signingInput), marshalES256Sig(r, s)) {
		// Try direct r,s verify
		if !ecdsa.Verify(pubKey, sha256Hash(signingInput), r, s) {
			return &SignatureError{Message: "ES256 signature verification failed"}
		}
	}
	return nil
}

// sha256Hash returns the SHA-256 hash of data.
func sha256Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// marshalES256Sig encodes r, s as ASN.1 DER for VerifyASN1.
func marshalES256Sig(r, s *big.Int) []byte {
	rb := r.Bytes()
	sb := s.Bytes()
	// Pad with leading zero if high bit is set
	if len(rb) > 0 && rb[0]&0x80 != 0 {
		rb = append([]byte{0}, rb...)
	}
	if len(sb) > 0 && sb[0]&0x80 != 0 {
		sb = append([]byte{0}, sb...)
	}
	// SEQUENCE { INTEGER r, INTEGER s }
	inner := make([]byte, 0, 2+len(rb)+2+len(sb))
	inner = append(inner, 0x02, byte(len(rb)))
	inner = append(inner, rb...)
	inner = append(inner, 0x02, byte(len(sb)))
	inner = append(inner, sb...)
	out := make([]byte, 0, 2+len(inner))
	out = append(out, 0x30, byte(len(inner)))
	out = append(out, inner...)
	return out
}

// decodeEd25519PublicKey decodes a base64-encoded Ed25519 public key.
func decodeEd25519PublicKey(b64Key string) (ed25519.PublicKey, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return nil, &SignatureError{Message: fmt.Sprintf("decoding Ed25519 public key: %v", err)}
	}
	if len(keyBytes) != ed25519.PublicKeySize {
		return nil, &SignatureError{Message: fmt.Sprintf("invalid Ed25519 public key size: got %d, want %d", len(keyBytes), ed25519.PublicKeySize)}
	}
	return ed25519.PublicKey(keyBytes), nil
}

// decodeES256PublicKey decodes a base64-encoded ECDSA P-256 public key.
// Accepts raw 64-byte (X||Y), 65-byte uncompressed (0x04||X||Y), or DER/PKIX encoded keys.
func decodeES256PublicKey(b64Key string) (*ecdsa.PublicKey, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return nil, &SignatureError{Message: fmt.Sprintf("decoding ES256 public key: %v", err)}
	}

	switch len(keyBytes) {
	case 64:
		// Raw X||Y
		x := new(big.Int).SetBytes(keyBytes[:32])
		y := new(big.Int).SetBytes(keyBytes[32:])
		return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
	case 65:
		// Uncompressed point (0x04 || X || Y)
		if keyBytes[0] != 0x04 {
			return nil, &SignatureError{Message: "invalid uncompressed EC point prefix"}
		}
		x := new(big.Int).SetBytes(keyBytes[1:33])
		y := new(big.Int).SetBytes(keyBytes[33:])
		return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
	default:
		// Try DER/PKIX
		pub, err := x509.ParsePKIXPublicKey(keyBytes)
		if err != nil {
			return nil, &SignatureError{Message: fmt.Sprintf("parsing ES256 public key: %v", err)}
		}
		ecPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, &SignatureError{Message: "public key is not ECDSA"}
		}
		if ecPub.Curve != elliptic.P256() {
			return nil, &SignatureError{Message: "ECDSA key is not P-256"}
		}
		return ecPub, nil
	}
}

// ParseNotificationFileJSON parses and validates the JSON payload of a notification file.
// source must match the nf.Source field.
func ParseNotificationFileJSON(data []byte, source string) (*NotificationFile, error) {
	var nf NotificationFile
	if err := json.Unmarshal(data, &nf); err != nil {
		return nil, fmt.Errorf("parsing notification file: %w", err)
	}
	if nf.NRTMVersion != 4 {
		return nil, fmt.Errorf("notification file: nrtm_version %d, want 4", nf.NRTMVersion)
	}
	if nf.Type != "notification" {
		return nil, fmt.Errorf("notification file: type %q, want \"notification\"", nf.Type)
	}
	if nf.Source != source {
		return nil, fmt.Errorf("notification file: source %q does not match configured source %q", nf.Source, source)
	}
	return &nf, nil
}
