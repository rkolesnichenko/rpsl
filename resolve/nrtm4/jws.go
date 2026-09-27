package nrtm4

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
)

// ParsePublicKey reads a signing key as NRTMv4 distributes it (§4.1): an
// ECDSA P-256 public key in PEM ("BEGIN PUBLIC KEY", RFC 7468 §13), the only
// kind ES256 verifies with.
func ParsePublicKey(text string) (*ecdsa.PublicKey, error) {
	b, rest := pem.Decode([]byte(text))
	if b == nil {
		return nil, errors.New("nrtm4: public key: no PEM block")
	}
	if b.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("nrtm4: public key: PEM block %q, want \"PUBLIC KEY\"", b.Type)
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, errors.New("nrtm4: public key: data after the PEM block")
	}
	k, err := x509.ParsePKIXPublicKey(b.Bytes)
	if err != nil {
		return nil, fmt.Errorf("nrtm4: public key: %w", err)
	}
	ec, ok := k.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, fmt.Errorf("nrtm4: public key: %T is not an ECDSA P-256 key, which ES256 needs", k)
	}
	return ec, nil
}

// verifyJWS checks a JWS in compact serialization (RFC 7515 §7.1) signed with
// ES256 (RFC 7518 §3.4) against key, and returns its payload. Any other
// algorithm is refused — "none", a MAC, RSA — as is a header naming
// extensions that must be understood ("crit", RFC 7515 §4.1.11).
func verifyJWS(compact []byte, key *ecdsa.PublicKey) ([]byte, error) {
	compact = bytes.TrimSpace(compact)
	parts := bytes.Split(compact, []byte("."))
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a JWS in compact serialization: %d parts, want 3", len(parts))
	}
	header, err := b64(parts[0])
	if err != nil {
		return nil, fmt.Errorf("JWS header: %w", err)
	}
	var h map[string]json.RawMessage
	if err := json.Unmarshal(header, &h); err != nil || h == nil {
		return nil, fmt.Errorf("JWS header is not a JSON object: %q", header)
	}
	var alg string
	if err := json.Unmarshal(h["alg"], &alg); err != nil || alg != "ES256" {
		return nil, fmt.Errorf("JWS algorithm %s, want \"ES256\"", h["alg"])
	}
	if _, ok := h["crit"]; ok {
		return nil, fmt.Errorf("JWS header names critical extensions %s, which are not understood", h["crit"])
	}
	sig, err := b64(parts[2])
	if err != nil {
		return nil, fmt.Errorf("JWS signature: %w", err)
	}
	if len(sig) != 64 { // R and S, 32 bytes each (RFC 7518 §3.4)
		return nil, fmt.Errorf("ES256 signature of %d bytes, want 64", len(sig))
	}
	digest := sha256.Sum256(compact[:len(parts[0])+1+len(parts[1])])
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(key, digest[:], r, s) {
		return nil, errors.New("JWS signature does not verify")
	}
	payload, err := b64(parts[1])
	if err != nil {
		return nil, fmt.Errorf("JWS payload: %w", err)
	}
	return payload, nil
}

// b64 decodes base64url without padding, as JWS writes it (RFC 7515 §2).
func b64(s []byte) ([]byte, error) {
	out := make([]byte, base64.RawURLEncoding.DecodedLen(len(s)))
	n, err := base64.RawURLEncoding.Strict().Decode(out, s)
	return out[:n], err
}
