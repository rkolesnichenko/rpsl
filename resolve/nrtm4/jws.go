package nrtm4

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
)

// ParsePublicKey reads a signing key as NRTMv4 distributes it (§4.1): a public
// key in PEM ("BEGIN PUBLIC KEY", RFC 7468 §13) of a type verification
// accepts — *ecdsa.PublicKey on P-256, P-384 or P-521, ed25519.PublicKey, or
// *rsa.PublicKey of at least 2048 bits. The key decides the JWS algorithm a
// file it verifies must name (algsFor).
func ParsePublicKey(text string) (crypto.PublicKey, error) {
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
	if algsFor(k) == nil {
		return nil, fmt.Errorf("nrtm4: public key: %s is not a key NRTMv4 verification accepts (ECDSA P-256, P-384 or P-521, Ed25519, RSA of at least 2048 bits)", describeKey(k))
	}
	return k, nil
}

// algsFor returns the JWS algorithms key verifies: those the NRTMv4 draft
// (draft-ietf-grow-nrtm-v4-11 §4.1) lets a server use that are neither
// deprecated nor a MAC (IANA JOSE registry; "EdDSA" is deprecated by RFC
// 9864 in favour of "Ed25519"), and that the standard library implements.
// nil: none.
func algsFor(key crypto.PublicKey) []string {
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return []string{"ES256"}
		case elliptic.P384():
			return []string{"ES384"}
		case elliptic.P521():
			return []string{"ES512"}
		}
	case ed25519.PublicKey:
		return []string{"Ed25519"}
	case *rsa.PublicKey:
		if k.N.BitLen() >= 2048 {
			return []string{"RS256", "PS256"}
		}
	}
	return nil
}

func describeKey(k crypto.PublicKey) string {
	switch k := k.(type) {
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA of %d bits", k.N.BitLen())
	}
	return fmt.Sprintf("%T", k)
}

var errBadSignature = errors.New("JWS signature does not verify")

// verifyJWS checks a JWS in compact serialization (RFC 7515 §7.1) against
// key and returns its payload. The header's "alg" must be one algsFor gives
// the key — so a header cannot choose a different check than the key was
// issued for — and a header naming extensions that must be understood
// ("crit", RFC 7515 §4.1.11) is refused.
func verifyJWS(compact []byte, key crypto.PublicKey) ([]byte, error) {
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
	if err := json.Unmarshal(h["alg"], &alg); err != nil {
		return nil, fmt.Errorf("JWS algorithm %s: not a string", h["alg"])
	}
	allowed := algsFor(key)
	if !slices.Contains(allowed, alg) {
		if alg == "EdDSA" {
			return nil, errors.New(`JWS algorithm "EdDSA" is deprecated (RFC 9864); an Ed25519 key signs as "Ed25519"`)
		}
		return nil, fmt.Errorf("JWS algorithm %q, want %q for this key", alg, strings.Join(allowed, `" or "`))
	}
	if _, ok := h["crit"]; ok {
		return nil, fmt.Errorf("JWS header names critical extensions %s, which are not understood", h["crit"])
	}
	sig, err := b64(parts[2])
	if err != nil {
		return nil, fmt.Errorf("JWS signature: %w", err)
	}
	if err := verifySignature(alg, key, compact[:len(parts[0])+1+len(parts[1])], sig); err != nil {
		return nil, err
	}
	payload, err := b64(parts[1])
	if err != nil {
		return nil, fmt.Errorf("JWS payload: %w", err)
	}
	return payload, nil
}

// verifySignature checks sig over input with key as alg (RFC 7518 §3.3-3.5,
// RFC 8037 §3.1 as RFC 9864 names it). verifyJWS has matched alg to key.
func verifySignature(alg string, key crypto.PublicKey, input, sig []byte) error {
	switch alg {
	case "ES256", "ES384", "ES512":
		k := key.(*ecdsa.PublicKey)
		size := (k.Curve.Params().BitSize + 7) / 8 // R and S, each this long (RFC 7518 §3.4)
		if len(sig) != 2*size {
			return fmt.Errorf("%s signature of %d bytes, want %d", alg, len(sig), 2*size)
		}
		var digest []byte
		switch alg {
		case "ES256":
			d := sha256.Sum256(input)
			digest = d[:]
		case "ES384":
			d := sha512.Sum384(input)
			digest = d[:]
		default:
			d := sha512.Sum512(input)
			digest = d[:]
		}
		if !ecdsa.Verify(k, digest, new(big.Int).SetBytes(sig[:size]), new(big.Int).SetBytes(sig[size:])) {
			return errBadSignature
		}
	case "Ed25519":
		if !ed25519.Verify(key.(ed25519.PublicKey), input, sig) {
			return errBadSignature
		}
	case "RS256", "PS256":
		d := sha256.Sum256(input)
		k := key.(*rsa.PublicKey)
		var err error
		if alg == "RS256" {
			err = rsa.VerifyPKCS1v15(k, crypto.SHA256, d[:], sig)
		} else {
			err = rsa.VerifyPSS(k, crypto.SHA256, d[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		}
		if err != nil {
			return errBadSignature
		}
	default:
		return fmt.Errorf("JWS algorithm %q is not implemented", alg)
	}
	return nil
}

// b64 decodes base64url without padding, as JWS writes it (RFC 7515 §2).
func b64(s []byte) ([]byte, error) {
	out := make([]byte, base64.RawURLEncoding.DecodedLen(len(s)))
	n, err := base64.RawURLEncoding.Strict().Decode(out, s)
	return out[:n], err
}
