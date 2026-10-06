package nrtm4

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
)

// TestVerifyRIPE verifies the notification file RIPE served for RIPE-NONAUTH
// (testdata, captured 2026-09-27) with the key RIPE publishes
// (ftp.ripe.net/ripe/dbase/nrtmv4/nrtmv4_public_key.txt).
func TestVerifyRIPE(t *testing.T) {
	keyPEM, err := os.ReadFile("testdata/ripe-public-key.pem")
	if err != nil {
		t.Fatal(err)
	}
	jose, err := os.ReadFile("testdata/ripe-nonauth-unf.jose")
	if err != nil {
		t.Fatal(err)
	}
	key, err := ParsePublicKey(string(keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := verifyJWS(jose, key)
	if err != nil {
		t.Fatal(err)
	}
	n, err := parseNotification(payload)
	if err != nil {
		t.Fatal(err)
	}
	if n.Source != "RIPE-NONAUTH" || n.Version != 3495 || n.Snapshot.Version != 3495 || len(n.Deltas) != 0 ||
		n.SessionID != "4f3ff2a7-1877-4cab-82f4-1dd6425c4e7d" {
		t.Errorf("parsed %+v", n)
	}
	// One flipped byte in the payload breaks it.
	bad := []byte(string(jose))
	i := strings.IndexByte(string(bad), '.') + 10
	bad[i] ^= 1
	if _, err := verifyJWS(bad, key); err == nil {
		t.Error("a tampered payload verified")
	}
}

// TestVerifyRFC7515 is RFC 7515 Appendix A.3, a JWS signed with ES256.
func TestVerifyRFC7515(t *testing.T) {
	x, _ := base64.RawURLEncoding.DecodeString("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU")
	y, _ := base64.RawURLEncoding.DecodeString("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0")
	key := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	const jws = "eyJhbGciOiJFUzI1NiJ9" +
		".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
		".DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
	payload, err := verifyJWS([]byte(jws), key)
	if err != nil {
		t.Fatal(err)
	}
	if want := "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}"; string(payload) != want {
		t.Errorf("payload %q", payload)
	}
}

func TestVerifyRefuses(t *testing.T) {
	key, other := newKey(t), newKey(t)
	good := sign(t, key, `{"alg":"ES256"}`, "payload")
	if p, err := verifyJWS([]byte(good), &key.PublicKey); err != nil || string(p) != "payload" {
		t.Fatalf("a good JWS: %q, %v", p, err)
	}
	if p, err := verifyJWS([]byte("\n"+good+"\n"), &key.PublicKey); err != nil || string(p) != "payload" {
		t.Fatalf("a good JWS with a line break: %q, %v", p, err)
	}
	parts := strings.Split(good, ".")
	unsigned := b64s(`{"alg":"none"}`) + "." + parts[1] + "."
	for name, jws := range map[string]string{
		"the wrong key":     sign(t, other, `{"alg":"ES256"}`, "payload"),
		"alg none":          unsigned,
		"HS256":             sign(t, key, `{"alg":"HS256"}`, "payload"),
		"EdDSA":             sign(t, key, `{"alg":"EdDSA"}`, "payload"),
		"RS256 on EC key":   sign(t, key, `{"alg":"RS256"}`, "payload"),
		"no alg":            sign(t, key, `{"kid":"x"}`, "payload"),
		"crit":              sign(t, key, `{"alg":"ES256","crit":["exp"],"exp":1}`, "payload"),
		"a header not JSON": sign(t, key, `alg`, "payload"),
		"two parts":         parts[0] + "." + parts[1],
		"four parts":        good + ".x",
		"a short signature": parts[0] + "." + parts[1] + "." + b64s("short"),
		"padded base64":     parts[0] + "." + parts[1] + "=." + parts[2],
		"a bad character":   parts[0] + "." + parts[1] + "." + parts[2][:10] + "*" + parts[2][11:],
		"another payload":   parts[0] + "." + b64s("other") + "." + parts[2],
		"another header":    b64s(`{"alg":"ES256","kid":"x"}`) + "." + parts[1] + "." + parts[2],
	} {
		if _, err := verifyJWS([]byte(jws), &key.PublicKey); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
}

func TestParsePublicKey(t *testing.T) {
	for alg, k := range testKeys(t) {
		if _, err := ParsePublicKey(pemOf(t, k.Public())); err != nil {
			t.Errorf("%s key: %v", alg, err)
		}
	}
	key := newKey(t)
	rsa1024, _ := rsa.GenerateKey(rand.Reader, 1024)
	for name, text := range map[string]string{
		"no PEM":         "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE",
		"a private key":  strings.Replace(pemOf(t, &key.PublicKey), "PUBLIC KEY", "EC PRIVATE KEY", 2),
		"RSA 1024":       pemOf(t, &rsa1024.PublicKey),
		"trailing data":  pemOf(t, &key.PublicKey) + "junk",
		"a broken block": "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
	} {
		if _, err := ParsePublicKey(text); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func newKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func pemOf(t testing.TB, pub any) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func b64s(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// sign makes a JWS in compact serialization, signed as ES256 whatever header says.
func sign(t testing.TB, key *ecdsa.PrivateKey, header, payload string) string {
	t.Helper()
	input := b64s(header) + "." + b64s(payload)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// signAs makes a JWS signed as alg with key, whatever header says.
func signAs(t testing.TB, alg string, key crypto.Signer, header, payload string) string {
	t.Helper()
	input := b64s(header) + "." + b64s(payload)
	var sig []byte
	var err error
	switch alg {
	case "ES256", "ES384", "ES512":
		k := key.(*ecdsa.PrivateKey)
		var digest []byte
		switch alg {
		case "ES256":
			d := sha256.Sum256([]byte(input))
			digest = d[:]
		case "ES384":
			d := sha512.Sum384([]byte(input))
			digest = d[:]
		default:
			d := sha512.Sum512([]byte(input))
			digest = d[:]
		}
		r, s, e := ecdsa.Sign(rand.Reader, k, digest)
		if e != nil {
			t.Fatal(e)
		}
		size := (k.Curve.Params().BitSize + 7) / 8
		sig = make([]byte, 2*size)
		r.FillBytes(sig[:size])
		s.FillBytes(sig[size:])
	case "Ed25519":
		sig = ed25519.Sign(key.(ed25519.PrivateKey), []byte(input))
	case "RS256":
		d := sha256.Sum256([]byte(input))
		sig, err = rsa.SignPKCS1v15(rand.Reader, key.(*rsa.PrivateKey), crypto.SHA256, d[:])
	case "PS256":
		d := sha256.Sum256([]byte(input))
		sig, err = rsa.SignPSS(rand.Reader, key.(*rsa.PrivateKey), crypto.SHA256, d[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	default:
		t.Fatalf("signAs: %s", alg)
	}
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// testKeys generates one key of each accepted type, once per test binary.
func testKeys(t testing.TB) map[string]crypto.Signer {
	t.Helper()
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]crypto.Signer{"ES256": p256, "ES384": p384, "ES512": p521, "Ed25519": ed, "RS256": rk, "PS256": rk}
}

// Every accepted algorithm verifies with its own key type, and only with it.
func TestVerifyAlgorithms(t *testing.T) {
	keys := testKeys(t)
	for alg, k := range keys {
		pub, err := ParsePublicKey(pemOf(t, k.Public()))
		if err != nil {
			t.Fatalf("%s key: %v", alg, err)
		}
		jws := signAs(t, alg, k, `{"alg":"`+alg+`"}`, "payload")
		if p, err := verifyJWS([]byte(jws), pub); err != nil || string(p) != "payload" {
			t.Errorf("%s: %q, %v", alg, p, err)
		}
		// The same file presented with any other algorithm's key is refused.
		for other, ko := range keys {
			if ko.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(k.Public()) {
				continue // RS256 and PS256 share one RSA key
			}
			opub, _ := ParsePublicKey(pemOf(t, ko.Public()))
			if _, err := verifyJWS([]byte(jws), opub); err == nil {
				t.Errorf("%s file verified with the %s key", alg, other)
			}
		}
	}
	// A header naming another algorithm than the key's is refused before any
	// signature check: an ES256 key never verifies "ES384".
	p256 := keys["ES256"]
	pub, _ := ParsePublicKey(pemOf(t, p256.Public()))
	if _, err := verifyJWS([]byte(signAs(t, "ES256", p256, `{"alg":"ES384"}`, "x")), pub); err == nil || !strings.Contains(err.Error(), `"ES384"`) {
		t.Errorf("an ES384 header on a P-256 key: %v", err)
	}
	// Review Focus 3: an Ed25519 key with the deprecated "EdDSA" header.
	ed := keys["Ed25519"]
	edPub, _ := ParsePublicKey(pemOf(t, ed.Public()))
	if _, err := verifyJWS([]byte(signAs(t, "Ed25519", ed, `{"alg":"EdDSA"}`, "x")), edPub); err == nil ||
		!strings.Contains(err.Error(), "deprecated") || !strings.Contains(err.Error(), `"Ed25519"`) {
		t.Errorf(`"EdDSA" header: %v; want refused as deprecated, naming "Ed25519"`, err)
	}
	// RS256 and PS256 are two algorithms on one RSA key: each verifies only
	// its own signature.
	rk := keys["RS256"]
	rpub, _ := ParsePublicKey(pemOf(t, rk.Public()))
	if _, err := verifyJWS([]byte(signAs(t, "RS256", rk, `{"alg":"PS256"}`, "x")), rpub); err == nil {
		t.Error("a PKCS#1 v1.5 signature verified as PS256")
	}
}
