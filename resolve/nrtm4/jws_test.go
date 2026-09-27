package nrtm4

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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
		"ES384":             sign(t, key, `{"alg":"ES384"}`, "payload"),
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
	key := newKey(t)
	if _, err := ParsePublicKey(pemOf(t, &key.PublicKey)); err != nil {
		t.Fatal(err)
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	for name, text := range map[string]string{
		"no PEM":         "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE",
		"a private key":  strings.Replace(pemOf(t, &key.PublicKey), "PUBLIC KEY", "EC PRIVATE KEY", 2),
		"P-384":          pemOf(t, &p384.PublicKey),
		"RSA":            pemOf(t, &rsaKey.PublicKey),
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
