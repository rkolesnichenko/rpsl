package nrtm4

import (
	"bytes"
	"encoding/hex"
	"io"
	"os"
	"strings"
	"testing"
)

// FuzzParseNotification: no JWS or payload panics; a payload accepted holds
// every §6.3 rule — the version the highest listed, deltas contiguous, hashes
// hex SHA-256, the session a lower-case UUIDv4.
func FuzzParseNotification(f *testing.F) {
	jose, _ := os.ReadFile("testdata/ripe-nonauth-unf.jose")
	f.Add(jose)
	f.Add([]byte(specExample))
	f.Add([]byte(`{"nrtm_version":4}`))
	keyPEM, _ := os.ReadFile("testdata/ripe-public-key.pem")
	key, err := ParsePublicKey(string(keyPEM))
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		verifyJWS(in, key)
		n, err := parseNotification(in)
		if err != nil {
			return
		}
		top := n.Snapshot.Version
		for i, d := range n.Deltas {
			if i > 0 && d.Version != n.Deltas[i-1].Version+1 {
				t.Fatalf("deltas not contiguous: %+v", n.Deltas)
			}
			top = max(top, d.Version)
		}
		if n.Version != top || n.Version < 1 {
			t.Fatalf("version %d, highest listed %d", n.Version, top)
		}
		for _, r := range append([]fileRef{n.Snapshot}, n.Deltas...) {
			if b, err := hex.DecodeString(r.Hash); err != nil || len(b) != 32 || r.Hash != strings.ToLower(r.Hash) || r.URL == "" {
				t.Fatalf("file reference %+v", r)
			}
		}
		if len(n.SessionID) != 36 || n.SessionID != strings.ToLower(n.SessionID) || n.SessionID[14] != '4' {
			t.Fatalf("session %q", n.SessionID)
		}
	})
}

// FuzzReadDelta: no delta file body panics the sequence reader, the header
// check or the change parser, and each record read is non-empty and within
// the cap.
func FuzzReadDelta(f *testing.F) {
	f.Add([]byte("\x1e" + `{"nrtm_version":4,"type":"delta","source":"TEST","session_id":"` + testSession + `","version":2}` +
		"\n\x1e" + `{"action":"add_modify","object":"route: 192.0.2.0/24\norigin: AS1\nsource: TEST\n"}` +
		"\n\x1e" + `{"action":"delete","object_class":"route","primary_key":"192.0.2.0/24AS1"}` + "\n"))
	f.Add([]byte("\x1e\x1e{}\x1e"))
	f.Add([]byte(`{"action":"delete"}`))
	c := &Client{Database: "TEST"}
	n := &notification{Source: "TEST", SessionID: testSession}
	f.Fuzz(func(t *testing.T, in []byte) {
		seq := newSeqReader(bytes.NewReader(in), 1<<10)
		if err := c.fileHeader(seq, "delta", n, 2); err != nil {
			seq = newSeqReader(bytes.NewReader(in), 1<<10)
		}
		for {
			rec, err := seq.next()
			if err == io.EOF || err != nil {
				return
			}
			if len(rec) == 0 || len(rec) > 1<<10 {
				t.Fatalf("record of %d bytes", len(rec))
			}
			c.change(rec)
		}
	})
}

// FuzzVerifyJWS: no input panics with any key type, and only a correctly
// signed file in the key's own algorithm verifies — which the fuzzer cannot
// forge, so verifying an input it changed means a check was skipped.
func FuzzVerifyJWS(f *testing.F) {
	keys := testKeys(f)
	signed := map[string]string{}
	for alg, k := range keys {
		signed[alg] = signAs(f, alg, k, `{"alg":"`+alg+`"}`, "payload")
		f.Add(signed[alg], alg)
	}
	f.Add("e30.e30.", "ES256")
	f.Fuzz(func(t *testing.T, jws, alg string) {
		k, ok := keys[alg]
		if !ok {
			return
		}
		pub, err := ParsePublicKey(pemOf(t, k.Public()))
		if err != nil {
			t.Fatal(err)
		}
		p, err := verifyJWS([]byte(jws), pub)
		if err != nil {
			return
		}
		// Only the signed header and payload verify; ECDSA's (r, n-s)
		// re-signature is the one legitimate variant.
		hdr := strings.Split(signed[alg], ".")[0]
		if string(p) != "payload" || strings.Split(strings.TrimSpace(jws), ".")[0] != hdr {
			t.Fatalf("an input the fuzzer made verified as %s: %q (payload %q)", alg, jws, p)
		}
	})
}
