// Package nrtmtest is an NRTMv4 mirror server for tests (draft-ietf-grow-nrtm-v4):
// it publishes an IRR database's changes as signed Update Notification Files,
// gzipped Snapshot Files and Delta Files over HTTPS on a localhost port, as
// IRRd and the RIPE Database do, and can misbehave in each way a client must
// survive. It signs and encodes everything itself — not through package
// nrtm4 — so that tests hold the client to an independent server.
package nrtmtest

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// Change is one record of a Delta File: an object added or modified (Text),
// or deleted (Delete, with its class and primary key as the server spells it).
type Change struct {
	Delete bool
	Class  string
	PK     string
	Text   string
}

// Server is an NRTMv4 publication of one IRR database.
type Server struct {
	t      testing.TB
	source string
	srv    *httptest.Server

	mu       sync.Mutex
	key      *ecdsa.PrivateKey
	next     *ecdsa.PrivateKey // announced in next_signing_key, or nil
	session  string
	version  int64
	objects  map[string]string // class + " " + upper-case pk -> text
	snapshot file
	deltas   []file
	files    map[string][]byte // path -> bytes, as served
	now      time.Time
	fail     int                        // answer this many requests with 503
	requests []string                   // paths requested, in order
	unf      func(map[string]any) error // edits the payload before signing
}

type file struct {
	Version int64  `json:"version"`
	URL     string `json:"url"`
	Hash    string `json:"hash"`
}

// New starts a server for source at version 1: a new session and an empty
// snapshot.
func New(t testing.TB, source string) *Server {
	t.Helper()
	s := &Server{t: t, source: source, key: newKey(t), objects: map[string]string{}, files: map[string][]byte{},
		now: time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)}
	s.srv = httptest.NewTLSServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.srv.Close)
	s.NewSession()
	return s
}

// URL is the Update Notification File's.
func (s *Server) URL() string {
	return s.srv.URL + "/nrtmv4/" + s.source + "/update-notification-file.jose"
}

// HTTPClient trusts the server's certificate.
func (s *Server) HTTPClient() *http.Client { return s.srv.Client() }

// PublicKey is the PEM of the key the server signs with now.
func (s *Server) PublicKey() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return pemOf(s.t, &s.key.PublicKey)
}

// Session is the current session_id.
func (s *Server) Session() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.session
}

// Version is the database version published last.
func (s *Server) Version() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.version
}

// Objects returns the database at the version published last: object texts
// by class and upper-case primary key.
func (s *Server) Objects() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]string{}
	for k, v := range s.objects {
		out[k] = v
	}
	return out
}

// Requests returns the paths requested so far, in order.
func (s *Server) Requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.requests...)
}

// NewSession starts over, as a server that lost its history must (§4.2): a
// new session_id, a snapshot of the objects at version 1, and no deltas.
func (s *Server) NewSession() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.session = uuid4(s.t)
	s.version = 1
	s.deltas = nil
	s.snapshotLocked()
}

// Publish records one Delta File of changes, as the next version.
func (s *Server) Publish(changes ...Change) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.version++
	var b bytes.Buffer
	s.record(&b, map[string]any{"nrtm_version": 4, "type": "delta", "source": s.source, "session_id": s.session, "version": s.version})
	for _, c := range changes {
		if c.Delete {
			delete(s.objects, strings.ToLower(c.Class)+" "+strings.ToUpper(c.PK))
			s.record(&b, map[string]any{"action": "delete", "object_class": c.Class, "primary_key": c.PK})
			continue
		}
		s.objects[strings.ToLower(c.Class)+" "+strings.ToUpper(c.PK)] = c.Text
		s.record(&b, map[string]any{"action": "add_modify", "object": c.Text})
	}
	s.deltas = append(s.deltas, s.put(fmt.Sprintf("nrtm-delta.%d.%s.%s.json", s.version, s.session, token(s.t)), b.Bytes(), s.version))
}

// Snapshot publishes a Snapshot File at the current version, unless the
// last one is at it already (§4.3.2: no new snapshot without changes).
func (s *Server) Snapshot() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.snapshot.Version != s.version {
		s.snapshotLocked()
	}
}

func (s *Server) snapshotLocked() {
	var b bytes.Buffer
	s.record(&b, map[string]any{"nrtm_version": 4, "type": "snapshot", "source": s.source, "session_id": s.session, "version": s.version})
	keys := make([]string, 0, len(s.objects))
	for k := range s.objects {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		s.record(&b, map[string]any{"object": s.objects[k]})
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write(b.Bytes())
	zw.Close()
	s.snapshot = s.put(fmt.Sprintf("nrtm-snapshot.%d.%s.%s.json.gz", s.version, s.session, token(s.t)), gz.Bytes(), s.version)
}

// Expire drops the references to deltas up to and including version, as a
// server does after 24 hours (§4.3.1) — but none after the snapshot, which
// would leave no way from it to the current version; the files stay served.
func (s *Server) Expire(version int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	version = min(version, s.snapshot.Version)
	for len(s.deltas) > 0 && s.deltas[0].Version <= version {
		s.deltas = s.deltas[1:]
	}
}

// Corrupt serves other bytes for the delta of version, or for the snapshot
// when version is 0, than those its hash is of.
func (s *Server) Corrupt(version int64, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.snapshot
	for _, d := range s.deltas {
		if d.Version == version {
			f = d
		}
	}
	s.files[f.URL] = data
}

// Replace publishes data as the delta of version, with a matching hash: a
// well-signed file whose content is wrong.
func (s *Server) Replace(version int64, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, d := range s.deltas {
		if d.Version == version {
			s.deltas[i] = s.put(d.URL, data, version)
		}
	}
}

// ReplaceSnapshot publishes data as the snapshot, with a matching hash.
func (s *Server) ReplaceSnapshot(data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapshot = s.put(s.snapshot.URL, data, s.snapshot.Version)
}

// Rehash changes the hash the notification file lists for the delta of
// version, without changing the file: a server rewriting history.
func (s *Server) Rehash(version int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, d := range s.deltas {
		if d.Version == version {
			s.deltas[i].Hash = strings.Repeat("0", 64)
		}
	}
}

// AnnounceKey generates the next signing key and announces it in
// next_signing_key; RotateKey then signs with it (§9.6).
func (s *Server) AnnounceKey() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next = newKey(s.t)
	return pemOf(s.t, &s.next.PublicKey)
}

// RotateKey signs with the announced key from now on, and announces none.
func (s *Server) RotateKey() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.key, s.next = s.next, nil
}

// SignWith signs with key from now on, announced or not.
func (s *Server) SignWith(key *ecdsa.PrivateKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.key = key
}

// SetTime sets the timestamp of the notification files served from now on.
func (s *Server) SetTime(t time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = t
}

// Fail answers the next n requests with 503 Service Unavailable.
func (s *Server) Fail(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fail = n
}

// EditNotification changes every notification file's payload before it is
// signed, with edit; nil stops.
func (s *Server) EditNotification(edit func(map[string]any) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.unf = edit
}

// NewKey returns a fresh ES256 key, for SignWith.
func NewKey(t testing.TB) *ecdsa.PrivateKey { return newKey(t) }

// PEM returns a public key as NRTMv4 distributes it.
func PEM(t testing.TB, key *ecdsa.PrivateKey) string { return pemOf(t, &key.PublicKey) }

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, r.URL.Path)
	if s.fail > 0 {
		s.fail--
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	dir := "/nrtmv4/" + s.source + "/"
	name, ok := strings.CutPrefix(r.URL.Path, dir)
	switch {
	case !ok:
		http.NotFound(w, r)
	case name == "update-notification-file.jose":
		w.Header().Set("Content-Type", "application/jose+json")
		w.Header().Set("Cache-Control", "max-age=60")
		w.Write(s.notification())
	default:
		data, ok := s.files[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(data)
	}
}

func (s *Server) notification() []byte {
	deltas := s.deltas
	if deltas == nil {
		deltas = []file{}
	}
	p := map[string]any{"nrtm_version": 4, "timestamp": s.now.Format(time.RFC3339), "type": "notification",
		"source": s.source, "session_id": s.session, "version": s.version, "snapshot": s.snapshot, "deltas": deltas}
	if s.next != nil {
		p["next_signing_key"] = pemOf(s.t, &s.next.PublicKey)
	}
	if s.unf != nil {
		// Round-trip through JSON so that edit sees plain maps and slices.
		b, _ := json.Marshal(p)
		p = map[string]any{}
		json.Unmarshal(b, &p)
		if err := s.unf(p); err != nil {
			s.t.Errorf("nrtmtest: editing the notification: %v", err)
		}
	}
	payload, err := json.Marshal(p)
	if err != nil {
		s.t.Errorf("nrtmtest: %v", err)
	}
	return []byte(signES256(s.t, s.key, payload))
}

func (s *Server) put(name string, data []byte, version int64) file {
	s.files[name] = data
	sum := sha256.Sum256(data)
	return file{Version: version, URL: name, Hash: hex.EncodeToString(sum[:])}
}

// record writes one JSON text sequence record (RFC 7464).
func (s *Server) record(b *bytes.Buffer, v any) {
	j, err := json.Marshal(v)
	if err != nil {
		s.t.Errorf("nrtmtest: %v", err)
	}
	b.WriteByte(0x1E)
	b.Write(j)
	b.WriteByte('\n')
}

func signES256(t testing.TB, key *ecdsa.PrivateKey, payload []byte) string {
	input := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`)) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	r, sg, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("nrtmtest: %v", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	sg.FillBytes(sig[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func newKey(t testing.TB) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("nrtmtest: %v", err)
	}
	return k
}

func pemOf(t testing.TB, pub *ecdsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("nrtmtest: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func uuid4(t testing.TB) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("nrtmtest: %v", err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func token(t testing.TB) string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("nrtmtest: %v", err)
	}
	return hex.EncodeToString(b[:])
}
