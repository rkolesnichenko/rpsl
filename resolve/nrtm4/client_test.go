package nrtm4

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/internal/nrtmtest"
	"github.com/rkolesnichenko/rpsl/types"
)

func init() { retryUnit, minInterval = time.Millisecond, 20*time.Millisecond }

func newClient(s *nrtmtest.Server, db string) *Client {
	return &Client{URL: s.URL(), Database: db, PublicKey: s.PublicKey(), HTTP: s.HTTPClient(),
		Now: func() time.Time { return time.Date(2026, 9, 27, 12, 30, 0, 0, time.UTC) }}
}

func route(prefix string, as int, extra string) nrtmtest.Change {
	return nrtmtest.Change{Class: "route", PK: fmt.Sprintf("%sAS%d", prefix, as),
		Text: fmt.Sprintf("route:  %s\norigin: AS%d\n%ssource: TEST\n", prefix, as, extra)}
}

func asSet(name string, members ...string) nrtmtest.Change {
	return nrtmtest.Change{Class: "as-set", PK: name,
		Text: fmt.Sprintf("as-set:  %s\nmembers: %s\nsource:  TEST\n", name, strings.Join(members, ", "))}
}

func expand(t *testing.T, c *Client, set string) []string {
	t.Helper()
	n, err := types.ParseSetName(set)
	if err != nil {
		t.Fatal(err)
	}
	ps, err := (&resolve.Expander{Src: c.Source()}).ExpandPrefixes(context.Background(), types.Ref(n))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, p := range ps.List() {
		out = append(out, p.String())
	}
	slices.Sort(out)
	return out
}

func mustSync(t *testing.T, c *Client) Update {
	t.Helper()
	u, err := c.Sync(context.Background())
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	return u
}

func TestClientFollowsServer(t *testing.T) {
	s := nrtmtest.New(t, "TEST")
	s.Publish(asSet("AS-TOP", "AS1", "AS2"), route("192.0.2.0/24", 1, ""))
	s.Snapshot()
	c := newClient(s, "test") // the name is case-insensitive
	if c.Source() != nil || c.Status().Version != 0 {
		t.Fatal("a view before the first Sync")
	}
	u := mustSync(t, c)
	if !u.Snapshot || u.Reason != "first load" || u.To != 2 || u.Added != 2 {
		t.Errorf("first Sync: %+v", u)
	}
	if got := expand(t, c, "AS-TOP"); !slices.Equal(got, []string{"192.0.2.0/24"}) {
		t.Errorf("AS-TOP = %v", got)
	}
	old := c.Source()

	s.Publish(route("198.51.100.0/24", 2, ""), route("203.0.113.0/24", 2, ""))
	s.Publish(nrtmtest.Change{Delete: true, Class: "route", PK: "192.0.2.0/24AS1"},
		nrtmtest.Change{Delete: true, Class: "ROUTE", PK: "203.0.113.0/24as2"}) // spelled as the server likes
	u = mustSync(t, c)
	if u.Snapshot || u.Deltas != 2 || u.From != 2 || u.To != 4 || u.Added != 2 || u.Deleted != 2 {
		t.Errorf("deltas: %+v", u)
	}
	if got := expand(t, c, "AS-TOP"); !slices.Equal(got, []string{"198.51.100.0/24"}) {
		t.Errorf("AS-TOP = %v", got)
	}
	// The earlier view is untouched: an expansion holds one version.
	if got, _ := old.OriginatedRoutes(context.Background(), 1, types.AFIAny); len(got) != 1 {
		t.Errorf("the old view changed: %v", got)
	}
	u = mustSync(t, c)
	if u.Snapshot || u.Deltas != 0 || u.From != 4 || u.To != 4 {
		t.Errorf("up to date: %+v", u)
	}
	if c.Source() == old {
		t.Error("no new view after deltas")
	}
	st := c.Status()
	if st.Version != 4 || st.Objects != 2 || st.CurrentKey != s.PublicKey() || st.Stale {
		t.Errorf("status %+v", st)
	}
}

func TestClientReloads(t *testing.T) {
	s := nrtmtest.New(t, "TEST")
	c := newClient(s, "TEST")
	mustSync(t, c)
	s.Publish(route("192.0.2.0/24", 1, ""))
	s.Publish(route("198.51.100.0/24", 1, ""))
	s.Snapshot()
	s.Publish(route("203.0.113.0/24", 1, ""))
	s.Expire(3) // the deltas after version 1 are gone: a gap
	u := mustSync(t, c)
	if !u.Snapshot || !strings.Contains(u.Reason, "reach back to version 2") || u.To != 4 || u.Deltas != 1 {
		t.Errorf("gap: %+v", u)
	}
	s.NewSession()
	u = mustSync(t, c)
	if !u.Snapshot || !strings.HasPrefix(u.Reason, "new session") || u.To != 1 || c.Status().Objects != 3 {
		t.Errorf("new session: %+v, %d objects", u, c.Status().Objects)
	}
}

func TestClientRefusesTampering(t *testing.T) {
	s := nrtmtest.New(t, "TEST")
	c := newClient(s, "TEST")
	mustSync(t, c)
	s.Publish(route("192.0.2.0/24", 1, ""))
	s.Publish(route("198.51.100.0/24", 1, ""))
	s.Publish(route("203.0.113.0/24", 1, ""))
	s.Corrupt(3, []byte("\x1e{}\n"))
	u, err := c.Sync(context.Background())
	if err == nil || !strings.Contains(err.Error(), "delta 3: SHA-256") {
		t.Fatalf("a corrupt delta: %v", err)
	}
	// Delta 2 applied; 3 refused, and 4 not applied after it.
	if u.To != 2 || c.Status().Version != 2 || c.Status().Objects != 1 {
		t.Errorf("after a corrupt delta: %+v, status %+v", u, c.Status())
	}
	s.Rehash(2)
	if _, err := c.Sync(context.Background()); err == nil || !strings.Contains(err.Error(), "rewrote history") {
		t.Errorf("history rewritten: %v", err)
	}
	if c.Status().Version != 2 {
		t.Error("a refused notification file moved the mirror")
	}
}

func TestClientRefusesBadDeltas(t *testing.T) {
	const hdr = `{"nrtm_version":4,"type":"delta","source":"TEST","session_id":"SESSION","version":3}`
	const del = `{"action":"delete","object_class":"route","primary_key":"192.0.2.0/24AS1"}`
	for name, delta := range map[string]string{
		"no changes":       hdr,
		"another session":  strings.Replace(hdr, "SESSION", "ca128382-78d9-41d1-8927-1ecef15275be", 1) + "\x1e" + del,
		"another version":  strings.Replace(hdr, `"version":3`, `"version":4`, 1) + "\x1e" + del,
		"another source":   strings.Replace(hdr, `"TEST"`, `"OTHER"`, 1) + "\x1e" + del,
		"a snapshot":       strings.Replace(hdr, `"delta"`, `"snapshot"`, 1) + "\x1e" + del,
		"a bad action":     hdr + "\x1e" + `{"action":"modify","object":"route: 192.0.2.0/24"}`,
		"no object":        hdr + "\x1e" + `{"action":"add_modify"}`,
		"no primary key":   hdr + "\x1e" + `{"action":"delete","object_class":"route"}`,
		"not JSON":         hdr + "\x1e" + `{"action":`,
		"no header":        "",
		"a good one first": hdr + "\x1e" + del + "\x1e" + `{"action":"nope"}`,
	} {
		t.Run(name, func(t *testing.T) {
			s := nrtmtest.New(t, "TEST")
			s.Publish(route("192.0.2.0/24", 1, ""))
			s.Snapshot()
			c := newClient(s, "TEST")
			mustSync(t, c)
			s.Publish(route("198.51.100.0/24", 1, ""))
			s.Replace(3, []byte("\x1e"+strings.Replace(delta, "SESSION", s.Session(), 1)+"\n"))
			if _, err := c.Sync(context.Background()); err == nil {
				t.Fatal("accepted")
			}
			if st := c.Status(); st.Version != 2 || st.Objects != 1 {
				t.Errorf("a refused delta changed the mirror: %+v", st)
			}
		})
	}
}

// A notification file whose deltas skip the one after its snapshot leaves no
// way to its version (§4.3.1): the snapshot loads, and nothing after it.
func TestClientRefusesDeltaGapAfterSnapshot(t *testing.T) {
	s := nrtmtest.New(t, "TEST")
	s.Publish(route("192.0.2.0/24", 1, ""))
	s.Snapshot()
	s.Publish(route("198.51.100.0/24", 1, ""))
	s.Publish(route("203.0.113.0/24", 1, ""))
	s.EditNotification(func(p map[string]any) error {
		p["deltas"] = p["deltas"].([]any)[2:] // keep delta 4 only: 3 is missing
		return nil
	})
	c := newClient(s, "TEST")
	u, err := c.Sync(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no delta leads from version 2 to 4") {
		t.Fatalf("a gap after the snapshot: %v", err)
	}
	if !u.Snapshot || u.To != 2 || c.Status().Objects != 1 {
		t.Errorf("after the gap: %+v, %d objects", u, c.Status().Objects)
	}
}

func TestClientKeys(t *testing.T) {
	s := nrtmtest.New(t, "TEST")
	c := newClient(s, "TEST")
	mustSync(t, c)
	next := s.AnnounceKey()
	mustSync(t, c)
	if st := c.Status(); st.NextKey != next {
		t.Fatalf("next key not seen: %+v", st)
	}
	s.RotateKey()
	s.Publish(route("192.0.2.0/24", 1, ""))
	mustSync(t, c)
	if st := c.Status(); st.CurrentKey != next || st.NextKey != "" || st.Version != 2 {
		t.Fatalf("after the rotation: %+v", st)
	}
	// The old key is never trusted again (§9.6).
	oldKey := nrtmtest.NewKey(t)
	s.SignWith(oldKey)
	if _, err := c.Sync(context.Background()); err == nil {
		t.Error("an unknown key verified")
	}
	// A client never told of the rotation, configured with the old key, fails.
	s2 := nrtmtest.New(t, "TEST")
	c2 := newClient(s2, "TEST")
	s2.SignWith(nrtmtest.NewKey(t))
	if _, err := c2.Sync(context.Background()); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Errorf("a key the client does not know: %v", err)
	}
}

func TestClientNotificationChecks(t *testing.T) {
	s := nrtmtest.New(t, "OTHER")
	c := newClient(s, "TEST")
	if _, err := c.Sync(context.Background()); err == nil || !strings.Contains(err.Error(), `for source "OTHER"`) {
		t.Errorf("another database: %v", err)
	}

	s = nrtmtest.New(t, "TEST")
	c = newClient(s, "TEST")
	s.Publish(route("192.0.2.0/24", 1, ""))
	s.Publish(route("198.51.100.0/24", 1, ""))
	mustSync(t, c)
	for _, tc := range []struct {
		back int64
		want string
	}{{1, "one before"}, {2, "far before"}} {
		back := tc.back
		s.EditNotification(func(p map[string]any) error {
			v := p["version"].(float64) - float64(back)
			p["version"] = v
			ds := p["deltas"].([]any)
			p["deltas"] = ds[:len(ds)-int(back)]
			if v == 1 {
				p["deltas"] = []any{}
				p["snapshot"].(map[string]any)["version"] = 1
			}
			return nil
		})
		if _, err := c.Sync(context.Background()); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%d versions back: %v", back, err)
		}
	}
	s.EditNotification(nil)

	s.SetTime(time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC))
	u := mustSync(t, c)
	if !u.Stale || !c.Status().Stale {
		t.Errorf("a two-day-old notification file is not stale: %+v", u)
	}
}

func TestClientRetries(t *testing.T) {
	s := nrtmtest.New(t, "TEST")
	c := newClient(s, "TEST")
	s.Fail(3)
	mustSync(t, c) // three 503s, then an answer
	s.Fail(20)
	if _, err := c.Sync(context.Background()); err == nil || !strings.Contains(err.Error(), "503") {
		t.Errorf("a server that keeps failing: %v", err)
	}
}

// After three Syncs in a row fail on a delta, the next reloads the snapshot.
func TestClientFallsBackToSnapshot(t *testing.T) {
	s := nrtmtest.New(t, "TEST")
	c := newClient(s, "TEST")
	mustSync(t, c)
	s.Publish(route("192.0.2.0/24", 1, ""))
	s.Snapshot()
	s.Corrupt(2, []byte("junk"))
	for i := 0; i < 3; i++ {
		if _, err := c.Sync(context.Background()); err == nil {
			t.Fatal("a corrupt delta applied")
		}
	}
	u := mustSync(t, c)
	if !u.Snapshot || !strings.Contains(u.Reason, "3 Syncs") || u.To != 2 || c.Status().Objects != 1 {
		t.Errorf("fallback: %+v", u)
	}
}

func TestClientSnapshotChecks(t *testing.T) {
	gz := func(s string) []byte {
		var b bytes.Buffer
		w := gzip.NewWriter(&b)
		w.Write([]byte(s))
		w.Close()
		return b.Bytes()
	}
	const hdr = "\x1e" + `{"nrtm_version":4,"type":"snapshot","source":"TEST","session_id":"SESSION","version":1}`
	for name, data := range map[string]func(session string) []byte{
		"not gzip":  func(string) []byte { return []byte(hdr) },
		"no header": func(string) []byte { return gz("") },
		"a delta header": func(s string) []byte {
			return gz(strings.Replace(strings.Replace(hdr, "SESSION", s, 1), "snapshot", "delta", 1))
		},
		"no object":     func(s string) []byte { return gz(strings.Replace(hdr, "SESSION", s, 1) + "\x1e{\"x\":1}") },
		"trailing junk": func(s string) []byte { return append(gz(strings.Replace(hdr, "SESSION", s, 1)), "junk"...) },
		"too large": func(s string) []byte {
			return gz(strings.Replace(hdr, "SESSION", s, 1) + "\x1e" + `{"object":"` + strings.Repeat("x", 4<<10) + `"}`)
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := nrtmtest.New(t, "TEST")
			s.Publish(route("192.0.2.0/24", 1, ""))
			c := newClient(s, "TEST")
			c.MaxFileBytes = 2 << 10
			mustSync(t, c)
			s.NewSession()
			s.ReplaceSnapshot(data(s.Session()))
			if _, err := c.Sync(context.Background()); err == nil {
				t.Fatal("accepted")
			}
			if st := c.Status(); st.Version != 2 || st.Objects != 1 {
				t.Errorf("a refused snapshot changed the mirror: %+v", st)
			}
		})
	}
}

func TestClientDiscards(t *testing.T) {
	s := nrtmtest.New(t, "TEST")
	s.Publish(
		route("192.0.2.0/24", 1, ""),
		nrtmtest.Change{Class: "route", PK: "x", Text: "route: 198.51.100.0/24\norigin: AS1\nsource: OTHER\n"}, // another source
		nrtmtest.Change{Class: "route", PK: "y", Text: "route: 203.0.113.0/24\nsource: TEST\n"},                // no origin: no key
		nrtmtest.Change{Class: "person", PK: "P1", Text: "person: A\nnic-hdl: P1-TEST\nsource: TEST\n"},        // not the engine's, unparsed
		nrtmtest.Change{Class: "route", PK: "z", Text: "route: 10.0.0.0/8\norigin: ASX\nsource: TEST\n"},       // no AS's route
		nrtmtest.Change{Class: "aut-num", PK: "AS1", Text: "aut-num: AS1\nas-name: X\nsource: TEST\n"},         // claims nothing
	)
	var rules []string
	c := newClient(s, "TEST")
	c.OnDiagnostics = func(o *ast.Object, ds []ast.Diagnostic) {
		for _, d := range ds {
			rules = append(rules, d.Rule)
		}
	}
	u := mustSync(t, c)
	if c.Status().Objects != 1 || u.Discarded != 5 {
		t.Errorf("kept %d, discarded %d; want 1 and 5", c.Status().Objects, u.Discarded)
	}
	if n := strings.Count(strings.Join(rules, " "), "nrtm4/discarded"); n != 2 {
		t.Errorf("%d nrtm4/discarded diagnostics, want 2 (other source, no key): %v", n, rules)
	}
	// An update from another source is discarded, as IRRd discards it: the
	// object it names stays.
	s.Publish(nrtmtest.Change{Class: "route", PK: "192.0.2.0/24AS1", Text: "route: 192.0.2.0/24\norigin: AS1\nsource: ELSEWHERE\n"})
	if mustSync(t, c); c.Status().Objects != 1 {
		t.Errorf("the object went: %d objects", c.Status().Objects)
	}
	// An update the engine has no use for removes the version it replaces.
	s.Publish(nrtmtest.Change{Class: "aut-num", PK: "AS2", Text: "aut-num: AS2\nmember-of: AS-X\nsource: TEST\n"})
	s.Publish(nrtmtest.Change{Class: "aut-num", PK: "AS2", Text: "aut-num: AS2\nsource: TEST\n"})
	if mustSync(t, c); c.Status().Objects != 1 {
		t.Errorf("the replaced aut-num stayed: %d objects", c.Status().Objects)
	}
}

// CopyTo merges a mirror's version into a corpus of the caller's, to expand
// against several databases under one precedence.
func TestClientCopyTo(t *testing.T) {
	a, b := nrtmtest.New(t, "RIPE"), nrtmtest.New(t, "RIPE-NONAUTH")
	a.Publish(asSet("AS-X", "AS1"), route("192.0.2.0/24", 1, "")) // source TEST: discarded
	a.Publish(nrtmtest.Change{Class: "as-set", PK: "AS-X", Text: "as-set: AS-X\nmembers: AS1\nsource: RIPE\n"})
	b.Publish(nrtmtest.Change{Class: "route", PK: "192.0.2.0/24AS1", Text: "route: 192.0.2.0/24\norigin: AS1\nsource: RIPE-NONAUTH\n"})
	ca, cb := newClient(a, "RIPE"), newClient(b, "RIPE-NONAUTH")
	mustSync(t, ca)
	mustSync(t, cb)
	all := &resolve.Corpus{}
	ca.CopyTo(all)
	cb.CopyTo(all)
	if all.Len() != 2 {
		t.Fatalf("merged %d objects, want 2", all.Len())
	}
	n, _ := types.ParseSetName("AS-X")
	ps, err := (&resolve.Expander{Src: all.Source("RIPE", "RIPE-NONAUTH")}).ExpandPrefixes(context.Background(), types.Ref(n))
	if err != nil || ps.Len() != 1 {
		t.Errorf("AS-X over both mirrors: %v, %v", ps.List(), err)
	}
}

func TestClientURLs(t *testing.T) {
	s := nrtmtest.New(t, "TEST")
	s.EditNotification(func(p map[string]any) error {
		p["snapshot"].(map[string]any)["url"] = "https://elsewhere.example/snapshot.json.gz"
		return nil
	})
	if _, err := newClient(s, "TEST").Sync(context.Background()); err == nil || !strings.Contains(err.Error(), "leaves") {
		t.Errorf("a snapshot on another host: %v", err)
	}
	c := &Client{URL: "http://example.com/nrtmv4/X/update-notification-file.jose", Database: "X", PublicKey: s.PublicKey()}
	if _, err := c.Sync(context.Background()); err == nil || !strings.Contains(err.Error(), "HTTPS only") {
		t.Errorf("plain HTTP: %v", err)
	}
	c = &Client{URL: s.URL(), Database: "TEST", PublicKey: "nope"}
	if _, err := c.Sync(context.Background()); err == nil {
		t.Error("a bad configured key")
	}
}

// A mirror can be read from local files (§9.4), verified all the same.
func TestClientLocalFiles(t *testing.T) {
	s := nrtmtest.New(t, "TEST")
	s.Publish(route("192.0.2.0/24", 1, ""))
	s.Snapshot()
	s.Publish(route("198.51.100.0/24", 1, ""))
	dir := t.TempDir()
	hc := s.HTTPClient()
	get := func(name string) []byte {
		resp, err := hc.Get(strings.TrimSuffix(s.URL(), "update-notification-file.jose") + name)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var b bytes.Buffer
		b.ReadFrom(resp.Body)
		return b.Bytes()
	}
	unf := get("update-notification-file.jose")
	os.WriteFile(filepath.Join(dir, "update-notification-file.jose"), unf, 0o600)
	payload, err := verifyJWS(unf, mustKey(t, s.PublicKey()))
	if err != nil {
		t.Fatal(err)
	}
	n, err := parseNotification(payload)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, n.Snapshot.URL), get(n.Snapshot.URL), 0o600)
	for _, d := range n.Deltas {
		os.WriteFile(filepath.Join(dir, d.URL), get(d.URL), 0o600)
	}
	c := &Client{URL: "file://" + filepath.Join(dir, "update-notification-file.jose"), Database: "TEST", PublicKey: s.PublicKey(),
		Now: func() time.Time { return time.Date(2026, 9, 27, 12, 30, 0, 0, time.UTC) }}
	u := mustSync(t, c)
	if u.To != 3 || c.Status().Objects != 2 {
		t.Errorf("from files: %+v", u)
	}
}

func mustKey(t *testing.T, s string) *ecdsa.PublicKey {
	t.Helper()
	k, err := ParsePublicKey(s)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestDiscardRuleIsDocumented holds docs/diagnostics.md to the rule and
// severity the client emits.
func TestDiscardRuleIsDocumented(t *testing.T) {
	// docs/diagnostics.md lives in the root rpsl module, outside resolve's
	// own module tree, so it is not in resolve's published zip (release.sh
	// step 6 tests resolve alone, from an empty module cache). Skip rather
	// than fail when this is not a checkout of the whole repository —
	// detected by the repo root's go.work, which only a checkout has.
	if _, err := os.Stat("../../go.work"); err != nil {
		t.Skip("not running inside the rpsl repository checkout (../../go.work not found); docs/diagnostics.md lives outside resolve's own module")
	}
	doc, err := os.ReadFile("../../docs/diagnostics.md")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(doc), "**`nrtm4/discarded`**, severity **Warning**") {
		t.Error("docs/diagnostics.md does not document nrtm4/discarded as a Warning")
	}
	s := nrtmtest.New(t, "TEST")
	s.Publish(nrtmtest.Change{Class: "route", PK: "x", Text: "route: 198.51.100.0/24\norigin: AS1\nsource: OTHER\n"})
	var got []ast.Diagnostic
	c := newClient(s, "TEST")
	c.OnDiagnostics = func(_ *ast.Object, ds []ast.Diagnostic) { got = append(got, ds...) }
	mustSync(t, c)
	if len(got) != 1 || got[0].Rule != "nrtm4/discarded" || got[0].Severity != ast.Warning {
		t.Errorf("emitted %v", got)
	}
}

func TestRun(t *testing.T) {
	s := nrtmtest.New(t, "TEST")
	c := newClient(s, "TEST")
	ctx, cancel := context.WithCancel(context.Background())
	var errs []error
	done := make(chan error)
	go func() { done <- c.Run(ctx, time.Nanosecond, func(err error) { errs = append(errs, err) }) }()
	deadline := time.Now().Add(10 * time.Second)
	for c.Status().Version != 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	s.Publish(route("192.0.2.0/24", 1, ""))
	s.Fail(4) // one Sync's four attempts fail; Run backs off and tries again
	for c.Status().Version != 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != context.Canceled {
		t.Errorf("Run returned %v", err)
	}
	if c.Status().Version != 2 || len(errs) == 0 || !strings.Contains(errs[0].Error(), "503") {
		t.Errorf("version %d, errors %v", c.Status().Version, errs)
	}
}

// Review regressions (v0.19.0).

// An object whose primary key lengthens when upper-cased is discarded, not a
// panic.
func TestClientUnicodeKey(t *testing.T) {
	s := nrtmtest.New(t, "TEST")
	s.Publish(nrtmtest.Change{Class: "route", PK: "x", Text: "route: " + strings.Repeat("ɐ", 10) + "\norigin: AS1\nsource: TEST\n"})
	c := newClient(s, "TEST")
	if _, err := c.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.Publish(nrtmtest.Change{Delete: true, Class: "route", PK: strings.Repeat("ɐ", 10) + "AS1"})
	if _, err := c.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// A snapshot's objects reach OnDiagnostics only once its hash has checked out.
func TestClientSnapshotDiagnosticsAfterHash(t *testing.T) {
	s := nrtmtest.New(t, "TEST")
	c := newClient(s, "TEST")
	var seen int
	c.OnDiagnostics = func(*ast.Object, []ast.Diagnostic) { seen++ }
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	fmt.Fprintf(w, "\x1e{\"nrtm_version\":4,\"type\":\"snapshot\",\"source\":\"TEST\",\"session_id\":%q,\"version\":1}\n", s.Session())
	fmt.Fprintf(w, "\x1e{\"object\":\"route: 192.0.2.0/24\\norigin: AS1\\nsource: OTHER\\n\"}\n")
	w.Close()
	s.Corrupt(0, b.Bytes()) // served in place of the snapshot the hash is of
	if _, err := c.Sync(context.Background()); err == nil {
		t.Fatal("a snapshot with the wrong hash loaded")
	}
	if seen != 0 {
		t.Errorf("OnDiagnostics saw %d objects of a snapshot that failed its hash", seen)
	}
}

// A notification file that redirects elsewhere is refused, with the client
// the caller gave as well as the default one.
func TestClientRefusesRedirect(t *testing.T) {
	s := nrtmtest.New(t, "TEST")
	elsewhere := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, s.URL(), http.StatusFound) // same content, another host
	}))
	defer elsewhere.Close()
	c := newClient(s, "TEST")
	c.URL = elsewhere.URL + "/nrtmv4/TEST/update-notification-file.jose"
	c.HTTP = elsewhere.Client()
	if _, err := c.Sync(context.Background()); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Errorf("a redirect to another host: %v", err)
	}
}

// MaxAge refuses a notification file older than it; a new session older than
// the version held is refused whatever MaxAge says.
func TestClientRefusesOld(t *testing.T) {
	s := nrtmtest.New(t, "TEST")
	c := newClient(s, "TEST")
	c.MaxAge = 24 * time.Hour
	s.SetTime(time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)) // two days before the client's clock
	if _, err := c.Sync(context.Background()); err == nil || !strings.Contains(err.Error(), "MaxAge") {
		t.Fatalf("a two-day-old file with MaxAge 24h: %v", err)
	}
	c.MaxAge = 0
	s.SetTime(time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC))
	s.Publish(route("192.0.2.0/24", 1, ""))
	mustSync(t, c)
	s.NewSession()
	s.SetTime(time.Date(2026, 9, 27, 11, 0, 0, 0, time.UTC)) // older than the file the mirror came from
	if _, err := c.Sync(context.Background()); err == nil || !strings.Contains(err.Error(), "older") {
		t.Fatalf("a new session older than the mirror: %v", err)
	}
	if st := c.Status(); st.Version != 2 || st.Objects != 1 {
		t.Errorf("a refused session moved the mirror: %+v", st)
	}
}

// Run never polls again sooner than the minimum, after a failure either.
func TestRunWaits(t *testing.T) {
	for _, interval := range []time.Duration{minInterval, 3 * minInterval, time.Hour} {
		for failures := 0; failures < 12; failures++ {
			w := runWait(failures, interval)
			if w < minInterval || w > interval {
				t.Errorf("runWait(%d, %v) = %v: outside [%v, %v]", failures, interval, w, minInterval, interval)
			}
		}
	}
}

func TestClientKeepsPolicy(t *testing.T) {
	s := nrtmtest.New(t, "TEST")
	s.Publish(nrtmtest.Change{Class: "aut-num", PK: "AS1",
		Text: "aut-num: AS1\nas-name: ONE\nimport: from AS2 accept ANY\nsource: TEST\n"})
	s.Snapshot()
	c := newClient(s, "TEST")
	c.KeepPolicy = true
	mustSync(t, c)
	an, err := c.Source().AutNum(context.Background(), 1, "")
	if err != nil || an.AsName != "ONE" {
		t.Fatalf("AutNum = %q, %v", an.AsName, err)
	}
	s.Publish(nrtmtest.Change{Delete: true, Class: "aut-num", PK: "AS1"})
	mustSync(t, c)
	if _, err := c.Source().AutNum(context.Background(), 1, ""); !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("after the delta's delete: %v", err)
	}
	// Without KeepPolicy the mirror's Source serves no policy objects.
	plain := newClient(s, "TEST")
	mustSync(t, plain)
	if _, err := plain.Source().AutNum(context.Background(), 1, ""); !errors.Is(err, resolve.ErrNoPolicy) {
		t.Errorf("a mirror without KeepPolicy: AutNum = %v; want ErrNoPolicy", err)
	}
}

// TestClientKeepsRouteText: a Client with KeepRouteText keeps each route's
// text — from the snapshot and from a delta — so CopyTo into a corpus that
// keeps text carries it.
func TestClientKeepsRouteText(t *testing.T) {
	s := nrtmtest.New(t, "TEST")
	s.Publish(route("192.0.2.0/24", 1, ""))
	s.Snapshot()
	c := newClient(s, "TEST")
	c.KeepRouteText = true
	mustSync(t, c)
	s.Publish(route("198.51.100.0/24", 2, "descr: by delta\n"))
	mustSync(t, c)
	dst := &resolve.Corpus{KeepRouteText: true}
	c.CopyTo(dst)
	texts := map[types.ASN]string{}
	for r := range dst.Routes() {
		texts[r.Origin] = r.Text
	}
	if !strings.HasPrefix(texts[1], "route:  192.0.2.0/24\n") {
		t.Errorf("the snapshot's route: %q", texts[1])
	}
	if !strings.Contains(texts[2], "descr: by delta\n") {
		t.Errorf("the delta's route: %q", texts[2])
	}
}
