// Package nrtm4 mirrors an IRR database over NRTMv4 (draft-ietf-grow-nrtm-v4),
// the protocol IRRd 4 and the RIPE Database publish their changes with: a
// signed Update Notification File that lists a Snapshot File and the Delta
// Files since, fetched over HTTPS. A Client keeps an in-memory mirror and
// publishes each version it reaches as an immutable resolve.MemSource, so an
// expansion always sees one version whole while the mirror moves on.
//
// Every file is verified before any of it is used: the notification file's
// ES256 signature against the operator's key (rotated in-band, §9.6), each
// snapshot's and delta's SHA-256 against the notification file, each header
// against the session and version it should have. A delta is applied whole
// or not at all, and none after one that was refused.
//
// Network access is confined to this sub-package; the core resolve engine
// stays pure and socket-free.
package nrtm4

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
)

// Default caps. A notification file lists at most a day of deltas (RIPE's is
// about 200 KB); the largest RIPE object is about 2 MB.
const (
	DefaultMaxFileBytes = 16 << 30 // any snapshot or delta, decompressed
	maxNotification     = 64 << 20
	maxRecord           = 64 << 20
)

// Client mirrors one IRR database over NRTMv4. URL, Database and PublicKey are
// required; the other fields may be left zero. A Client must not be copied
// after first use, and its fields must not change after it.
type Client struct {
	URL       string // the Update Notification File (…/update-notification-file.jose): https://, or file:// (§9.4)
	Database  string // the IRR database's name, e.g. "RIPE": the notification file's source must be it
	PublicKey string // PEM of the key the server signs with now (ES256); Status().CurrentKey after a rotation

	HTTP         *http.Client // nil: http.DefaultClient with a 10-minute timeout per file
	MaxFileBytes int64        // cap on a snapshot or delta after decompression; 0: DefaultMaxFileBytes

	// MaxAge, when set, refuses a notification file older than it, as IRRd
	// refuses one over 24 hours old, so that a server replaying an old but
	// validly signed file cannot roll the mirror back. Zero accepts any age
	// and reports it (Status.Stale), as the draft allows (§5.6). Whatever
	// MaxAge, a new session older than the file the mirror came from is
	// refused.
	MaxAge time.Duration

	// OnDiagnostics, when set, is called for each object that raised
	// diagnostics, or was discarded — its source: not the database's, no
	// primary key (§9.2) — with rule "nrtm4/discarded". Discarding an object
	// never fails the file it came in.
	OnDiagnostics func(o *ast.Object, ds []ast.Diagnostic)

	// Now is the clock staleness is judged by (§5.6); nil is time.Now.
	Now func() time.Time

	// KeepPolicy keeps aut-nums and inet-rtrs, so Source() serves them
	// (resolve.Corpus.KeepPolicy); without it its AutNum and InetRtr return
	// resolve.ErrNoPolicy.
	KeepPolicy bool

	// KeepRouteText keeps each route's text (resolve.Corpus.KeepRouteText),
	// so CopyTo into a corpus that keeps text carries it.
	KeepRouteText bool

	mu       sync.Mutex // serializes Sync
	st       state
	view     atomic.Pointer[view]
	failures int          // consecutive Syncs that failed on a delta
	hc       *http.Client // httpClient's, once built
}

// state is what the client knows between Syncs.
type state struct {
	session string
	version int64 // 0: nothing loaded
	cur     *ecdsa.PublicKey
	curPEM  string
	next    *ecdsa.PublicKey
	nextPEM string
	seen    map[fileID]fileRef // snapshot or delta -> the reference a valid notification file gave
	corpus  *resolve.Corpus
	stamp   time.Time
	stale   bool
}

// view is one published version.
type view struct {
	src    *resolve.MemSource
	status Status
}

// Status is where a Client stands.
type Status struct {
	SessionID string
	Version   int64     // the version the mirror holds; 0 before the first load
	Timestamp time.Time // of the notification file that version came from
	Stale     bool      // that file was over 24 hours old (§5.6): warned, not refused
	Objects   int       // held, whole or reduced (see resolve.Corpus)
	// CurrentKey is the PEM of the key the last notification file verified
	// with: Client.PublicKey, or the key it rotated to (§9.6). Persist it and
	// pass it as PublicKey next time, or a rotation while the program was
	// down leaves nothing that verifies.
	CurrentKey string
	NextKey    string // the key announced in next_signing_key, or ""
}

// Update says what one Sync did.
type Update struct {
	Snapshot  bool   // a snapshot was loaded
	Reason    string // why: "first load", "new session", "deltas do not reach back to version N", …
	From, To  int64  // versions before and after
	Deltas    int    // delta files applied
	Added     int    // objects added or replaced
	Deleted   int    // objects deleted
	Discarded int    // objects left out: nothing the engine uses, or §9.2
	Stale     bool   // the notification file was over 24 hours old
}

// Source returns the mirror at the latest version it holds, as an immutable
// MemSource: use one for the whole of an expansion. nil before the first
// successful Sync.
func (c *Client) Source() *resolve.MemSource {
	if v := c.view.Load(); v != nil {
		return v.src
	}
	return nil
}

// CopyTo merges the mirror's current version into dst, for expanding
// against several mirrors — RIPE and RIPE-NONAUTH — or a mirror with dumps and
// RPKI pseudo routes, under one precedence (dst.Source("RIPE", …)).
func (c *Client) CopyTo(dst *resolve.Corpus) {
	c.mu.Lock()
	defer c.mu.Unlock()
	dst.Merge(c.st.corpus)
}

// Status reports the version the mirror holds and the keys it trusts.
func (c *Client) Status() Status {
	if v := c.view.Load(); v != nil {
		return v.status
	}
	return Status{CurrentKey: c.PublicKey}
}

// Sync polls the server once: it fetches and verifies the notification file,
// loads the snapshot when it must — the first time, after a new session, or
// when the deltas no longer reach back to the version held — and applies the
// deltas after it, in order. What it reached is published even when a later
// file fails, and the error says which file and why; the next Sync starts
// from there. After three Syncs in a row fail on a delta, the next reloads the
// snapshot (§5.5). Transient failures (network errors, HTTP 5xx) are retried
// a few times within one Sync.
func (c *Client) Sync(ctx context.Context) (Update, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	u := Update{From: c.st.version}
	n, err := c.notification(ctx)
	if err != nil {
		return u, err
	}
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	age := now().Sub(n.Timestamp)
	u.Stale = age > 24*time.Hour
	if c.MaxAge > 0 && age > c.MaxAge {
		return u, fmt.Errorf("nrtm4: %s: notification file is %s old, over MaxAge %s", c.Database, age.Round(time.Second), c.MaxAge)
	}
	if c.st.version != 0 && n.SessionID != c.st.session && n.Timestamp.Before(c.st.stamp) {
		return u, fmt.Errorf("nrtm4: %s: a new session %s whose notification file (%s) is older than the one the mirror came from (%s): refused, as a rollback",
			c.Database, n.SessionID, n.Timestamp.Format(time.RFC3339), c.st.stamp.Format(time.RFC3339))
	}

	next := c.st.version + 1
	switch {
	case c.st.version == 0:
		u.Reason = "first load"
	case n.SessionID != c.st.session:
		u.Reason = "new session " + n.SessionID
	case c.failures >= 3:
		u.Reason = fmt.Sprintf("%d Syncs in a row failed on a delta", c.failures)
	case n.Version < c.st.version:
		return u, c.older(n)
	case n.Version >= next && (len(n.Deltas) == 0 || n.Deltas[0].Version > next || n.Deltas[len(n.Deltas)-1].Version < n.Version):
		u.Reason = fmt.Sprintf("deltas do not reach back to version %d", next)
	}
	if err := c.history(n); err != nil {
		return u, err
	}
	if u.Reason != "" {
		corpus, added, discarded, err := c.loadSnapshot(ctx, n)
		if err != nil {
			return u, fmt.Errorf("nrtm4: %s: snapshot %d: %w", c.Database, n.Snapshot.Version, err)
		}
		c.st.session, c.st.version, c.st.corpus = n.SessionID, n.Snapshot.Version, corpus
		c.st.seen = map[fileID]fileRef{}
		c.failures = 0
		u.Snapshot, u.Added, u.Discarded = true, added, discarded
	}
	c.remember(n)
	c.st.stamp, c.st.stale = n.Timestamp, u.Stale
	var derr error
	for _, d := range n.Deltas {
		if d.Version <= c.st.version {
			continue
		}
		if d.Version != c.st.version+1 {
			// A server that dropped a delta after its snapshot (§4.3.1).
			derr = fmt.Errorf("nrtm4: %s: no delta leads from version %d to %d", c.Database, c.st.version, d.Version)
			c.failures++
			break
		}
		added, deleted, discarded, err := c.applyDelta(ctx, n, d)
		if err != nil {
			derr = fmt.Errorf("nrtm4: %s: delta %d: %w", c.Database, d.Version, err)
			c.failures++
			break
		}
		c.st.version = d.Version
		u.Deltas++
		u.Added += added
		u.Deleted += deleted
		u.Discarded += discarded
	}
	if derr == nil {
		c.failures = 0
	}
	u.To = c.st.version
	c.publish(u.Snapshot || u.Deltas > 0)
	return u, derr
}

// notification fetches the notification file, verifies it with the current
// key or the announced next one — and from then on only with that — and
// checks what does not depend on the version held.
func (c *Client) notification(ctx context.Context) (*notification, error) {
	wrap := func(err error) error { return fmt.Errorf("nrtm4: %s: notification file: %w", c.Database, err) }
	if c.st.cur == nil {
		k, err := ParsePublicKey(c.PublicKey)
		if err != nil {
			return nil, err
		}
		c.st.cur, c.st.curPEM = k, c.PublicKey
	}
	body, err := c.fetch(ctx, c.URL, maxNotification)
	if err != nil {
		return nil, wrap(err)
	}
	payload, err := verifyJWS(body, c.st.cur)
	if err != nil && c.st.next != nil {
		var err2 error
		if payload, err2 = verifyJWS(body, c.st.next); err2 == nil {
			// The rotation happened (§9.6): the old key is never used again.
			c.st.cur, c.st.curPEM, c.st.next, c.st.nextPEM, err = c.st.next, c.st.nextPEM, nil, "", nil
		}
	}
	if err != nil {
		return nil, wrap(err)
	}
	n, err := parseNotification(payload)
	if err != nil {
		return nil, wrap(err)
	}
	if !strings.EqualFold(n.Source, c.Database) {
		return nil, fmt.Errorf("nrtm4: %s: notification file is for source %q", c.Database, n.Source)
	}
	if n.NextSigningKey != "" && n.NextSigningKey != c.st.curPEM {
		k, _ := ParsePublicKey(n.NextSigningKey) // parseNotification checked it
		c.st.next, c.st.nextPEM = k, n.NextSigningKey
	}
	return n, nil
}

// older refuses a notification file of the same session older than the
// version held, telling the harmless race from a broken server (§5.4).
func (c *Client) older(n *notification) error {
	if n.Version == c.st.version-1 {
		return fmt.Errorf("nrtm4: %s: notification file is at version %d, one before the %d held: a cache served it late", c.Database, n.Version, c.st.version)
	}
	return fmt.Errorf("nrtm4: %s: notification file is at version %d, far before the %d held: the server is misbehaving", c.Database, n.Version, c.st.version)
}

// history refuses a notification file that gives a snapshot or delta another
// hash than an earlier one of the same session did (§5.4). A URL may change —
// the file is the same — which IRRd, comparing URLs too, refuses.
func (c *Client) history(n *notification) error {
	if n.SessionID != c.st.session {
		return nil
	}
	for id, r := range n.refs() {
		if prev, ok := c.st.seen[id]; ok && prev.Hash != r.Hash {
			return fmt.Errorf("nrtm4: %s: the server rewrote history: %s was %s (%s), now %s (%s)", c.Database, id, prev.URL, prev.Hash, r.URL, r.Hash)
		}
	}
	return nil
}

func (c *Client) remember(n *notification) {
	if c.st.seen == nil {
		c.st.seen = map[fileID]fileRef{}
	}
	for id, r := range n.refs() {
		c.st.seen[id] = r
	}
}

// loadSnapshot reads the snapshot into a new object store, streaming: the
// store is returned only when the file's hash and header check out and every
// record is well-formed.
func (c *Client) loadSnapshot(ctx context.Context, n *notification) (*resolve.Corpus, int, int, error) {
	u, err := c.resolve(n.Snapshot.URL)
	if err != nil {
		return nil, 0, 0, err
	}
	body, err := c.open(ctx, u)
	if err != nil {
		return nil, 0, 0, err
	}
	defer body.Close()
	h := sha256.New()
	tee := io.TeeReader(body, h)
	r, err := c.decompress(u, tee)
	if err != nil {
		return nil, 0, 0, err
	}
	seq := newSeqReader(r, maxRecord)
	if err := c.fileHeader(seq, "snapshot", n, n.Snapshot.Version); err != nil {
		return nil, 0, 0, err
	}
	corpus := &resolve.Corpus{KeepPolicy: c.KeepPolicy, KeepRouteText: c.KeepRouteText}
	added, discarded := 0, 0
	type report struct {
		o  *ast.Object
		ds []ast.Diagnostic
	}
	var reports []report                            // told only once the whole snapshot has checked out
	var collect func(*ast.Object, []ast.Diagnostic) // nil: nobody listens, nothing kept
	if c.OnDiagnostics != nil {
		collect = func(o *ast.Object, ds []ast.Diagnostic) { reports = append(reports, report{o, ds}) }
	}
	for {
		rec, err := seq.next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, 0, 0, err
		}
		if skippable(rec) {
			discarded++
			continue
		}
		text, err := objectText(rec)
		if err != nil {
			return nil, 0, 0, err
		}
		if o := c.object(text, collect); o != nil && corpus.Put(o) {
			added++
		} else {
			discarded++
		}
	}
	if err := drain(tee); err != nil {
		return nil, 0, 0, err
	}
	if err := hashes(h, n.Snapshot.Hash); err != nil {
		return nil, 0, 0, err
	}
	if c.OnDiagnostics != nil {
		for _, r := range reports {
			c.OnDiagnostics(r.o, r.ds)
		}
	}
	return corpus, added, discarded, nil
}

// change is one validated record of a delta: a delete of class and primary
// key, or an object to put (nil: it was discarded, and changes nothing).
type change struct {
	del       bool
	class, pk string
	obj       object.Object
}

// applyDelta fetches, verifies and parses a whole delta file, and only then
// applies its changes, in order.
func (c *Client) applyDelta(ctx context.Context, n *notification, d fileRef) (added, deleted, discarded int, err error) {
	u, err := c.resolve(d.URL)
	if err != nil {
		return 0, 0, 0, err
	}
	data, err := c.fetch(ctx, u, c.maxFile())
	if err != nil {
		return 0, 0, 0, err
	}
	h := sha256.New()
	h.Write(data)
	if err := hashes(h, d.Hash); err != nil {
		return 0, 0, 0, err
	}
	r, err := c.decompress(u, bytes.NewReader(data))
	if err != nil {
		return 0, 0, 0, err
	}
	seq := newSeqReader(r, maxRecord)
	if err := c.fileHeader(seq, "delta", n, d.Version); err != nil {
		return 0, 0, 0, err
	}
	var changes []change
	for {
		rec, err := seq.next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, 0, 0, err
		}
		ch, err := c.change(rec)
		if err != nil {
			return 0, 0, 0, fmt.Errorf("change %d: %w", len(changes)+1, err)
		}
		changes = append(changes, ch)
	}
	if len(changes) == 0 {
		return 0, 0, 0, errors.New("no changes (§8.3: a delta holds at least one)")
	}
	for _, ch := range changes {
		switch {
		case ch.del:
			if c.st.corpus.Delete(ch.class, ch.pk, c.Database) {
				deleted++
			}
		case ch.obj != nil && c.st.corpus.Put(ch.obj):
			added++
		default:
			discarded++ // left out; a version it replaces is gone (Corpus.Put)
		}
	}
	return added, deleted, discarded, nil
}

// change reads one delta record.
func (c *Client) change(rec []byte) (change, error) {
	m, err := jsonObject(rec)
	if err != nil {
		return change{}, err
	}
	action, err := str(m, "action")
	if err != nil {
		return change{}, err
	}
	switch action {
	case "delete":
		class, err := str(m, "object_class")
		if err != nil {
			return change{}, err
		}
		pk, err := str(m, "primary_key")
		if err != nil {
			return change{}, err
		}
		if class == "" || pk == "" {
			return change{}, errors.New("a delete without an object class or primary key")
		}
		return change{del: true, class: class, pk: pk}, nil
	case "add_modify":
		text, err := str(m, "object")
		if err != nil {
			return change{}, err
		}
		return change{obj: c.object(text, c.OnDiagnostics)}, nil // the delta's hash has checked out
	}
	return change{}, fmt.Errorf("action %q, want \"add_modify\" or \"delete\"", action)
}

// object parses and decodes one object text, or returns nil when it is left
// out: a class the engine has no use for (skipped unparsed), or — with a
// diagnostic — an object with no primary key, or of another source (§9.2).
func (c *Client) object(text string, report func(*ast.Object, []ast.Diagnostic)) object.Object {
	class, _, _ := strings.Cut(text, ":")
	if !resolve.ExpandableClass(class) {
		return nil
	}
	raw, ds := rpsl.ParseObject(text)
	if !hasPrimaryKey(raw) {
		discard(report, raw, ds, "it has no class, or no primary key")
		return nil
	}
	if src, has := raw.GetFirst("source"); !has || !strings.EqualFold(strings.TrimSpace(src.Value), c.Database) {
		discard(report, raw, ds, fmt.Sprintf("its source: is not %s", c.Database))
		return nil
	}
	obj, dds := object.Decode(raw) // a typed object of its class, whatever its values
	ds = append(ds, dds...)
	if len(ds) > 0 && report != nil {
		report(raw, ds)
	}
	return obj
}

// discard reports an object left out, with the rule nrtm4/discarded.
func discard(report func(*ast.Object, []ast.Diagnostic), raw *ast.Object, ds []ast.Diagnostic, why string) {
	if report == nil {
		return
	}
	d := ast.Diagnostic{Severity: ast.Warning, Rule: "nrtm4/discarded", Message: "object left out of the mirror: " + why}
	if attrs := raw.Attributes(); len(attrs) > 0 {
		d.Span = attrs[0].Span
	}
	report(raw, append(ds, d))
}

// fileHeader reads a snapshot's or delta's first record and checks it
// against the notification file (§7.3, §8.3).
func (c *Client) fileHeader(seq *seqReader, typ string, n *notification, version int64) error {
	rec, err := seq.next()
	if err == io.EOF {
		return errors.New("empty file: no header")
	}
	if err != nil {
		return err
	}
	h, err := parseFileHeader(rec, typ)
	if err != nil {
		return fmt.Errorf("header: %w", err)
	}
	switch {
	case !strings.EqualFold(h.Source, n.Source):
		return fmt.Errorf("header: source %q, want %q", h.Source, n.Source)
	case h.SessionID != n.SessionID:
		return fmt.Errorf("header: session %s, want %s", h.SessionID, n.SessionID)
	case h.Version != version:
		return fmt.Errorf("header: version %d, want %d", h.Version, version)
	}
	return nil
}

// skippable reports, without decoding it, whether a snapshot record is a
// valid {"object": "<class>:…"} of a class the engine has no use for — what
// objectText and object would decide at a cost of microseconds and kilobytes
// per record, for most of a registry (persons, inetnums). It says false when
// unsure: a record of another shape is decoded in full.
func skippable(rec []byte) bool {
	const lead = `{"object":"`
	if !bytes.HasPrefix(rec, []byte(lead)) || bytes.Count(rec, []byte(`"object"`)) != 1 || bytes.Contains(rec, []byte(`\u`)) {
		return false // another spelling, another "object" key (the last wins), or an escaped one
	}
	class, _, ok := bytes.Cut(rec[len(lead):], []byte(":"))
	if !ok || len(class) == 0 {
		return false
	}
	for _, b := range class {
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-') {
			return false
		}
	}
	return !resolve.ExpandableClass(string(class)) && json.Valid(rec)
}

func objectText(rec []byte) (string, error) {
	m, err := jsonObject(rec)
	if err != nil {
		return "", err
	}
	return str(m, "object")
}

// publish makes the state visible as a new view; with changed false only the
// status moves.
func (c *Client) publish(changed bool) {
	if c.st.version == 0 {
		return
	}
	prev := c.view.Load()
	v := &view{status: Status{SessionID: c.st.session, Version: c.st.version, Timestamp: c.st.stamp,
		Stale: c.st.stale, Objects: c.st.corpus.Len(), CurrentKey: c.st.curPEM, NextKey: c.st.nextPEM}}
	if changed || prev == nil {
		v.src = c.st.corpus.Source()
	} else {
		v.src = prev.src
	}
	c.view.Store(v)
}

func (c *Client) maxFile() int64 {
	if c.MaxFileBytes > 0 {
		return c.MaxFileBytes
	}
	return DefaultMaxFileBytes
}

// resolve turns a URL from the notification file into one on the same scheme
// and host, relative to the notification file's path (§6.3).
func (c *Client) resolve(ref string) (string, error) {
	base, err := url.Parse(c.URL)
	if err != nil {
		return "", err
	}
	r, err := url.Parse(ref)
	if err != nil {
		return "", fmt.Errorf("url %q: %w", ref, err)
	}
	u := base.ResolveReference(r)
	if err := sameOrigin(base, u); err != nil {
		return "", err
	}
	return u.String(), nil
}

// sameOrigin refuses a URL on another scheme or host than base: what the
// notification file names, and every redirect — which is not signed.
func sameOrigin(base, u *url.URL) error {
	if u.Scheme != base.Scheme || u.Host != base.Host {
		return fmt.Errorf("%s leaves %s://%s", u.Redacted(), base.Scheme, base.Host)
	}
	return nil
}

// httpClient is the client files are fetched with, built once: Client.HTTP
// or a default, and either way unable to follow a redirect off the origin
// before the caller's own CheckRedirect has its say.
func (c *Client) httpClient() *http.Client {
	if c.hc != nil {
		return c.hc
	}
	hc := &http.Client{Timeout: 10 * time.Minute}
	if c.HTTP != nil {
		*hc = *c.HTTP
	}
	base, _ := url.Parse(c.URL)
	theirs := hc.CheckRedirect
	hc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if err := sameOrigin(base, req.URL); err != nil {
			return fmt.Errorf("refusing a redirect: %w", err)
		}
		if theirs != nil {
			return theirs(req, via)
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}
	c.hc = hc
	return hc
}

func (c *Client) decompress(u string, r io.Reader) (io.Reader, error) {
	if !strings.HasSuffix(strings.SplitN(u, "?", 2)[0], ".gz") {
		return &capReader{r: r, n: c.maxFile()}, nil
	}
	zr, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("gzip: %w", err)
	}
	return &capReader{r: zr, n: c.maxFile()}, nil
}

// capReader fails once more than n bytes are read, rather than truncating.
type capReader struct {
	r io.Reader
	n int64
}

func (c *capReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n -= int64(n)
	if c.n < 0 {
		return n, errors.New("file larger than MaxFileBytes")
	}
	return n, err
}

// fetch reads a whole file, at most max bytes.
func (c *Client) fetch(ctx context.Context, u string, max int64) ([]byte, error) {
	body, err := c.open(ctx, u)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	data, err := io.ReadAll(&capReader{r: body, n: max})
	if err != nil {
		return nil, err
	}
	return data, nil
}

// open opens u for reading, over HTTPS or from a local file, retrying
// transient failures — network errors and HTTP 5xx — with backoff (§5.5).
func (c *Client) open(ctx context.Context, u string) (io.ReadCloser, error) {
	pu, err := url.Parse(u)
	if err != nil {
		return nil, err
	}
	switch pu.Scheme {
	case "file":
		return os.Open(pu.Path)
	case "https":
	default:
		return nil, fmt.Errorf("url %s: NRTMv4 is served over HTTPS only (§11)", u)
	}
	hc := c.httpClient()
	var last error
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(1<<(attempt-1)) * retryUnit):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		resp, err := hc.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			last = err
			continue
		}
		if resp.StatusCode == http.StatusOK {
			return resp.Body, nil
		}
		resp.Body.Close()
		last = fmt.Errorf("%s: HTTP %s", u, resp.Status)
		if resp.StatusCode < 500 {
			return nil, last
		}
	}
	return nil, last
}

// retryUnit is the first wait before retrying a transient failure; it
// doubles with each attempt. minInterval is the least time between polls
// (§5.2). Tests shorten both.
var (
	retryUnit   = time.Second
	minInterval = time.Minute
)

// drain reads what follows the last record, so that the hash covers the
// whole file.
func drain(r io.Reader) error {
	_, err := io.Copy(io.Discard, r)
	return err
}

func hashes(h hash.Hash, want string) error {
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return fmt.Errorf("SHA-256 %s, but the notification file says %s", got, want)
	}
	return nil
}

// Run calls Sync every interval, at least a minute (§5.2), until ctx ends,
// and returns ctx's error. After a failed Sync it tries again after a minute,
// then doubles the wait with each further failure, up to interval. onError,
// when set, is told of each failure.
func (c *Client) Run(ctx context.Context, interval time.Duration, onError func(error)) error {
	if interval < minInterval {
		interval = minInterval
	}
	wait := time.Duration(0)
	failures := 0
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		if _, err := c.Sync(ctx); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if onError != nil {
				onError(err)
			}
			failures++
			wait = runWait(failures, interval)
			continue
		}
		failures = 0
		wait = runWait(0, interval)
	}
}

// runWait is how long Run waits after failures failed Syncs in a row: the
// interval after a success, and after a failure the minimum doubled with each
// further one, never below the minimum (§5.2) nor above the interval.
func runWait(failures int, interval time.Duration) time.Duration {
	if failures == 0 {
		return interval
	}
	w := minInterval
	for i := 1; i < failures && w < interval; i++ {
		w *= 2
	}
	return min(w, interval)
}
