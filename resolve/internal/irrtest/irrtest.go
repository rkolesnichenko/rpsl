// Package irrtest is an in-memory IRR for tests: RPSL objects from several
// sources, served over the IRRd query protocol and over whois the way an IRRd
// server answers them. It implements IRRd's membership rules itself — straight
// from the objects' attributes, not through the resolve package — so tests can
// hold the backends, and bgpq4, against an independent server.
//
// The IRRd port answers as IRRd 4.5.3 does, and is held to what a real IRRd
// 4.5.3 answered on a fixture (TestMatchesIRRd, against the goldens in
// resolve/testdata/irrd/golden): "!i<set>,1" resolves recursively and drops
// every member it cannot resolve (see Recursive), "!a" expands an as-set to
// its routes' prefixes (see ASetPrefixes), WithRPKI turns on IRRd 4's
// RPKI-aware mode, "!s-*" changes nothing, only "!q" closes ("q" is a
// RIPE-style query for the text "q"), and a command with no "!" is answered
// as IRRd 4 answers a RIPE-style whois query sent on the IRRd port (see
// ripeQuery). "!r", "!o", "!J" and the RIPE-style -l, -L, -M, -x, -t
// and -g are not implemented. The Whois listener is not IRRd: it models the
// RIPE Database's whois server.
package irrtest

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/types"
)

// DB is a set of RPSL objects, in load order.
type DB struct {
	objs     []entry
	extra    []string            // sources that exist without objects
	byKey    map[string][]int    // class + " " + key -> objects, in load order
	byPK     map[string][]int    // class + " " + pk -> objects, in load order
	ids      map[string]int      // class + " " + pk + " " + source -> the live object
	byOrigin map[types.ASN][]int // origin -> route and route6 objects
	claims   map[string][]int    // upper-case set name -> objects naming it in member-of

	// defaults are the sources the IRRd port serves when a connection has
	// selected none (IRRd's sources_default); nil: every source.
	defaults []string

	// unique identifies objects by class, primary key and source, as IRRd
	// does, so that a later one replaces an earlier one. It is off by
	// default: the random IRRs the engine's models draw hold such pairs, and
	// their oracles and MemSource keep both.
	unique bool

	rpki bool  // IRRd's RPKI-aware mode (WithRPKI)
	roas []ROA // the ROAs it imported

	noSerialRange bool // refuse "!j", as a server without it does (WithoutSerialRange)
	serialHangups int  // "!j" commands answered by hanging up; < 0: every one (WithSerialRangeHangups)
	legacyClasses bool // accept IRRd 2/3's !m class abbreviations (WithLegacyClasses)

	mu   sync.Mutex
	cmds []string
}

type entry struct {
	text   string // "" when loaded without it: obj.String() then
	obj    *ast.Object
	class  string
	key    string // upper-case
	pk     string // upper-case: IRRd's primary key (rpsl_pk)
	source string // upper-case
	pseudo bool   // a pseudo route object made from a ROA
	dead   bool   // replaced by a later object with the same identity
}

// New loads RPSL objects, one per text.
func New(texts ...string) *DB {
	db := &DB{byKey: map[string][]int{}, byPK: map[string][]int{}, ids: map[string]int{},
		byOrigin: map[types.ASN][]int{}, claims: map[string][]int{}}
	for _, text := range texts {
		o, _ := rpsl.ParseObject(text)
		db.Add(o, text)
	}
	return db
}

// Add loads one parsed object, whose text is text; "" saves memory, and the
// object's own String() is served instead.
func (db *DB) Add(o *ast.Object, text string) { db.add(o, text, false) }

func (db *DB) add(o *ast.Object, text string, pseudo bool) {
	if o.Class() == "" {
		return
	}
	src := ""
	if a, ok := o.GetFirst("source"); ok {
		src = strings.ToUpper(strings.TrimSpace(strings.SplitN(a.Value, "#", 2)[0]))
	}
	i := len(db.objs)
	if text != "" {
		text = strings.TrimRight(text, "\n") + "\n"
	}
	e := entry{text: text, obj: o, class: o.Class(),
		key: strings.ToUpper(strings.TrimSpace(o.Key())), source: src, pseudo: pseudo}
	e.pk = e.key
	if e.class == "person" || e.class == "role" {
		// IRRd's primary key of a person or role is its nic-hdl.
		if a, ok := o.GetFirst("nic-hdl"); ok {
			e.pk = strings.ToUpper(strings.TrimSpace(strings.SplitN(a.Value, "#", 2)[0]))
		}
	}
	if e.class == "route" || e.class == "route6" {
		if a, ok := o.GetFirst("origin"); ok {
			if as, err := types.ParseASN(strings.TrimSpace(a.Value)); err == nil {
				db.byOrigin[as] = append(db.byOrigin[as], i)
				// A route's primary key is its prefix, as IRRd prints it,
				// and its origin run together ("192.0.2.0/24AS65001").
				pfx := e.key
				if p, err := types.ParsePrefix(e.key); err == nil {
					pfx = p.String()
				}
				e.pk = strings.ToUpper(pfx) + as.String()
				// IRRd's pseudo route object of a ROA is keyed by its
				// maximum length too (RPSLObjectFromROA:
				// "192.0.2.0/24AS65001/ML24"), so a prefix and an origin
				// name none (golden rpki/pseudo).
				if a, ok := o.GetFirst("max-length"); ok && pseudo {
					e.pk += "/ML" + strings.TrimSpace(a.Value)
				}
			}
		}
	}
	if db.unique && !pseudo { // two ROAs may differ only in their max-length
		id := e.class + " " + e.pk + " " + e.source
		if old, ok := db.ids[id]; ok {
			db.objs[old].dead = true
		}
		db.ids[id] = i
	}
	db.objs = append(db.objs, e)
	db.byKey[e.class+" "+e.key] = append(db.byKey[e.class+" "+e.key], i)
	db.byPK[e.class+" "+e.pk] = append(db.byPK[e.class+" "+e.pk], i)
	for _, n := range items(o, "member-of") {
		n = strings.ToUpper(n)
		db.claims[n] = append(db.claims[n], i)
	}
}

// WithSources declares sources that exist even if no object is in them, as on
// a server configured with empty sources, and returns db.
func (db *DB) WithSources(names ...string) *DB {
	for _, n := range names {
		db.extra = append(db.extra, strings.ToUpper(n))
	}
	return db
}

// WithoutSerialRange makes the IRRd server refuse "!j" ('F'), as a server
// that does not implement it would, and returns db.
func (db *DB) WithoutSerialRange() *DB {
	db.noSerialRange = true
	return db
}

// WithSerialRangeHangups makes the IRRd server close the connection, answering
// nothing, on the first n "!j" commands, or on every one when n < 0 — as a
// server that does not know the command might — and returns db.
func (db *DB) WithSerialRangeHangups(n int) *DB {
	db.serialHangups = n
	return db
}

// WithLegacyClasses makes the IRRd server accept IRRd 2/3's "!m" class
// abbreviations — "an" (aut-num), "ir" (inet-rtr), "rt" (route, keyed
// "prefix-ASn") — which IRRd 4 answers D. IRRToolSet asks for aut-nums with
// "!man,ASn". It returns db.
func (db *DB) WithLegacyClasses() *DB {
	db.legacyClasses = true
	return db
}

// hangUpOnSerialRange reports whether this "!j" is to be answered by hanging
// up, counting it against WithSerialRangeHangups.
func (db *DB) hangUpOnSerialRange() bool {
	db.mu.Lock()
	defer db.mu.Unlock()
	switch {
	case db.serialHangups < 0:
		return true
	case db.serialHangups > 0:
		db.serialHangups--
		return true
	}
	return false
}

// serialRange answers "!j" as IRRd 4's handle_irrd_database_serial_range
// does: one line per source, "NAME:N:0-<serial>" (no journal kept; a source
// with no objects has no serial, "NAME:N:-"), for every source with "-*",
// and "NAME:X:Database unknown" for a named source the server lacks. The
// serial here is the source's object count.
func (db *DB) serialRange(arg string) string {
	known := db.sources()
	count := map[string]int{}
	for _, e := range db.objs {
		if !e.dead {
			count[e.source]++
		}
	}
	want := known
	if arg != "-*" {
		want = nil
		for _, s := range strings.Split(arg, ",") {
			want = append(want, strings.ToUpper(s))
		}
	}
	var lines, unknown []string
	for _, s := range want {
		switch {
		case !contains(known, s):
			unknown = append(unknown, s+":X:Database unknown")
		case count[s] > 0:
			lines = append(lines, fmt.Sprintf("%s:N:0-%d", s, count[s]))
		default:
			lines = append(lines, s+":N:-")
		}
	}
	return strings.Join(append(lines, unknown...), "\n")
}

// ROA is one ROA as IRRd 4 imports it from rpki.roa_source.
type ROA struct {
	Prefix    netip.Prefix // canonical
	ASN       types.ASN
	MaxLength int
	TA        string
}

// WithRPKI puts db in IRRd 4's RPKI-aware mode with roas, and returns db.
// Route and route6 objects that are RPKI invalid are suppressed from every
// answer — decided here as IRRd's validators.py decides it, not by package
// rpki, so that tests can hold one to the other — and each ROA is served as
// IRRd's pseudo route object from the source RPKI. Route objects in whois and
// "!m" answers carry IRRd's rpki-ov-state: line. Call it after the objects
// are loaded.
func (db *DB) WithRPKI(roas ...ROA) *DB {
	db.rpki = true
	db.roas = append(db.roas, roas...)
	db.extra = append(db.extra, "RPKI")
	for _, r := range roas {
		text := pseudoText(r)
		o, _ := rpsl.ParseObject(text)
		db.add(o, text, true)
	}
	return db
}

// pseudoText renders a ROA as IRRd's RPSLObjectFromROA does, with IRRd's
// default rpki.pseudo_irr_remarks.
func pseudoText(r ROA) string {
	class := "route"
	if r.Prefix.Addr().Is6() {
		class = "route6"
	}
	col := func(name, value string) string { return fmt.Sprintf("%-16s%s\n", name+":", value) }
	indent := strings.Repeat(" ", 16)
	return col(class, r.Prefix.String()) +
		col("descr", fmt.Sprintf("RPKI ROA for %s / AS%d", r.Prefix, uint32(r.ASN))) +
		col("remarks", fmt.Sprintf("This AS%d route object represents routing data retrieved", uint32(r.ASN))) +
		indent + "from the RPKI. This route object is the result of an automated\n" +
		indent + "RPKI-to-IRR conversion process performed by IRRd.\n" +
		col("max-length", strconv.Itoa(r.MaxLength)) +
		col("origin", fmt.Sprintf("AS%d", uint32(r.ASN))) +
		col("source", "RPKI  # Trust Anchor: "+r.TA)
}

// status is the RPKI state IRRd gives e — "valid", "invalid" or "not_found",
// as SingleRouteROAValidator.validate_route computes it — or "" when e has
// none: not in RPKI-aware mode, not a route, or a pseudo object.
func (db *DB) status(e entry) string {
	if !db.rpki || e.pseudo || e.class != "route" && e.class != "route6" {
		return ""
	}
	p, err := types.ParsePrefix(e.key)
	a, ok := e.obj.GetFirst("origin")
	if err != nil || !ok {
		return "not_found"
	}
	origin, err := types.ParseASN(strings.TrimSpace(a.Value))
	if err != nil {
		return "not_found"
	}
	p = p.Masked()
	covered := false
	for _, r := range db.roas { // ip_less_specific_or_exact
		if r.Prefix.Addr().Is4() != p.Addr().Is4() || r.Prefix.Bits() > p.Bits() || !r.Prefix.Contains(p.Addr()) {
			continue
		}
		covered = true
		if r.ASN != 0 && r.ASN == origin && p.Bits() <= r.MaxLength {
			return "valid"
		}
	}
	if covered {
		return "invalid"
	}
	return "not_found"
}

// visible reports whether IRRd serves e: suppressed and replaced objects are
// in no answer.
func (db *DB) visible(e entry) bool { return !e.dead && db.status(e) != "invalid" }

// text is e as the Whois listener serves it: in RPKI-aware mode a route
// object ends with its rpki-ov-state:.
func (db *DB) text(e entry) string {
	if st := db.status(e); st != "" {
		return e.String() + fmt.Sprintf("%-16s%s\n", "rpki-ov-state:", st)
	}
	return e.String()
}

// irrdText is e as the IRRd port serves it: its rpki-ov-state: as IRRd 4.5.3
// writes it ("not_found" with IRRd's comment), and password hashes replaced
// (removeAuthHashes).
func (db *DB) irrdText(e entry) string {
	t := e.String()
	if st := db.status(e); st != "" {
		if st == "not_found" {
			st += " # No ROAs found, or RPKI validation not enabled for source"
		}
		t += fmt.Sprintf("%-16s%s\n", "rpki-ov-state:", st)
	}
	return removeAuthHashes(t)
}

// authHash is IRRd's RE_PASSWORD_HASHES: a password hash scheme and the rest
// of its line, anywhere in the text, in any case.
var authHash = regexp.MustCompile(`(?i)(BCRYPT-PW|CRYPT-PW|MD5-PW)[^\n]+`)

// removeAuthHashes replaces each password hash as IRRd's remove_auth_hashes
// does before it answers ("auth: MD5-PW DummyValue  # Filtered for security").
func removeAuthHashes(s string) string {
	return authHash.ReplaceAllString(s, "${1} DummyValue  # Filtered for security")
}

// String returns the object's text.
func (e entry) String() string {
	if e.text != "" {
		return e.text
	}
	return strings.TrimRight(e.obj.String(), "\n") + "\n"
}

// Commands returns the IRRd commands received so far, in order.
func (db *DB) Commands() []string {
	db.mu.Lock()
	defer db.mu.Unlock()
	return append([]string(nil), db.cmds...)
}

func (db *DB) record(cmd string) {
	db.mu.Lock()
	db.cmds = append(db.cmds, cmd)
	db.mu.Unlock()
}

// sources returns the distinct sources, in load order.
func (db *DB) sources() []string {
	var out []string
	for _, e := range db.objs {
		if e.source != "" && !contains(out, e.source) {
			out = append(out, e.source)
		}
	}
	for _, s := range db.extra {
		if !contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// find returns the first object of class with key among the selected sources,
// in their priority order.
func (db *DB) find(sel []string, class, key string) (entry, bool) {
	return db.first(sel, db.byKey[class+" "+strings.ToUpper(key)])
}

// findPK is find by IRRd's primary key.
func (db *DB) findPK(sel []string, class, pk string) (entry, bool) {
	return db.first(sel, db.byPK[class+" "+strings.ToUpper(pk)])
}

// first returns the first visible object of idx among the selected sources,
// in their priority order (in load order when sel is empty).
func (db *DB) first(sel []string, idx []int) (entry, bool) {
	if len(sel) == 0 {
		for _, i := range idx {
			if db.visible(db.objs[i]) {
				return db.objs[i], true
			}
		}
	}
	for _, s := range sel {
		for _, i := range idx {
			if db.objs[i].source == s && db.visible(db.objs[i]) {
				return db.objs[i], true
			}
		}
	}
	return entry{}, false
}

// items returns the items of every name attribute of o, split at commas and
// line breaks as IRRd splits them (see ast.Attribute.List).
func items(o *ast.Object, name string) []string {
	var out []string
	for _, a := range o.GetAll(name) {
		for _, it := range a.List() {
			if it.Value != "" {
				out = append(out, it.Value)
			}
		}
	}
	return out
}

// Members answers "!i<set>" as IRRd does: the set's members: and mp-members:
// items, and — when the set has mbrs-by-ref — the key of every aut-num (for
// an as-set) or route/route6 (for a route-set) of the set's own source that
// names the set in member-of and is maintained by one of the mbrs-by-ref
// maintainers (or any, for ANY). Each member is IRRd's parsed value (see
// normalizeMember: "as65001" is "AS65001", a route-set's address without a
// length gets its host length, as rr.arin.net answers "206.197.238.0/32" for
// rs-HCHBNET's "206.197.238.0"), and they come sorted, each once. The set is
// taken from the first selected source that has it. ok is false when there
// is no such set.
func (db *DB) Members(sel []string, name string) (members []string, ok bool) {
	class := "as-set"
	if n, err := types.ParseSetName(name); err == nil && n.Class() == types.ClassRouteSet {
		class = "route-set"
	}
	set, ok := db.find(sel, class, name)
	if !ok {
		return nil, false
	}
	seen := map[string]bool{}
	add := func(m string) {
		m = normalizeMember(class, m)
		if !seen[m] {
			seen[m] = true
			members = append(members, m)
		}
	}
	for _, it := range append(items(set.obj, "members"), items(set.obj, "mp-members")...) {
		add(it)
	}
	if refs := items(set.obj, "mbrs-by-ref"); len(refs) > 0 {
		for _, i := range db.claims[strings.ToUpper(name)] {
			e := db.objs[i]
			if e.source != set.source || !db.visible(e) {
				continue
			}
			switch {
			case class == "as-set" && e.class == "aut-num":
			case class == "route-set" && (e.class == "route" || e.class == "route6"):
			default:
				continue
			}
			if !containsFold(items(e.obj, "member-of"), name) {
				continue
			}
			allowed := containsFold(refs, "ANY")
			for _, m := range items(e.obj, "mnt-by") {
				allowed = allowed || containsFold(refs, m)
			}
			if allowed {
				add(e.key)
			}
		}
	}
	sort.Strings(members)
	return members, true
}

// normalizeMember returns a member of a set of class as IRRd parses it: an AS
// number in its plain form ("as65002^24" is "AS65002^24"), a set name
// upper-cased, a prefix as netip prints it (in a route-set an address without
// a length gets its host length), anything else as written. A range operator
// is kept as written.
func normalizeMember(class, item string) string {
	base, op, hasOp := strings.Cut(item, "^")
	suffix := ""
	if hasOp {
		suffix = "^" + op
	}
	if as, err := types.ParseASN(base); err == nil {
		return as.String() + suffix
	}
	if _, err := types.ParseSetName(base); err == nil {
		return strings.ToUpper(base) + suffix
	}
	if class == "route-set" {
		base, _, _ = strings.Cut(withLength(item), "^")
	}
	if strings.Contains(base, "/") {
		if p, err := types.ParsePrefix(base); err == nil {
			return p.String() + suffix
		}
	}
	return item
}

// withLength returns item with the host length added when its prefix is an
// address without one ("192.0.2.1^+" is "192.0.2.1/32^+"), and unchanged
// otherwise.
func withLength(item string) string {
	base, op, hasOp := strings.Cut(item, "^")
	addr, err := types.ParseAddr(base)
	if err != nil || strings.Contains(base, "/") {
		return item
	}
	base += "/" + strconv.Itoa(addr.BitLen())
	if hasOp {
		base += "^" + op
	}
	return base
}

// Recursive answers "!i<set>,1" as IRRd's _recursive_set_resolve does: the
// set's members, resolved through nested sets, and only what resolves.
// Nested sets of the classes the set may include (as-sets in an as-set;
// route-sets and as-sets, at any depth, in a route-set) are resolved, each
// once, with their indirect members. In a route-set an AS number becomes the
// prefixes its route and route6 objects hold, and a prefix member stays as
// IRRd parsed it, range operator included; in an as-set an AS number stays an
// AS number. Everything else is dropped: a set that is not found (AS-ANY
// included), a set of a class the root may not include, a set or AS number
// with a range operator (IRRd looks "RS-INNER^25" up as a set name and finds
// none), a prefix in an as-set, junk. The members come sorted, each once. ok
// is false when the set itself is not found.
func (db *DB) Recursive(sel []string, name string) (members []string, ok bool) {
	root, err := types.ParseSetName(name)
	if err != nil {
		return nil, false
	}
	if _, ok := db.Members(sel, name); !ok {
		return nil, false
	}
	seen, out := map[string]bool{}, map[string]bool{}
	var walk func(set string)
	walk = func(set string) {
		if seen[strings.ToUpper(set)] {
			return
		}
		seen[strings.ToUpper(set)] = true
		ms, _ := db.Members(sel, set) // a set not found has no members
		for _, m := range ms {
			base, _, hasOp := strings.Cut(m, "^")
			if strings.Contains(base, "/") {
				if root.Class() == types.ClassRouteSet {
					out[m] = true
				}
				continue
			}
			if hasOp {
				continue // looked up as a set name, found nowhere
			}
			if as, err := types.ParseASN(m); err == nil {
				if root.Class() == types.ClassAsSet {
					out[as.String()] = true
					continue
				}
				for _, v6 := range []bool{false, true} {
					for _, p := range db.Routes(sel, as, v6) {
						out[p.String()] = true
					}
				}
				continue
			}
			if n, err := types.ParseSetName(m); err == nil &&
				(n.Class() == types.ClassAsSet || root.Class() == types.ClassRouteSet && n.Class() == types.ClassRouteSet) {
				walk(m)
			}
		}
	}
	walk(name)
	for m := range out {
		members = append(members, m)
	}
	sort.Strings(members)
	return members, true
}

// ASetPrefixes answers "!a<set>" as IRRd 4 does: the as-set resolved
// recursively to AS numbers ("!i<set>,1"), then the distinct prefixes those
// ASes originate, of family 4 or 6, or both for 0. ok is false when name is
// not an as-set of the selected sources — a route-set included, as IRRd looks
// the name up only among as-sets.
func (db *DB) ASetPrefixes(sel []string, name string, fam int) (prefixes []string, ok bool) {
	n, err := types.ParseSetName(name)
	if err != nil || n.Class() != types.ClassAsSet {
		return nil, false
	}
	members, ok := db.Recursive(sel, name)
	if !ok {
		return nil, false
	}
	seen := map[netip.Prefix]bool{}
	var out []netip.Prefix
	for _, m := range members {
		as, err := types.ParseASN(m)
		if err != nil {
			continue
		}
		for _, v6 := range []bool{false, true} {
			if fam == 4 && v6 || fam == 6 && !v6 {
				continue
			}
			for _, p := range db.Routes(sel, as, v6) {
				if !seen[p] {
					seen[p] = true
					out = append(out, p)
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if c := out[i].Addr().Compare(out[j].Addr()); c != 0 {
			return c < 0
		}
		return out[i].Bits() < out[j].Bits()
	})
	for _, p := range out {
		prefixes = append(prefixes, p.String())
	}
	return prefixes, true
}

// Routes answers "!g"/"!6": the distinct prefixes of the route (v4) or route6
// (v6) objects of the selected sources originated by as.
func (db *DB) Routes(sel []string, as types.ASN, v6 bool) []netip.Prefix {
	class := "route"
	if v6 {
		class = "route6"
	}
	seen := map[netip.Prefix]bool{}
	var out []netip.Prefix
	for _, i := range db.byOrigin[as] {
		e := db.objs[i]
		if e.class != class || len(sel) > 0 && !contains(sel, e.source) || !db.visible(e) {
			continue
		}
		p, err := types.ParsePrefix(e.key) // as IRRd reads route keys: padded or abbreviated IPv4 too
		if err != nil || seen[p.Masked()] {
			continue
		}
		seen[p.Masked()] = true
		out = append(out, p.Masked())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// IRRd serves db over the IRRd query protocol on a localhost port until the
// test ends, and returns its address. Like IRRd, it answers one command and
// closes unless the client sends "!!" first.
func (db *DB) IRRd(t testing.TB) string {
	t.Helper()
	return serve(t, db.irrdConn)
}

func (db *DB) irrdConn(c net.Conn) {
	br := bufio.NewReader(c)
	persistent := false
	var sel []string
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.TrimSpace(line) // IRRd strips each line; a blank one is no query
		if cmd == "" {
			continue
		}
		db.record(cmd)
		switch {
		case strings.Contains(cmd, "\x00"):
			fmt.Fprint(c, "F Queries may not contain null bytes\n")
		case strings.EqualFold(cmd, "!q"):
			return
		case strings.HasPrefix(cmd, "!"):
			if !db.irrdCommand(c, cmd[1:], &sel, &persistent) {
				return
			}
		default:
			// IRRd 4 answers a RIPE-style query on its IRRd port too.
			ans, keep := db.ripeQuery(&sel, cmd)
			fmt.Fprint(c, ans)
			persistent = persistent || keep
		}
		if !persistent {
			return
		}
	}
}

// current is the selection a connection's queries are answered from: the
// sources it selected, or else the server's default sources (nil: all).
func (db *DB) current(sel []string) []string {
	if len(sel) > 0 {
		return sel
	}
	return db.defaults
}

// irrdCommand answers one IRRd command, its "!" removed, as IRRd 4.5.3's
// handle_irrd_command does. It returns false when the connection is to close
// unanswered.
func (db *DB) irrdCommand(c net.Conn, full string, sel *[]string, persistent *bool) bool {
	if full == "" {
		fmt.Fprint(c, "F Missing IRRD command\n")
		return true
	}
	_, size := utf8.DecodeRuneInString(full)
	letter, param := full[:size], full[size:]
	if strings.Contains("tg6ijmnors", letter) && param == "" {
		fmt.Fprintf(c, "F Missing parameter for %s query\n", letter)
		return true
	}
	cur := db.current(*sel)
	switch letter {
	case "!":
		*persistent = true
	case "v":
		frame(c, "IRRd -- version 4.5.3") // IRRToolSet reads the version; it crashes on an answer without "version"
	case "n":
		fmt.Fprint(c, "C\n")
	case "s":
		switch param {
		case "-lc":
			list := cur
			if len(list) == 0 {
				list = db.sources()
			}
			frame(c, strings.Join(list, ","))
		case "-*":
			fmt.Fprint(c, "C\n") // IRRd 4.5.3 accepts it and changes nothing
		default:
			next := strings.Split(strings.ToUpper(param), ",")
			known := db.sources()
			for _, s := range next {
				if !contains(known, s) {
					fmt.Fprint(c, "F One or more selected sources are unavailable.\n")
					return true
				}
			}
			*sel = next
			fmt.Fprint(c, "C\n")
		}
	case "j":
		if db.hangUpOnSerialRange() {
			return false // the connection closes, unanswered
		}
		if db.noSerialRange {
			fmt.Fprintf(c, "F unsupported command %q\n", "!"+full)
		} else if ans := db.serialRange(param); ans == "" {
			fmt.Fprint(c, "C\n")
		} else {
			frame(c, ans)
		}
	case "i":
		var members []string
		var ok bool
		name := param
		if base, recursive := strings.CutSuffix(param, ",1"); recursive {
			name = base
			members, ok = db.Recursive(cur, base)
		} else {
			members, ok = db.Members(cur, param)
		}
		// IRRd's members_for_set (irrd/server/query_resolver.py) ends with
		// "if parameter in members: members.remove(parameter)": the set's
		// own name goes, but only as sent — "!iAS-SELF" drops a member
		// AS-SELF, "!ias-self" keeps it.
		for i, m := range members {
			if m == name {
				members = append(members[:i:i], members[i+1:]...)
				break
			}
		}
		if !ok || len(members) == 0 {
			fmt.Fprint(c, "D\n") // IRRd answers an empty set like a missing one
		} else {
			frame(c, strings.Join(members, " "))
		}
	case "a":
		name, fam := param, 0
		switch {
		case strings.HasPrefix(name, "4"):
			name, fam = name[1:], 4
		case strings.HasPrefix(name, "6"):
			name, fam = name[1:], 6
		}
		if name == "" {
			fmt.Fprint(c, "F Missing required set name for A query\n") // IRRd's words; bgpq4 probes with them
			break
		}
		if prefixes, ok := db.ASetPrefixes(cur, name, fam); !ok || len(prefixes) == 0 {
			fmt.Fprint(c, "D\n")
		} else {
			frame(c, strings.Join(prefixes, " "))
		}
	case "g", "6":
		as, err := parseIRRdASN(param)
		if err != "" {
			fmt.Fprintf(c, "F %s\n", err)
			break
		}
		var ps []string
		for _, p := range db.Routes(cur, as, letter == "6") {
			ps = append(ps, p.String())
		}
		if len(ps) == 0 {
			fmt.Fprint(c, "D\n")
		} else {
			frame(c, strings.Join(ps, " "))
		}
	case "m":
		class, key, ok := strings.Cut(param, ",")
		if !ok {
			fmt.Fprintf(c, "F Invalid argument for object lookup: %s\n", param)
			break
		}
		if db.legacyClasses {
			switch class {
			case "an":
				class = "aut-num"
			case "ir":
				class = "inet-rtr"
			case "rt":
				class = "route"
			}
		}
		if class == "route" || class == "route6" {
			// IRRd's handle_irrd_exact_key: "192.0.2.0/24 AS1" and
			// "192.0.2.0/24-AS1" name "192.0.2.0/24AS1".
			key = strings.NewReplacer(" ", "", "-", "").Replace(strings.ToUpper(key))
		}
		if e, ok := db.findPK(cur, class, key); ok {
			frame(c, strings.TrimRight(db.irrdText(e), "\n"))
		} else {
			fmt.Fprint(c, "D\n")
		}
	case "t":
		// IRRd's handle_irrd_timeout_update: 1 to 1000 seconds. irrtest
		// keeps no idle timeout, so a valid one changes nothing.
		if n, err := strconv.Atoi(param); err != nil || n < 1 || n > 1000 {
			fmt.Fprintf(c, "F Invalid value for timeout: %s\n", param)
		} else {
			fmt.Fprint(c, "C\n")
		}
	case "o", "r", "J":
		fmt.Fprintf(c, "F irrtest does not implement !%s\n", letter)
	default:
		if strings.EqualFold(full, "FNO-RPKI-FILTER") {
			fmt.Fprint(c, "F irrtest does not implement !fno-rpki-filter\n")
			break
		}
		fmt.Fprintf(c, "F Unrecognised command: %s\n", letter)
	}
	return true
}

// parseIRRdASN reads an AS number as IRRd's parse_as_number does: upper-cased
// first, so "as65001" is AS65001, then "AS" and decimal digits naming a 32-bit
// number. It returns IRRd's error text otherwise.
func parseIRRdASN(s string) (types.ASN, string) {
	v := strings.ToUpper(strings.TrimSpace(s))
	if !strings.HasPrefix(v, "AS") {
		return 0, fmt.Sprintf("Invalid AS number %s: must start with \"AS\"", v)
	}
	num := v[2:]
	if num == "" || strings.Trim(num, "0123456789") != "" {
		return 0, fmt.Sprintf("Invalid AS number %s: number part is not numeric", v)
	}
	n, err := strconv.ParseUint(num, 10, 32)
	if err != nil {
		return 0, fmt.Sprintf("Invalid AS number %s: valid range is 0-4294967295", v)
	}
	return types.ASN(n), ""
}

// frame writes an IRRd data response: "A<len>", the payload and its newline,
// then "C".
func frame(c net.Conn, payload string) {
	payload += "\n"
	fmt.Fprintf(c, "A%d\n%sC\n", len(payload), payload)
}

// Whois serves db over whois on a localhost port until the test ends, and
// returns its address. It reads a query as IRRd's whois parser does: flags left
// to right ("-s" sources, "-T" classes, "-r" ignored), and "-i attr value" ends
// the query; otherwise the last token is a primary key. Each query gets one
// answer, then the connection closes.
func (db *DB) Whois(t testing.TB) string {
	t.Helper()
	return serve(t, func(c net.Conn) {
		line, err := bufio.NewReader(c).ReadString('\n')
		if err != nil {
			return
		}
		fmt.Fprint(c, db.whoisAnswer(strings.Fields(line)))
	})
}

func (db *DB) whoisAnswer(tokens []string) string {
	var classes, sel []string
	var attr, value string
query:
	for i := 0; i < len(tokens); i++ {
		switch tokens[i] {
		case "-r", "-B", "-G":
		case "-T", "-s":
			if i+1 >= len(tokens) {
				return "%ERROR:106: no search key specified\n"
			}
			list := strings.Split(tokens[i+1], ",")
			if tokens[i] == "-T" {
				classes = list
			} else {
				for _, s := range list {
					sel = append(sel, strings.ToUpper(s))
				}
			}
			i++
		case "-i":
			if i+2 >= len(tokens) {
				return "%% ERROR: Missing argument for inverse query.\n"
			}
			attr, value = tokens[i+1], tokens[i+2]
			break query
		default:
			value = tokens[i]
		}
	}
	for _, s := range sel {
		if !contains(db.sources(), s) {
			return "%% ERROR: One or more selected sources are unavailable.\n" // IRRd's whois reply
		}
	}
	var out []string
	for _, e := range db.objs { // load order, not priority: the client picks
		if len(sel) > 0 && !contains(sel, e.source) || len(classes) > 0 && !containsFold(classes, e.class) || !db.visible(e) {
			continue
		}
		if attr == "" && strings.EqualFold(e.key, value) ||
			attr != "" && containsFold(items(e.obj, attr), value) {
			out = append(out, db.text(e))
		}
	}
	if len(out) == 0 {
		return "%ERROR:101: no entries found\n"
	}
	return "% irrtest\n\n" + strings.Join(out, "\n")
}

// inverseAttrs are the attributes IRRd 4.5.3 searches with -i, in the order
// it listed them when recorded (it lists a Python set).
var inverseAttrs = []string{"role", "mnt-by", "person", "origin", "members", "zone-c",
	"mp-members", "mbrs-by-ref", "member-of", "admin-c", "tech-c"}

// ripeQuery answers a RIPE-style query sent on the IRRd port, as IRRd 4.5.3's
// handle_ripe_command does: the line split at spaces and read left to right —
// -s selects sources for the rest of the connection (*sel), -a selects the
// default ones again, -T restricts the classes, -K writes only primary keys
// and members, -k keeps the connection open, -r, -F and -V change nothing,
// -i searches an attribute and ends the query, and any other word is a text
// search (the last one counts). The answer is the matching objects, or IRRd's
// "No entries" or "%% ERROR:" text, and two empty lines. keep reports -k.
func (db *DB) ripeQuery(sel *[]string, line string) (answer string, keep bool) {
	fail := func(msg string) (string, bool) { return "%% ERROR: " + msg + "\n\n\n", keep }
	comps := strings.Split(line, " ")
	var classes []string
	keysOnly := false
	var found []entry
	for len(comps) > 0 {
		comp := comps[0]
		comps = comps[1:]
		if !strings.HasPrefix(comp, "-") {
			found = db.textSearch(db.current(*sel), classes, comp)
			continue
		}
		flag := comp[1:]
		args := map[string]int{"i": 2, "s": 1, "T": 1, "V": 1}[flag]
		if len(comps) < args {
			return fail("Missing argument for flag/search: " + flag)
		}
		switch flag {
		case "k":
			keep = true
		case "K":
			keysOnly = true
		case "r", "F":
		case "V":
			comps = comps[1:]
		case "a":
			*sel = nil
		case "s":
			next := strings.Split(strings.ToUpper(comps[0]), ",")
			comps = comps[1:]
			for _, s := range next {
				if !contains(db.sources(), s) {
					return fail("One or more selected sources are unavailable.")
				}
			}
			*sel = next
		case "T":
			classes = strings.Split(comps[0], ",")
			comps = comps[1:]
		case "i":
			attr, value := comps[0], comps[1]
			if !contains(inverseAttrs, attr) {
				return fail("Inverse attribute search not supported for " + attr +
					",only supported for attributes: " + strings.Join(inverseAttrs, ", "))
			}
			found = db.inverseSearch(db.current(*sel), classes, attr, value)
			comps = nil // -i ends the query
		case "l", "L", "M", "x", "t", "g":
			return fail("irrtest does not implement -" + flag)
		default:
			return fail("Unrecognised flag/search: " + flag)
		}
	}
	if len(found) == 0 {
		return "%  No entries found for the selected source(s).\n\n\n", keep
	}
	var out []string
	for _, e := range found {
		var t string
		if keysOnly {
			t = keyFields(e)
		} else {
			t = db.irrdText(e)
		}
		if !keysOnly || !contains(out, t) { // IRRd lists each key block once
			out = append(out, t)
		}
	}
	return strings.Join(out, "\n") + "\n\n", keep
}

// wanted reports whether e is in an answer from the sources sel (all when
// empty) restricted to classes (all when empty).
func (db *DB) wanted(e entry, sel, classes []string) bool {
	return db.visible(e) && (len(sel) == 0 || contains(sel, e.source)) &&
		(len(classes) == 0 || contains(classes, e.class))
}

// textSearch is IRRd's text_search: for an AS number, the aut-num; for an
// address or prefix, the route and route6 objects of that prefix or a less
// specific one; otherwise the objects whose primary key is value, and the
// persons and roles of that name.
func (db *DB) textSearch(sel, classes []string, value string) []entry {
	var out []entry
	as, asErr := parseIRRdASN(value)
	p, pErr := types.ParsePrefix(value)
	if pErr != nil {
		if a, err := types.ParseAddr(value); err == nil {
			p, pErr = netip.PrefixFrom(a, a.BitLen()), nil
		}
	}
	for _, e := range db.objs {
		if !db.wanted(e, sel, classes) {
			continue
		}
		switch {
		case asErr == "":
			if e.class == "aut-num" {
				if a, err := types.ParseASN(e.key); err == nil && a == as {
					out = append(out, e)
				}
			}
		case pErr == nil:
			if e.class == "route" || e.class == "route6" {
				if q, err := types.ParsePrefix(e.key); err == nil && q.Addr().Is4() == p.Addr().Is4() &&
					q.Bits() <= p.Bits() && q.Masked().Contains(p.Addr()) {
					out = append(out, e)
				}
			}
		case e.pk == strings.ToUpper(value):
			out = append(out, e)
		case e.class == "person" || e.class == "role":
			if strings.EqualFold(strings.TrimSpace(e.obj.Key()), value) {
				out = append(out, e)
			}
		}
	}
	return out
}

// inverseSearch is IRRd's -i: the objects whose attr holds value.
func (db *DB) inverseSearch(sel, classes []string, attr, value string) []entry {
	var out []entry
	for _, e := range db.objs {
		if db.wanted(e, sel, classes) && containsFold(items(e.obj, attr), value) {
			out = append(out, e)
		}
	}
	return out
}

// keyFields is e as IRRd's -K writes it: its primary key attributes (a
// route's prefix and origin, a person's or role's nic-hdl) and each of its
// members: and mp-members: items, as IRRd parsed them.
func keyFields(e entry) string {
	var b strings.Builder
	switch e.class {
	case "route", "route6":
		pfx := e.key
		if p, err := types.ParsePrefix(e.key); err == nil {
			pfx = p.String()
		}
		fmt.Fprintf(&b, "%s: %s\n", e.class, pfx)
		if a, ok := e.obj.GetFirst("origin"); ok {
			origin := strings.TrimSpace(a.Value)
			if as, err := types.ParseASN(origin); err == nil {
				origin = as.String()
			}
			fmt.Fprintf(&b, "origin: %s\n", origin)
		}
	case "person", "role":
		fmt.Fprintf(&b, "nic-hdl: %s\n", e.pk)
	default:
		// IRRd writes parsed_data, which holds a set name, an inet-rtr's DNS
		// name and an AS number upper-case (their fields' keep_case is
		// False), a set name's AS components and an AS number canonical.
		key := strings.ToUpper(strings.TrimSpace(e.obj.Key()))
		if n, err := types.ParseSetName(key); err == nil {
			key = n.String()
		} else if as, err := types.ParseASN(key); err == nil && e.class == "aut-num" {
			key = as.String()
		}
		fmt.Fprintf(&b, "%s: %s\n", e.class, key)
	}
	for _, name := range []string{"members", "mp-members"} {
		// Every item, a repeated one too: IRRd's parsed_data keeps each
		// (IRRd 4.5.3's parser, asked directly: "members: AS1, as1" is
		// ['AS1', 'AS1']).
		for _, it := range items(e.obj, name) {
			fmt.Fprintf(&b, "%s: %s\n", name, normalizeMember(e.class, it))
		}
	}
	return b.String()
}

// serve accepts connections on a localhost listener until the test ends.
func serve(t testing.TB, handle func(net.Conn)) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("irrtest: listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				handle(c)
			}()
		}
	}()
	return ln.Addr().String()
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func containsFold(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(strings.TrimSpace(x), strings.TrimSpace(s)) {
			return true
		}
	}
	return false
}
