package resolve

import (
	"net/netip"
	"sort"
	"strings"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/lexer"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/types"
)

// Corpus holds IRR objects the way the engine uses them. Sets, and the
// objects that claim membership of a set (member-of:), are kept whole: GetSet
// and MembersByRef return them. Every other route and route6 is kept as its
// prefix, origin and source, all that OriginatedRoutes needs of it; aut-nums
// and inet-rtrs that claim nothing, and every other class, are not kept at
// all. For the RIPE Database that is about a tenth of the memory the decoded
// objects take.
//
// An object is identified by its class, its primary key and its source, so a
// later object replaces an earlier one with the same identity — as an NRTM
// update does — whether either is kept whole, reduced or not at all.
//
// The zero value is empty and ready to use. A Corpus is not safe for
// concurrent mutation; a MemSource built from it (Source, SourceOf) is
// immutable and unaffected by later changes.
type Corpus struct {
	// KeepPolicy keeps every aut-num and inet-rtr, as its text, so that a
	// MemSource built from the corpus is a PolicySource that serves them (an
	// aut-num costs 2.5 KB as text, 18 KB decoded: RIPE's 39,918 take 95 MB).
	// Set it before the first Put. Without it only those that claim membership
	// of a set are kept, and a MemSource built from the corpus answers AutNum
	// and InetRtr with ErrNoPolicy rather than serve that partial subset.
	KeepPolicy bool

	// IndexPeers keeps, for every aut-num, the AS numbers its import, export
	// and default peerings name, so that a MemSource built from the corpus
	// is a PolicyIndex whose NamedBy answers (otherwise ErrNoIndex). It
	// implies KeepPolicy. Only AS numbers are kept, never the decoded
	// policies. Set it before the first Put. A DumpLoader copies its own
	// IndexPeers onto its Corpus at each Read, so a caller merging into a
	// loader's Corpus before any Read sets Corpus.IndexPeers itself.
	IndexPeers bool

	whole   map[wholeKey]held
	routes  map[routeKey]struct{}
	sources map[string]string // upper-case source name -> the one copy kept
	seq     uint64
}

// wholeKey identifies a whole object: its class, canonical primary key and
// upper-case source.
type wholeKey struct{ class, pk, source string }

// routeKey is a reduced route: identity and content at once.
type routeKey struct {
	prefix netip.Prefix // canonical
	origin types.ASN
	source string // upper-case
}

type held struct {
	obj   object.Object
	text  string      // an aut-num or inet-rtr kept as text (KeepPolicy); obj is nil then
	named []types.ASN // an aut-num kept as text, with IndexPeers: the ASes its peerings name
	key   wholeKey
	seq   uint64 // load order: MemSource's ties go to the object loaded first
}

// keepPolicy reports whether aut-nums and inet-rtrs are kept whole or as
// text: KeepPolicy, or IndexPeers, which implies it.
func (c *Corpus) keepPolicy() bool { return c.KeepPolicy || c.IndexPeers }

// Put keeps what the engine needs of o, replacing any object with its class,
// primary key and source. It reports whether anything of o is kept; when
// nothing is, an earlier object with its identity is still removed.
func (c *Corpus) Put(o object.Object) bool {
	o = value(o)
	if o == nil {
		return false
	}
	c.init()
	if s, ok := o.(object.NamedSet); ok {
		c.putWhole(wholeKey{o.Class(), s.SetName().String(), c.intern(s.SetSource())}, o)
		return true
	}
	// What claims membership is what MembersByRef would return: the engine's
	// own rule (claimant), so that the two cannot disagree.
	memberOf, _, _, claims := claimant(o)
	var class, pk, source string
	switch t := o.(type) {
	case object.Route:
		class, source = "route", t.Source
	case object.Route6:
		class, source = "route6", t.Source
	case object.AutNum:
		if !claims {
			return false // its AS did not decode: no key, and nothing the engine reads
		}
		class, pk, source = "aut-num", t.AS.String(), t.Source
	case object.InetRtr:
		class, pk, source = "inet-rtr", strings.ToUpper(strings.TrimSpace(t.Name)), t.Source
	default:
		return false
	}
	prefix, origin, route := routeOf(o) // a route the engine indexes
	rk := routeKey{prefix, origin, ""}
	if class == "route" || class == "route6" {
		if route {
			pk = rk.pk()
		} else {
			pk = rawRouteKey(o) // a route no AS originates, known by its text
		}
	}
	if pk == "" {
		return false
	}
	src := c.intern(source)
	k := wholeKey{class, pk, src}
	if route {
		rk.source = src
		delete(c.routes, rk)
	}
	if claims && len(memberOf) > 0 {
		c.putWhole(k, o)
		return true
	}
	if c.keepPolicy() && (class == "aut-num" || class == "inet-rtr") {
		if raw := o.Raw(); raw != nil {
			var named []types.ASN
			if an, ok := o.(object.AutNum); ok && c.IndexPeers {
				named = peeringASNs(an)
			}
			c.putText(k, textFrom(raw), named)
		} else {
			c.putWhole(k, o) // built by hand: no text to keep
		}
		return true
	}
	delete(c.whole, k)
	if route {
		c.routes[rk] = struct{}{}
		return true
	}
	return false
}

// rawRouteKey is the identity of a route whose prefix or origin did not
// decode: its primary key as written, upper-case — as Delete falls back to.
func rawRouteKey(o object.Object) string {
	raw := o.Raw()
	if raw == nil {
		return ""
	}
	a, ok := raw.GetFirst("origin")
	if !ok {
		return ""
	}
	return strings.ToUpper(strings.TrimSpace(raw.Key()) + strings.TrimSpace(a.Value))
}

// pk is a route's primary key: its prefix and origin run together, the one
// spelling Put, Delete and Merge share.
func (rk routeKey) pk() string { return rk.prefix.String() + rk.origin.String() }

func (c *Corpus) init() {
	if c.whole == nil {
		c.whole, c.routes, c.sources = map[wholeKey]held{}, map[routeKey]struct{}{}, map[string]string{}
	}
}

// putWhole holds o whole under k. A replacement keeps its place in load order,
// by which MemSource breaks ties between sources: an update is not a new load.
func (c *Corpus) putWhole(k wholeKey, o object.Object) {
	if h, ok := c.whole[k]; ok {
		c.whole[k] = held{obj: o, key: k, seq: h.seq}
		return
	}
	c.seq++
	c.whole[k] = held{obj: o, key: k, seq: c.seq}
}

// textFrom returns raw's serialized text starting at its first attribute
// line, dropping the blank, comment and malformed lines the stream attached
// before the object (ast.Object owns them so the *stream's* own round-trip
// stays byte-exact; see rpsl.ParseWith). A Corpus entry kept as text is later
// re-decoded on its own (rpsl.ParseObject, in MemSource.AutNum/InetRtr), so
// keeping that leading trivia would shift every attribute's re-decoded line
// by the trivia's own line count.
//
// The scan uses the same line rule the streamer itself splits objects by
// (lexer.StartsAttribute — a blank line, a comment, and a malformed line all
// fail it and are trivia the stream can attach ahead of an object), not a
// content search: a leading comment can quote the object's first line
// verbatim ("# aut-num: AS1" followed by the real "aut-num: AS1"), which a
// strings.Index on the attribute's raw bytes would match inside the comment
// itself, understating how much trivia to drop.
func textFrom(raw *ast.Object) string {
	text := raw.String()
	rest, off := text, 0
	for len(rest) > 0 {
		line, eol := rest, len(rest)
		if nl := strings.IndexByte(rest, '\n'); nl >= 0 {
			line, eol = rest[:nl], nl+1
		}
		if lexer.StartsAttribute(strings.TrimSuffix(line, "\r")) {
			return text[off:]
		}
		off += eol
		rest = rest[eol:]
	}
	return text
}

// putText is putWhole for an object kept as its text.
func (c *Corpus) putText(k wholeKey, text string, named []types.ASN) {
	if h, ok := c.whole[k]; ok {
		c.whole[k] = held{text: text, named: named, key: k, seq: h.seq}
		return
	}
	c.seq++
	c.whole[k] = held{text: text, named: named, key: k, seq: c.seq}
}

// intern returns the one copy of a source name the corpus keeps, upper-case:
// a substring of an object's text would keep the whole text alive.
func (c *Corpus) intern(source string) string {
	up := strings.ToUpper(strings.TrimSpace(source))
	if s, ok := c.sources[up]; ok {
		return s
	}
	s := strings.Clone(up)
	c.sources[s] = s
	return s
}

// Delete removes the object of class with primaryKey and source, as an NRTM
// delete names it — the key as RFC 2622 defines it, a route's prefix and
// origin run together ("192.0.2.0/24AS64500") — compared in canonical form,
// so "2001:DB8::/32as1" is "2001:db8::/32AS1". It reports whether there was
// one.
func (c *Corpus) Delete(class, primaryKey, source string) bool {
	if c.whole == nil {
		return false
	}
	class = strings.ToLower(strings.TrimSpace(class))
	src := strings.ToUpper(strings.TrimSpace(source))
	pk, ok := canonicalKey(class, primaryKey)
	if !ok {
		pk = strings.ToUpper(strings.TrimSpace(primaryKey)) // as rawRouteKey keeps such a route
	}
	k := wholeKey{class, pk, src}
	if _, found := c.whole[k]; found {
		delete(c.whole, k)
		return true
	}
	if p, a, ok := splitRouteKey(primaryKey); ok && (class == "route" || class == "route6") {
		rk := routeKey{p, a, src}
		if _, found := c.routes[rk]; found {
			delete(c.routes, rk)
			return true
		}
	}
	return false
}

// canonicalKey returns a class's primary key in the form Put keys objects by.
func canonicalKey(class, pk string) (string, bool) {
	pk = strings.TrimSpace(pk)
	switch class {
	case "route", "route6":
		p, a, ok := splitRouteKey(pk)
		if !ok {
			return "", false
		}
		return routeKey{p, a, ""}.pk(), true
	case "aut-num":
		a, err := types.ParseASN(pk)
		return a.String(), err == nil
	case "as-set", "route-set", "rtr-set", "filter-set", "peering-set":
		n, err := types.ParseSetName(pk)
		return n.String(), err == nil
	case "inet-rtr":
		return strings.ToUpper(pk), pk != ""
	}
	return "", false
}

// splitRouteKey reads a route's primary key: its prefix and origin run
// together, the origin from the last "AS" (in either case). The prefix is
// kept as written, host bits and all, as the decoder keeps a route's.
func splitRouteKey(pk string) (netip.Prefix, types.ASN, bool) {
	i := lastIndexAS(pk)
	if i <= 0 {
		return netip.Prefix{}, 0, false
	}
	p, perr := types.ParsePrefix(strings.TrimSpace(pk[:i]))
	a, aerr := types.ParseASN(pk[i:])
	if perr != nil || aerr != nil {
		return netip.Prefix{}, 0, false
	}
	return p, a, true
}

// lastIndexAS returns the byte offset of the last "AS", in either case, in s
// itself — not in an upper-cased copy, whose offsets differ where upper-casing
// lengthens a character — or -1.
func lastIndexAS(s string) int {
	for i := len(s) - 2; i >= 0; i-- {
		if s[i]|0x20 == 'a' && s[i+1]|0x20 == 's' {
			return i
		}
	}
	return -1
}

// Merge adds other's objects, after this corpus's own in load order; an
// object with the identity of one already here replaces it. other is not
// changed.
func (c *Corpus) Merge(other *Corpus) {
	if other == nil || other.whole == nil {
		return
	}
	c.init()
	for _, h := range other.ordered(nil) {
		if h.obj != nil {
			c.Put(h.obj) // re-derived, so a whole route replaces a reduced one here
			continue
		}
		// A policy entry kept as text (KeepPolicy): no object to re-derive from,
		// so its held value is copied as it is — but only when this corpus
		// itself keeps policy text; otherwise it is what Put would do with the
		// non-claiming aut-num or inet-rtr the text represents: dropped, and
		// any earlier object of its identity removed.
		k := h.key
		k.source = c.intern(k.source)
		if c.keepPolicy() {
			named := h.named
			if named == nil && c.IndexPeers && k.class == "aut-num" {
				named = namedFromText(h.text) // other kept no index: derive it once, here
			}
			c.putText(k, h.text, named)
		} else {
			delete(c.whole, k)
		}
	}
	for rk := range other.routes {
		rk.source = c.intern(rk.source)
		delete(c.whole, wholeKey{routeClass(rk.prefix), rk.pk(), rk.source})
		c.routes[rk] = struct{}{}
	}
}

func routeClass(p netip.Prefix) string {
	if p.Addr().Is4() {
		return "route"
	}
	return "route6"
}

// ordered returns the whole objects in load order, those whose source keep
// accepts (nil: all).
func (c *Corpus) ordered(keep func(source string) bool) []held {
	out := make([]held, 0, len(c.whole))
	for _, h := range c.whole {
		if keep == nil || keep(h.key.source) {
			out = append(out, h)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].seq < out[j].seq })
	return out
}

// Len returns the number of objects held, whole or reduced.
func (c *Corpus) Len() int { return len(c.whole) + len(c.routes) }

// Source builds a MemSource over the corpus: the one NewMemSource builds
// over the same objects, with the same source precedence.
func (c *Corpus) Source(sourcePrecedence ...string) *MemSource {
	return c.build(nil, sourcePrecedence)
}

// SourceOf builds a MemSource whose unscoped lookups and routes see only the
// objects of the given sources (compared without regard to case), in the
// precedence given; an object without a source: is left out of them. A scoped
// lookup (RIPE::AS-FOO) and the claims of a set it finds see every source the
// corpus holds, as bgpq4's -S list does not limit a SOURCE:: object. It is
// DumpLoader.SourceOf's meaning.
func (c *Corpus) SourceOf(sources ...string) *MemSource {
	want := map[string]bool{}
	for _, s := range sources {
		want[strings.ToUpper(strings.TrimSpace(s))] = true
	}
	return c.build(func(s string) bool { return s != "" && want[s] }, sources)
}

func (c *Corpus) build(dflt func(string) bool, precedence []string) *MemSource {
	hs := c.ordered(nil) // every source: scoped lookups and claims see them all
	objs := make([]object.Object, 0, len(hs))
	for _, h := range hs {
		if h.obj != nil {
			objs = append(objs, h.obj)
		}
	}
	s := newMemSource(objs, precedence, dflt)
	// Policy entries (aut-num, inet-rtr) tie-break by this corpus's own load
	// order across whole and text-kept copies alike — never whole-before-text,
	// which newMemSource's own pass over the whole-only objs would give — so
	// rebuild them from every held entry, in seq order. Every entry that
	// reaches c.whole under the aut-num or inet-rtr class already has a valid
	// key (Put's own gating), so no further check is needed here; addPolicy
	// ignores every other class.
	s.autnums = map[types.ASN][]policyEntry{}
	s.rtrs = map[string][]policyEntry{}
	// Without KeepPolicy (or IndexPeers, which implies it) the corpus holds
	// only the aut-nums and inet-rtrs that claim membership of a set: a
	// policy lookup over them would be a partial answer posing as a whole
	// one, so the MemSource serves none (ErrNoPolicy).
	s.policy = c.keepPolicy()
	s.index = c.IndexPeers
	for _, h := range hs {
		s.addPolicy(h.key.class, h.key.pk, h.key.source, h.obj, h.text, h.named)
	}
	s.finish()
	for rk := range c.routes {
		if dflt == nil || dflt(rk.source) {
			s.routes[rk.origin] = append(s.routes[rk.origin], rk.prefix)
		}
	}
	// A map has no order: sort each AS's routes, so that every build of the
	// same corpus answers alike.
	for _, ps := range s.routes {
		sort.Slice(ps, func(i, j int) bool { return prefixLess(ps[i], ps[j]) })
	}
	return s
}
