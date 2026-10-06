package resolve_test

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/internal/routemodel"
	"github.com/rkolesnichenko/rpsl/types"
)

// NormalizeFilter against a brute-force model: random filters over the random
// IRRs of model_test.go — prefix lists, AS numbers, sets, PeerAS, AS-path
// regexps, community tests, filter-sets, AND, OR, NOT, range operators — are
// decided route by route from the model, and the normal form must accept
// exactly those routes. The model's regexps are matched by their own Go
// translation, from the model's AS numbers and set members, never from parsed
// text or engine code.

var modelCommunities = []string{"1:1", "1:2", "65000:3"}

var modelOps = []string{"", "", "", "", "^+", "^-", "^30", "^31-32", "^127-128", "^126"}

// pfxOp adapts a drawn operator to p itself (RFC 2622 §2): its window must lie
// within [p.Bits(), p's family's bit length]. Unlike an operator on an AS or
// set reference (parsed detached from any prefix, so any n<=m<=128 is
// syntactically valid — RangeOperator carries no prefix to check against), one
// written directly on a literal prefix inside "{...}" is parsed by
// types.ParsePrefixRange, which rejects a window outside that prefix's own
// family. modelOps mixes IPv4- and IPv6-length windows for exactly that
// AS/set-reference use, so on a literal prefix an incompatible draw (an IPv6
// window on a v4 prefix, or vice versa, or a length below the prefix's own)
// falls back to no operator, without drawing any further randomness.
func pfxOp(op string, p netip.Prefix) string {
	if op == "" || op == "^+" || op == "^-" {
		return op
	}
	lo, hi := p.Bits(), p.Addr().BitLen()
	var n, m int
	if _, err := fmt.Sscanf(op, "^%d-%d", &n, &m); err != nil {
		fmt.Sscanf(op, "^%d", &n)
		m = n
	}
	if n < lo || m > hi {
		return ""
	}
	return op
}

// samplePrefixes are the routes the model tests offer a filter: every prefix
// of the model's universes, and three from outside them.
var samplePrefixes = append(append(moreSpecifics(v4Universe, 29, 32), moreSpecifics(v6Universe, 126, 128)...),
	netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8::/32"))

// templateSet is the as-set a filter's set template names for peer:
// AS65001:AS-T:AS<peer>.
func templateSet(peer types.ASN) string {
	return fmt.Sprintf("%s:AS-T:%s", types.ASN(firstAS), peer)
}

// withTemplateSets adds, for each AS of the model, the as-set its set template
// names (templateSet), holding one or two of the model's AS numbers, so that
// AS65001:AS-T:PeerAS denotes something for every peer a test may bind.
func withTemplateSets(r *rand.Rand, m model) model {
	for a := firstAS; a < firstAS+4; a++ {
		s := &mSet{name: templateSet(types.ASN(a)), class: types.ClassAsSet, source: "RIPE"}
		for n := 1 + r.IntN(2); n > 0; n-- {
			as := types.ASN(firstAS + r.IntN(4))
			s.members = append(s.members, mMember{kind: "as", as: as, text: as.String()})
		}
		m.sets = append(m.sets, s)
	}
	return m
}

type mFilter struct {
	kind string // "any", "pfx", "as", "set", "peer", "re", "comm", "fltr", "tmpl", "and", "or", "not"
	pfx  netip.Prefix
	as   types.ASN
	set  string // a set name, or a filter-set name
	op   string
	re   *mRE
	comm []string
	eq   bool
	subs []*mFilter
}

func (f *mFilter) text() string {
	switch f.kind {
	case "any":
		return "ANY"
	case "pfx":
		return "{" + f.pfx.String() + f.op + "}"
	case "as":
		return f.as.String() + f.op
	case "set":
		return f.set + f.op
	case "peer":
		return "PeerAS" + f.op
	case "re":
		return "<" + f.re.text() + ">"
	case "comm":
		if f.eq {
			return "community == {" + strings.Join(f.comm, ", ") + "}"
		}
		return "community(" + strings.Join(f.comm, ", ") + ")"
	case "fltr":
		return f.set
	case "tmpl":
		return fmt.Sprintf("%s:AS-T:PeerAS", types.ASN(firstAS)) + f.op
	case "not":
		return "NOT (" + f.subs[0].text() + ")"
	case "and":
		return "(" + f.subs[0].text() + ") AND (" + f.subs[1].text() + ")"
	}
	return "(" + f.subs[0].text() + ") OR (" + f.subs[1].text() + ")"
}

type mRE struct {
	kind             string // "asn", "set", "any", "peer", "tmpl", "start", "end", "class", "seq", "alt", "star", "plus", "opt", "samestar", "sameplus", "samerange"
	as               types.ASN
	set              string
	cls              []types.ASN
	neg              bool   // class: "[^...]" (RFC 2622 §5.4)
	clsSet           string // class: an extra as-set item, as the parser also accepts ("" if none)
	clsAny           bool   // class: an extra '.' item
	sameMin, sameMax int    // samerange: the "~{m,n}" bounds
	subs             []*mRE
}

func (m *mRE) text() string {
	switch m.kind {
	case "asn":
		return m.as.String()
	case "set":
		return m.set
	case "any":
		return "."
	case "peer":
		return "PeerAS"
	case "tmpl":
		return fmt.Sprintf("%s:AS-T:PeerAS", types.ASN(firstAS))
	case "start":
		return "^"
	case "end":
		return "$"
	case "class":
		parts := make([]string, len(m.cls))
		for i, a := range m.cls {
			parts[i] = a.String()
		}
		if m.clsSet != "" {
			parts = append(parts, m.clsSet)
		}
		if m.clsAny {
			parts = append(parts, ".")
		}
		open := "["
		if m.neg {
			open = "[^"
		}
		return open + strings.Join(parts, " ") + "]"
	case "seq":
		parts := make([]string, len(m.subs))
		for i, s := range m.subs {
			parts[i] = s.text()
		}
		return strings.Join(parts, " ")
	case "alt":
		return "(" + m.subs[0].text() + " | " + m.subs[1].text() + ")"
	case "star":
		return "(" + m.subs[0].text() + ")*"
	case "plus":
		return "(" + m.subs[0].text() + ")+"
	case "samestar":
		return "(" + m.subs[0].text() + ")~*"
	case "sameplus":
		return "(" + m.subs[0].text() + ")~+"
	case "samerange":
		return fmt.Sprintf("(%s)~{%d,%d}", m.subs[0].text(), m.sameMin, m.sameMax)
	}
	return "(" + m.subs[0].text() + ")?"
}

// goRE is the model's own reading of the regexp, over "<n>" tokens. path is
// the route's AS path: a negated class ("[^...]") and a same-AS repetition
// ("~*", "~+", "~{m,n}") have no finite denotation on their own — RE2 (Go's
// regexp engine) has no negative lookahead to express "not one of these", and
// "the same AS, repeated" is not a regular property over an unbounded alphabet
// — so both are instead resolved against the finite set of ASes this one path
// actually carries, exactly as routemodel.MatchPath does over its own
// "universe" (see routemodel.go's builder.single/members): an AS the path
// never carries can never make the match differ, so restricting to the path's
// own ASes is not an approximation, only a finite way to say the same thing.
func (m *mRE) goRE(o *oracle, peer types.ASN, path []types.ASN) string {
	tok := func(a types.ASN) string { return fmt.Sprintf("<%d>", uint32(a)) }
	alt := func(as []types.ASN) string {
		if len(as) == 0 {
			return "(?:<never>)"
		}
		parts := make([]string, len(as))
		for i, a := range as {
			parts[i] = tok(a)
		}
		return "(?:" + strings.Join(parts, "|") + ")"
	}
	switch m.kind {
	case "asn":
		return tok(m.as)
	case "set":
		return alt(o.asns(m.set))
	case "any":
		return `<\d+>`
	case "peer":
		return tok(peer)
	case "tmpl":
		return alt(o.asns(templateSet(peer)))
	case "start":
		return "^"
	case "end":
		return "$"
	case "class":
		if !m.neg {
			if m.clsAny {
				return `<\d+>`
			}
			members := append([]types.ASN(nil), m.cls...)
			if m.clsSet != "" {
				members = append(members, o.asns(m.clsSet)...)
			}
			return alt(members)
		}
		return alt(sameMembers(m, o, peer, path))
	case "seq":
		var b strings.Builder
		for _, s := range m.subs {
			b.WriteString(s.goRE(o, peer, path))
		}
		return "(?:" + b.String() + ")"
	case "alt":
		return "(?:" + m.subs[0].goRE(o, peer, path) + "|" + m.subs[1].goRE(o, peer, path) + ")"
	case "star":
		return "(?:" + m.subs[0].goRE(o, peer, path) + ")*"
	case "plus":
		return "(?:" + m.subs[0].goRE(o, peer, path) + ")+"
	case "samestar":
		return sameAlt(sameMembers(m.subs[0], o, peer, path), "*", true)
	case "sameplus":
		return sameAlt(sameMembers(m.subs[0], o, peer, path), "+", false)
	case "samerange":
		q := fmt.Sprintf("{%d,%d}", m.sameMin, m.sameMax)
		if m.sameMin == m.sameMax {
			q = fmt.Sprintf("{%d}", m.sameMin)
		}
		return sameAlt(sameMembers(m.subs[0], o, peer, path), q, m.sameMin == 0)
	}
	return "(?:" + m.subs[0].goRE(o, peer, path) + ")?"
}

// atomMatchesAS reports whether the single-AS atom m (an "asn", "any",
// "peer", "set", "tmpl" or "class" mRE — never "alt"/"seq"/a quantifier)
// accepts a, straight from the model (o.asns, the literal peer and AS
// values), never from parsed text or engine code.
func atomMatchesAS(m *mRE, o *oracle, peer, a types.ASN) bool {
	switch m.kind {
	case "asn":
		return a == m.as
	case "any":
		return true
	case "peer":
		return a == peer
	case "set":
		return containsASN(o.asns(m.set), a)
	case "tmpl":
		return containsASN(o.asns(templateSet(peer)), a)
	case "class":
		in := containsASN(m.cls, a) || m.clsAny || (m.clsSet != "" && containsASN(o.asns(m.clsSet), a))
		return in != m.neg
	}
	return false
}

// sameMembers returns path's distinct ASes that the single-AS atom inner
// matches: the finite domain a negated class or a same-AS repetition ranges
// over (see goRE's doc comment).
func sameMembers(inner *mRE, o *oracle, peer types.ASN, path []types.ASN) []types.ASN {
	var out []types.ASN
	for _, a := range distinctASNs(path) {
		if atomMatchesAS(inner, o, peer, a) {
			out = append(out, a)
		}
	}
	return out
}

// sameAlt builds the Go-regex alternation for a same-AS repetition: each
// matching AS repeated by itself under q, plus the empty alternative when the
// quantifier admits zero repetitions (RFC 2622 §5.4: "~*", "~+", "~{m,n}"
// require every repetition to be the identical AS).
func sameAlt(as []types.ASN, q string, allowEmpty bool) string {
	var alts []string
	for _, a := range as {
		alts = append(alts, fmt.Sprintf("(?:<%d>)", uint32(a))+q)
	}
	if allowEmpty {
		alts = append(alts, "")
	}
	if len(alts) == 0 {
		return "(?:<never>)"
	}
	return "(?:" + strings.Join(alts, "|") + ")"
}

func containsASN(list []types.ASN, a types.ASN) bool {
	for _, x := range list {
		if x == a {
			return true
		}
	}
	return false
}

func distinctASNs(path []types.ASN) []types.ASN {
	seen := map[types.ASN]bool{}
	var out []types.ASN
	for _, a := range path {
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}

func encodePath(path []types.ASN) string {
	var b strings.Builder
	for _, a := range path {
		fmt.Fprintf(&b, "<%d>", uint32(a))
	}
	return b.String()
}

type mFltr struct {
	name string
	f    *mFilter
}

type filterGen struct {
	r      *rand.Rand
	o      *oracle
	sets   []string // set names a filter may name: the model's (none reaching AS-ANY) and one missing
	asSets []string // as-set names a regexp may name
	fltrs  []mFltr
	memo   map[string][]netip.Prefix
	v4only bool // prefix lists from IPv4 only (legacy import:)
}

func newFilterGen(r *rand.Rand, o *oracle) *filterGen {
	g := &filterGen{r: r, o: o, sets: []string{"RS-MISSING"}, memo: map[string][]netip.Prefix{}}
	for name, s := range o.sets {
		if _, anySet := o.reach(name); anySet {
			continue
		}
		g.sets = append(g.sets, name)
		if s.class == types.ClassAsSet {
			g.asSets = append(g.asSets, name)
		}
	}
	slices.Sort(g.sets)
	slices.Sort(g.asSets)
	return g
}

// filterSets draws n filter-sets, each naming only those drawn before it, so
// that none is on a cycle, and none naming the peer (a filter-set has no
// peer of its own). It returns their RPSL.
func (g *filterGen) filterSets(n int) []string {
	var texts []string
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("FLTR-M%d", i)
		f := g.filterNoPeer(2)
		g.fltrs = append(g.fltrs, mFltr{name, f})
		texts = append(texts, "filter-set: "+name+"\nmp-filter: "+f.text()+"\nmnt-by: MNT-A\nsource: RIPE\n")
	}
	return texts
}

func (g *filterGen) filterNoPeer(depth int) *mFilter {
	for {
		f := g.filter(depth)
		if !strings.Contains(f.text(), "PeerAS") {
			return f
		}
	}
}

func (g *filterGen) filter(depth int) *mFilter {
	r := g.r
	if depth > 0 && r.IntN(3) == 0 {
		switch r.IntN(3) {
		case 0:
			return &mFilter{kind: "not", subs: []*mFilter{g.filter(depth - 1)}}
		case 1:
			return &mFilter{kind: "and", subs: []*mFilter{g.filter(depth - 1), g.filter(depth - 1)}}
		default:
			return &mFilter{kind: "or", subs: []*mFilter{g.filter(depth - 1), g.filter(depth - 1)}}
		}
	}
	op := modelOps[r.IntN(len(modelOps))]
	switch r.IntN(10) {
	case 0:
		return &mFilter{kind: "any"}
	case 1:
		pool := samplePrefixes[:len(samplePrefixes)-3]
		if g.v4only {
			pool = moreSpecifics(v4Universe, 29, 32)
		}
		p := pool[r.IntN(len(pool))]
		return &mFilter{kind: "pfx", pfx: p, op: pfxOp(op, p)}
	case 2:
		return &mFilter{kind: "as", as: types.ASN(firstAS + r.IntN(4)), op: op}
	case 3:
		return &mFilter{kind: "set", set: g.sets[r.IntN(len(g.sets))], op: op}
	case 4:
		return &mFilter{kind: "peer", op: op}
	case 5, 6:
		return &mFilter{kind: "re", re: g.re(2)}
	case 7:
		var cs []string
		for n := 1 + r.IntN(2); n > 0; n-- {
			cs = append(cs, modelCommunities[r.IntN(len(modelCommunities))])
		}
		return &mFilter{kind: "comm", comm: cs, eq: r.IntN(3) == 0}
	case 9:
		return &mFilter{kind: "tmpl", op: op}
	default:
		if len(g.fltrs) == 0 {
			return &mFilter{kind: "any"}
		}
		return &mFilter{kind: "fltr", set: g.fltrs[r.IntN(len(g.fltrs))].name}
	}
}

func (g *filterGen) re(depth int) *mRE {
	seq := &mRE{kind: "seq"}
	if g.r.IntN(3) == 0 {
		seq.subs = append(seq.subs, &mRE{kind: "start"})
	}
	for n := 1 + g.r.IntN(2); n > 0; n-- {
		seq.subs = append(seq.subs, g.reAtom(depth))
	}
	if g.r.IntN(3) == 0 {
		seq.subs = append(seq.subs, &mRE{kind: "end"})
	}
	return seq
}

func (g *filterGen) reAtom(depth int) *mRE {
	r := g.r
	var a *mRE
	switch r.IntN(7) {
	case 0, 1:
		a = &mRE{kind: "asn", as: types.ASN(firstAS + r.IntN(4))}
	case 2:
		a = &mRE{kind: "any"}
	case 3:
		a = &mRE{kind: "peer"}
	case 4:
		a = g.reClass()
	case 5:
		a = &mRE{kind: "any"}
		if len(g.asSets) > 0 {
			a = &mRE{kind: "set", set: g.asSets[r.IntN(len(g.asSets))]}
		}
	default:
		a = &mRE{kind: "tmpl"}
	}
	// a is still a single-AS atom here (asn, any, peer, class, set or tmpl): a
	// same-AS repetition ("~*", "~+", "~{m,n}") applies only to one of those,
	// since every repetition must be the identical AS (RFC 2622 §5.4) — once
	// wrapped in "alt" below it may span more than one AS per position, so it
	// is excluded from singleAS and can only take a plain quantifier.
	singleAS := true
	if depth > 0 && r.IntN(4) == 0 {
		a = &mRE{kind: "alt", subs: []*mRE{g.re(depth - 1), g.re(depth - 1)}}
		singleAS = false
	}
	n := r.IntN(8)
	if !singleAS && n >= 3 && n <= 5 {
		n = 6 // no same-AS repetition on a multi-AS atom; fall back to "no quantifier"
	}
	switch n {
	case 0:
		return &mRE{kind: "star", subs: []*mRE{a}}
	case 1:
		return &mRE{kind: "plus", subs: []*mRE{a}}
	case 2:
		return &mRE{kind: "opt", subs: []*mRE{a}}
	case 3:
		return &mRE{kind: "samestar", subs: []*mRE{a}}
	case 4:
		return &mRE{kind: "sameplus", subs: []*mRE{a}}
	case 5:
		lo := 1 + r.IntN(3)       // 1..3
		hi := lo + r.IntN(3-lo+1) // lo..3
		return &mRE{kind: "samerange", subs: []*mRE{a}, sameMin: lo, sameMax: hi}
	}
	return a
}

// reClass draws a "[...]" or "[^...]" AS-path class (RFC 2622 §5.4):
// negated about half the time, and sometimes holding an as-set name or '.'
// alongside its bare ASNs, as the parser also accepts (policy/regexp.go's
// classifyWord and the reDot case in parseClass).
func (g *filterGen) reClass() *mRE {
	r := g.r
	c := &mRE{kind: "class", cls: []types.ASN{types.ASN(firstAS + r.IntN(4)), types.ASN(firstAS + r.IntN(4))}, neg: r.IntN(2) == 0}
	switch r.IntN(4) {
	case 0:
		if len(g.asSets) > 0 {
			c.clsSet = g.asSets[r.IntN(len(g.asSets))]
		}
	case 1:
		c.clsAny = true
	}
	return c
}

// prefixes is what a set denotes, from the oracle, memoized per generator.
func (g *filterGen) prefixes(name string) []netip.Prefix {
	if ps, ok := g.memo[name]; ok {
		return ps
	}
	ps := g.o.prefixes(name, types.AFIAny)
	g.memo[name] = ps
	return ps
}

// accepts is the model's decision: whether f accepts rt for peer.
func (g *filterGen) accepts(f *mFilter, rt routemodel.Route, peer types.ASN) bool {
	in := func(ps []netip.Prefix, op string) bool {
		for _, p := range ps {
			for _, q := range apply(op, p) {
				if q == rt.Prefix {
					return true
				}
			}
		}
		return false
	}
	switch f.kind {
	case "any":
		return true
	case "pfx":
		return in([]netip.Prefix{f.pfx}, f.op)
	case "as":
		return in(g.o.routes(f.as), f.op)
	case "set":
		return in(g.prefixes(f.set), f.op)
	case "tmpl":
		return in(g.prefixes(templateSet(peer)), f.op)
	case "peer":
		return in(g.o.routes(peer), f.op)
	case "re":
		return regexp.MustCompile(f.re.goRE(g.o, peer, rt.Path)).MatchString(encodePath(rt.Path))
	case "comm":
		have := map[string]bool{}
		for _, c := range rt.Communities {
			have[c] = true
		}
		want := map[string]bool{}
		for _, c := range f.comm {
			want[c] = true
		}
		for c := range want {
			if !have[c] {
				return false
			}
		}
		return !f.eq || len(have) == len(want)
	case "fltr":
		for _, x := range g.fltrs {
			if x.name == f.set {
				return g.accepts(x.f, rt, peer)
			}
		}
		return false
	case "not":
		return !g.accepts(f.subs[0], rt, peer)
	case "and":
		return g.accepts(f.subs[0], rt, peer) && g.accepts(f.subs[1], rt, peer)
	}
	return g.accepts(f.subs[0], rt, peer) || g.accepts(f.subs[1], rt, peer)
}

func randomRoute(r *rand.Rand, peer types.ASN) routemodel.Route {
	rt := routemodel.Route{Prefix: samplePrefixes[r.IntN(len(samplePrefixes))]}
	for n := 1 + r.IntN(3); n > 0; n-- {
		a := types.ASN(firstAS + r.IntN(4))
		if r.IntN(4) == 0 {
			a = peer
		}
		rt.Path = append(rt.Path, a)
	}
	for _, c := range modelCommunities {
		if r.IntN(2) == 0 {
			rt.Communities = append(rt.Communities, c)
		}
	}
	return rt
}

func mustParseFilter(t *testing.T, label, s string) policy.Filter {
	t.Helper()
	f, diags := policy.ParseFilter(s)
	for _, d := range diags {
		if d.Severity >= ast.Error {
			t.Fatalf("%s: %q: %v", label, s, d)
		}
	}
	return f
}

func TestModelNormalizeFilter(t *testing.T) {
	ctx := context.Background()
	seeds, _ := resolve.ModelSeeds(400)
	for seed := uint64(0); seed < seeds; seed++ {
		r := rand.New(rand.NewPCG(seed, 11))
		m := withTemplateSets(r, randomModel(r, false))
		o := newOracle(m)
		g := newFilterGen(r, o)
		texts := append(m.texts(r), g.filterSets(3)...)
		src := resolve.NewMemSource(decodeAll(t, texts), "RIPE", "RADB")
		peer := types.ASN(firstAS + 1)
		e := &resolve.Expander{Src: src, Peer: peer}
		for i := 0; i < 12; i++ {
			f := g.filter(3)
			label := fmt.Sprintf("seed %d: %s", seed, f.text())
			pf := mustParseFilter(t, label, f.text())
			nf, err := e.NormalizeFilter(ctx, pf)
			if err != nil {
				t.Fatalf("%s: NormalizeFilter: %v", label, err)
			}
			again, err := e.NormalizeFilter(ctx, mustParseFilter(t, label, nf.String()))
			if err != nil {
				t.Fatalf("%s: its normal form %s does not normalize: %v", label, nf, err)
			}
			for j := 0; j < 150; j++ {
				rt := randomRoute(r, peer)
				want := g.accepts(f, rt, peer)
				got, err := routemodel.Match(nf, rt)
				if err != nil || got != want {
					t.Fatalf("%s: route %v: the normal form %s accepts %v (%v); the model says %v", label, rt, nf, got, err, want)
				}
				if got, _ := routemodel.Match(again, rt); got != want {
					t.Fatalf("%s: route %v: %s, read back, accepts %v; the model says %v", label, rt, nf, got, want)
				}
			}
			checkEvalFilterAgrees(t, label, e, pf, nf)
		}
	}
}

// checkEvalFilterAgrees holds the contract of spec §4.2: when EvalFilter
// succeeds, the normal form is its answer as one pure conjunct (or none).
func checkEvalFilterAgrees(t *testing.T, label string, e *resolve.Expander, f policy.Filter, nf resolve.NormalFilter) {
	t.Helper()
	got, err := e.EvalFilter(context.Background(), f)
	if err != nil {
		var ne *resolve.NotEnumerableError
		if !errors.As(err, &ne) {
			t.Fatalf("%s: EvalFilter: %v, want a *NotEnumerableError or success", label, err)
		}
		return
	}
	var union []string
	for _, c := range nf.Conjuncts {
		if c.NotPrefixes.Len() > 0 || len(c.Paths) > 0 || len(c.Communities) > 0 {
			t.Fatalf("%s: EvalFilter succeeds but the normal form %s is not pure", label, nf)
		}
		for _, x := range c.Prefixes.List() {
			union = append(union, x.String())
		}
	}
	var want []string
	for _, x := range got.List() {
		want = append(want, x.String())
	}
	slices.Sort(union)
	slices.Sort(want)
	if len(nf.Conjuncts) > 1 || !slices.Equal(union, want) {
		t.Fatalf("%s: normal form %s, EvalFilter %v", label, nf, want)
	}
}

// MaxConjuncts holds exactly at the largest disjunction a filter needs. Only
// symbolic terms (AS-path regexps, community tests, NOT) multiply conjuncts —
// an AND or a positive OR of purely enumerable terms folds into one literal
// (see NormalizeFilter) — so a genuinely multi-conjunct filter needs an OR (or
// a doubly-negated AND) mixing a symbolic term with something else, which a
// depth-4 tree hits only some of the time, and even then only when the
// resulting prefix sets are not disjoint or empty. 700 seeds is the smallest
// round multiple of the original 300 found to reliably clear the floor below
// (a run of 300 lands at 27-29, and even a structural upper bound that assumes
// every leaf nonempty tops out at 47); the floor itself is unchanged.
func TestModelMaxConjuncts(t *testing.T) {
	ctx := context.Background()
	checked := 0
	for seed := uint64(0); seed < 700; seed++ {
		r := rand.New(rand.NewPCG(seed, 13))
		m := withTemplateSets(r, randomModel(r, false))
		o := newOracle(m)
		g := newFilterGen(r, o)
		src := resolve.NewMemSource(decodeAll(t, m.texts(r)), "RIPE", "RADB")
		e := &resolve.Expander{Src: src, Peer: types.ASN(firstAS)}
		f := mustParseFilter(t, "", g.filter(4).text())
		_, peak, err := resolve.NormalizePeak(e, ctx, f)
		if err != nil || peak < 2 {
			continue
		}
		checked++
		at := *e
		at.MaxConjuncts = peak
		if _, err := at.NormalizeFilter(ctx, f); err != nil {
			t.Errorf("seed %d: MaxConjuncts %d (the peak): %v", seed, peak, err)
		}
		at.MaxConjuncts = peak - 1
		_, err = at.NormalizeFilter(ctx, f)
		var tl *resolve.SetTooLargeError
		if !errors.As(err, &tl) || tl.Limit != resolve.LimitConjuncts {
			t.Errorf("seed %d: MaxConjuncts %d (below the peak): err %v", seed, peak-1, err)
		}
	}
	if checked < 50 {
		t.Fatalf("only %d filters needed two conjuncts or more", checked)
	}
}

// Exclude only ever narrows what a filter accepts: normalized with a random
// Expander.Exclude, every route the normal form accepts is one the model
// accepts without it — through NOT, AS-path regexps (a set inside "[^…]" as
// well) and filter-sets.
func TestModelNormalizeExclude(t *testing.T) {
	ctx := context.Background()
	narrowed := 0
	seeds, _ := resolve.ModelSeeds(500)
	for seed := uint64(0); seed < seeds; seed++ {
		r := rand.New(rand.NewPCG(seed, 19))
		m := randomModel(r, false)
		o := newOracle(m)
		g := newFilterGen(r, o)
		texts := append(m.texts(r), g.filterSets(3)...)
		src := resolve.NewMemSource(decodeAll(t, texts), "RIPE", "RADB")
		peer := types.ASN(firstAS + 1)
		ex := randomExclusion(r, m)
		rx := rand.New(rand.NewPCG(seed, 23)) // apart from r, so it does not change the filters r draws
		for _, x := range g.fltrs {
			if rx.IntN(4) == 0 {
				n, _ := types.ParseSetName(x.name)
				ex.Sets = append(ex.Sets, n)
			}
		}
		e := &resolve.Expander{Src: src, Peer: peer, Exclude: ex}
		for i := 0; i < 12; i++ {
			f := g.filter(3)
			label := fmt.Sprintf("seed %d: exclude %v: %s", seed, ex, f.text())
			nf, err := e.NormalizeFilter(ctx, mustParseFilter(t, label, f.text()))
			if err != nil {
				t.Fatalf("%s: NormalizeFilter: %v", label, err)
			}
			for j := 0; j < 150; j++ {
				rt := randomRoute(r, peer)
				got, err := routemodel.Match(nf, rt)
				if err != nil {
					t.Fatalf("%s: %v", label, err)
				}
				want := g.accepts(f, rt, peer)
				if got && !want {
					t.Fatalf("%s: route %v: the normal form %s accepts it; without Exclude the model refuses it", label, rt, nf)
				}
				if want && !got {
					narrowed++
				}
			}
		}
	}
	if narrowed == 0 {
		t.Fatal("Exclude never left out a route the model accepts")
	}
}
