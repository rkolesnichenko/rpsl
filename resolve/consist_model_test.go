package resolve_test

import (
	"context"
	"fmt"
	"maps"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/consist"
	"github.com/rkolesnichenko/rpsl/resolve/internal/irrtest"
	"github.com/rkolesnichenko/rpsl/resolve/internal/routemodel"
	"github.com/rkolesnichenko/rpsl/resolve/internal/rpsldtest"
	"github.com/rkolesnichenko/rpsl/resolve/irrd"
	"github.com/rkolesnichenko/rpsl/resolve/irrdq"
	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/resolve/whois"
	"github.com/rkolesnichenko/rpsl/types"
)

// The consistency model: two aut-nums, localAS and peerAS, whose policies
// name each other, checked against the policy model's own reading of them
// route by route (soundness and completeness of every finding).

const peerAS = types.ASN(64501)

var (
	aRtrs = []string{"", "198.51.100.1", "198.51.100.3", "192.0.2.1"}
	bRtrs = []string{"", "192.0.2.1", "192.0.2.2", "192.0.2.9", "198.51.100.1"}
)

type consistModel struct {
	texts            []string
	pg               *policyGen
	imports, exports map[types.ASN][]*mAttr // each aut-num's attributes, in document order
	autnums          map[types.ASN]string   // each aut-num's text, for a failure's message
	noAutNum         bool                   // peerAS's aut-num is left out of texts
	given            resolve.Source         // what a finding's Given is normalized over
}

func randomConsist(t *testing.T, r *rand.Rand, seed uint64) *consistModel {
	t.Helper()
	texts, pg := newPolicyIRR(r, consistActions)
	cm := &consistModel{pg: pg, imports: map[types.ASN][]*mAttr{}, exports: map[types.ASN][]*mAttr{}, autnums: map[types.ASN]string{}}
	for _, as := range []types.ASN{localAS, peerAS} {
		cm.autNum(t, r, seed, as)
	}
	texts = append(texts, cm.autnums[localAS])
	// About one seed in eight leaves peerAS's aut-num out: Check must then
	// give one NoAutNum finding in each direction, and nothing else.
	if r.IntN(8) == 0 {
		cm.noAutNum = true
		delete(cm.imports, peerAS)
		delete(cm.exports, peerAS)
	} else {
		texts = append(texts, cm.autnums[peerAS])
	}
	cm.texts = texts
	cm.given = resolve.NewMemSource(decodeAll(t, texts), "RIPE", "RADB")
	return cm
}

// autNum draws a new aut-num for as, its peerings naming the other AS half
// the time, replacing as's attributes in the model; it returns its text.
func (cm *consistModel) autNum(t *testing.T, r *rand.Rand, seed uint64, as types.ASN) string {
	t.Helper()
	pg := cm.pg
	pg.favour = peerAS
	if as == peerAS {
		pg.favour = localAS
	}
	defer func() { pg.favour = 0 }()
	other := pg.favour
	cm.imports[as], cm.exports[as] = nil, nil
	var b strings.Builder
	fmt.Fprintf(&b, "aut-num: %s\nas-name: X\n", as)
	for n := 1 + r.IntN(4); n > 0; n-- {
		// A third of the time an attribute mirrors one of the other aut-num's
		// toward this one, so both sides often hold the same tests.
		export := r.IntN(2) != 0
		mirrored := cm.exports[other]
		if export {
			mirrored = cm.imports[other]
		}
		var a *mAttr
		if len(mirrored) > 0 && r.IntN(3) == 0 {
			a = cm.mirror(r, mirrored[r.IntN(len(mirrored))], other)
		} else if export {
			a = pg.attr("export")
		} else {
			a = pg.attr("import")
		}
		if export {
			cm.exports[as] = append(cm.exports[as], a)
		} else {
			cm.imports[as] = append(cm.imports[as], a)
		}
		b.WriteString(a.line() + "\n")
	}
	b.WriteString("mnt-by: MNT-A\nsource: RIPE\n")
	raw, _ := rpsl.ParseObject(b.String())
	if _, ds := rpsl.Decode(raw); len(ds) > 0 {
		for _, d := range ds {
			if d.Severity >= ast.Error {
				t.Fatalf("seed %d: the generated aut-num does not decode: %v\n%s", seed, d, b.String())
			}
		}
	}
	cm.autnums[as] = b.String()
	return b.String()
}

// consistActions are the actions the consistency model's clauses draw
// from: the policy model's, and an append of a community its filters test,
// so an export action changes what the importer's community tests see.
var consistActions = append(slices.Clone(modelActions), "community.append(1:2)")

// crossed is rt as the importer receives it from from (Ruling R13): from
// prepended to the path, and the communities the announcing export term's
// actions (acts, as pg.decide gives them) append.
func crossed(rt routemodel.Route, from types.ASN, acts string) routemodel.Route {
	out := routemodel.Route{Prefix: rt.Prefix, Path: append([]types.ASN{from}, rt.Path...), Communities: slices.Clone(rt.Communities)}
	for _, a := range strings.Split(acts, "; ") {
		if c, ok := strings.CutPrefix(a, "community.append("); ok {
			for _, x := range strings.Split(strings.TrimSuffix(c, ")"), ",") {
				if x = strings.TrimSpace(x); !slices.Contains(out.Communities, x) {
					out.Communities = append(out.Communities, x)
				}
			}
		}
	}
	return out
}

// mirror returns a's counterpart on the other side of the session: an
// import for an export and the reverse, with the same structure, afi
// clause, protocol and filters, its every peering naming other, and an
// export's actions drawn afresh.
func (cm *consistModel) mirror(r *rand.Rand, a *mAttr, other types.ASN) *mAttr {
	m := *a
	m.export = !a.export
	fix := func(fs []mFactor) []mFactor {
		var out []mFactor
		for _, f := range fs {
			nf := mFactor{filter: f.filter}
			for range f.peers {
				pa := mPeerAct{p: &mPeering{kind: "as", as: other}}
				for k := r.IntN(3); m.export && k > 0; k-- {
					pa.actions = append(pa.actions, cm.pg.actions[r.IntN(len(cm.pg.actions))])
				}
				nf.peers = append(nf.peers, pa)
			}
			out = append(out, nf)
		}
		return out
	}
	m.left, m.right = fix(a.left), fix(a.right)
	return &m
}

func (cm *consistModel) pair(r *rand.Rand) consist.Pair {
	p := consist.Pair{A: localAS, B: peerAS, AF: families[r.IntN(2)]}
	if a := aRtrs[r.IntN(len(aRtrs))]; a != "" {
		p.ARtr = netip.MustParseAddr(a)
	}
	if b := bRtrs[r.IntN(len(bRtrs))]; b != "" {
		p.BRtr = netip.MustParseAddr(b)
	}
	return p
}

// oSide is the model's reading of one side of a direction: the terms that
// cover the session, and whether any is undecided.
type oSide struct {
	terms []oTerm
	und   bool
}

func (cm *consistModel) side(local, peer types.ASN, lrtr, prtr netip.Addr, af types.AddrFamily, export bool) oSide {
	attrs := cm.imports[local]
	if export {
		attrs = cm.exports[local]
	}
	terms, und := cm.pg.evaluate(attrs, peval.Session{Local: local, Peer: peer, LocalRtr: lrtr, PeerRtr: prtr, AF: af})
	return oSide{terms, len(und) > 0}
}

// Three-valued answers of maybe.
const (
	tFalse = iota
	tTrue
	tUnknown
)

// maybe is the filter model's three-valued (Kleene) reading of f for a
// route with prefix p: AS-path regexps and community tests are unknown,
// every other test is decided by p alone. tFalse means no route with prefix
// p passes f, whatever its path and communities.
func (cm *consistModel) maybe(f *mFilter, p netip.Prefix, peer types.ASN) int {
	g := cm.pg.fg
	switch f.kind {
	case "re", "comm":
		return tUnknown
	case "fltr":
		for _, x := range g.fltrs {
			if x.name == f.set {
				return cm.maybe(x.f, p, peer)
			}
		}
		return tFalse
	case "not":
		switch v := cm.maybe(f.subs[0], p, peer); v {
		case tFalse:
			return tTrue
		case tTrue:
			return tFalse
		default:
			return v
		}
	case "and", "or":
		a, b := cm.maybe(f.subs[0], p, peer), cm.maybe(f.subs[1], p, peer)
		short, long := tFalse, tTrue // and: false wins
		if f.kind == "or" {
			short, long = tTrue, tFalse
		}
		switch {
		case a == short || b == short:
			return short
		case a == long && b == long:
			return long
		}
		return tUnknown
	}
	if g.accepts(f, routemodel.Route{Prefix: p}, peer) {
		return tTrue
	}
	return tFalse
}

// mayAccept reports whether some route with prefix p, of family af, may
// pass one of terms (sessionPeer bound to PeerAS), whatever its path and
// communities: the prefix space a NoImport or NoExport finding may name.
func (cm *consistModel) mayAccept(terms []oTerm, p netip.Prefix, sessionPeer types.ASN, af types.AFI) bool {
	if prefixAFI(p) != af {
		return false
	}
	for _, t := range terms {
		peer := sessionPeer
		if t.peer != 0 {
			peer = t.peer
		}
		v := tTrue
		for _, f := range t.filters {
			v = min3(v, cm.maybe(f, p, peer))
		}
		for _, f := range t.notAny {
			switch cm.maybe(f, p, peer) {
			case tTrue:
				v = tFalse
			case tUnknown:
				v = min3(v, tUnknown)
			}
		}
		if v != tFalse {
			return true
		}
	}
	return false
}

// mustAccept reports whether every route with prefix p, of family af,
// passes one of terms (sessionPeer bound to PeerAS), whatever its path and
// communities.
func (cm *consistModel) mustAccept(terms []oTerm, p netip.Prefix, sessionPeer types.ASN, af types.AFI) bool {
	if prefixAFI(p) != af {
		return false
	}
	for _, t := range terms {
		peer := sessionPeer
		if t.peer != 0 {
			peer = t.peer
		}
		v := tTrue
		for _, f := range t.filters {
			v = min3(v, cm.maybe(f, p, peer))
		}
		for _, f := range t.notAny {
			switch cm.maybe(f, p, peer) {
			case tTrue:
				v = tFalse
			case tUnknown:
				v = min3(v, tUnknown)
			}
		}
		if v == tTrue {
			return true
		}
	}
	return false
}

// min3 is Kleene AND.
func min3(a, b int) int {
	switch {
	case a == tFalse || b == tFalse:
		return tFalse
	case a == tUnknown || b == tUnknown:
		return tUnknown
	}
	return tTrue
}

// givenHolds reports whether rt passes a finding's Given tests, read back
// and matched by the route model (test code: the library never matches a
// regexp against a path).
func (cm *consistModel) givenHolds(t *testing.T, rt routemodel.Route, given []string, afi types.AFI) bool {
	t.Helper()
	if len(given) == 0 {
		return true
	}
	f := mustParseFilter(t, "given", "ANY AND "+strings.Join(given, " AND "))
	nf, err := (&resolve.Expander{Src: cm.given, AFI: afi}).NormalizeFilter(context.Background(), f)
	if err != nil {
		t.Fatalf("given %q: %v", given, err)
	}
	ok, err := routemodel.Match(nf, rt)
	if err != nil {
		t.Fatalf("given %q, route %v: %v", given, rt, err)
	}
	return ok
}

// wantSeverity is the severity each kind of finding carries.
func wantSeverity(k consist.Kind) ast.Severity {
	switch k {
	case consist.NotImported, consist.NoImport, consist.NoAutNum:
		return ast.Warning
	}
	return ast.Info
}

// consistCounts tallies what the model exercised: findings by kind (and
// Undecided by what it may be and why), across directions.
type consistCounts map[string]int

// wantFinding is a finding the model expects when a side has no decided
// term: its kind and, for Undecided, what it may be and why.
type wantFinding struct {
	kind, of consist.Kind
	why      string
}

func (cm *consistModel) checkDirection(t *testing.T, label string, d consist.Direction, p consist.Pair, r *rand.Rand, kc consistCounts) {
	t.Helper()
	fromRtr, toRtr := p.ARtr, p.BRtr
	if d.From == p.B {
		fromRtr, toRtr = p.BRtr, p.ARtr
	}
	af := p.AF.AFI
	fail := func(format string, args ...any) {
		t.Helper()
		t.Fatalf("%s: %v→%v %v: %s\nfindings %+v\nobjects:\n%s\n%s", label, d.From, d.To, p, fmt.Sprintf(format, args...), d.Findings, cm.autnums[localAS], cm.autnums[peerAS])
	}
	for _, f := range d.Findings {
		key := f.Kind.String()
		if f.Kind == consist.Undecided {
			key += "/" + f.Of.String() + "/" + f.Why
		}
		kc[key]++
		if f.Severity != wantSeverity(f.Kind) {
			fail("%v has severity %v, want %v", key, f.Severity, wantSeverity(f.Kind))
		}
		if f.Truncated {
			fail("a finding was truncated; raise MaxRanges")
		}
	}
	if cm.noAutNum {
		if len(d.Findings) != 1 || d.Findings[0].Kind != consist.NoAutNum || d.Findings[0].AS != peerAS || d.NoPolicy {
			fail("peerAS's aut-num is missing: want one no-aut-num finding naming it, and policy")
		}
		return
	}
	exp := cm.side(d.From, d.To, fromRtr, toRtr, p.AF, true)
	imp := cm.side(d.To, d.From, toRtr, fromRtr, p.AF, false)
	if none := len(exp.terms) == 0 && !exp.und && len(imp.terms) == 0 && !imp.und; d.NoPolicy != none {
		fail("NoPolicy %v; the model: neither side has a term %v", d.NoPolicy, none)
	}
	if d.NoPolicy {
		kc["no policy"]++
	}
	// A side with no decided term: the findings are fixed by which side has
	// decided terms and which has undecided ones.
	expD, impD := len(exp.terms) > 0, len(imp.terms) > 0
	if expD != impD {
		// Ruling R15: when the one side with decided terms permits nothing
		// in the family, Check reads it as having none. Whether it permits
		// anything is read from Check's answer — a NoImport (NoExport)
		// finding, or its Undecided form for the other side's undecided
		// terms — and held to the model: an answer without one must come
		// with a side that passes no sampled route, and one with it names
		// prefixes (checkWholeSide).
		whole := func(f consist.Finding) bool {
			if expD {
				return f.Kind == consist.NoImport || f.Kind == consist.Undecided && f.Of == consist.NoImport && f.Why == consist.WhyImporterUndecided
			}
			return f.Kind == consist.NoExport || f.Kind == consist.Undecided && f.Of == consist.NoExport && f.Why == consist.WhyExporterUndecided
		}
		if len(d.Findings) != 1 || !whole(d.Findings[0]) {
			terms, peer, what := exp.terms, d.To, "announced"
			if impD {
				terms, peer, what = imp.terms, d.From, "accepted"
			}
			for _, q := range samplePrefixes {
				if cm.mayAccept(terms, q, peer, af) {
					fail("no whole-side finding, yet a route with prefix %v may be %s", q, what)
				}
			}
			for k := 0; k < 100; k++ {
				if ok, _ := cm.pg.decide(terms, randomRoute(r, d.From), peer, af); ok {
					fail("no whole-side finding, yet a sampled route is %s", what)
				}
			}
			expD, impD = false, false
		} else if len(d.Findings[0].Ranges) == 0 {
			fail("a whole-side %v finding names no prefix", d.Findings[0].Kind)
		}
	}
	if !expD || !impD {
		var want []wantFinding
		switch {
		case expD: // the importer has no decided term
			if imp.und {
				want = append(want, wantFinding{consist.Undecided, consist.NoImport, consist.WhyImporterUndecided})
			} else {
				want = append(want, wantFinding{consist.NoImport, 0, ""})
			}
		case impD: // the exporter has no decided term
			if exp.und {
				want = append(want, wantFinding{consist.Undecided, consist.NoExport, consist.WhyExporterUndecided})
			} else {
				want = append(want, wantFinding{consist.NoExport, 0, ""})
			}
		default: // neither has a decided term
			if exp.und {
				want = append(want, wantFinding{consist.Undecided, consist.NoImport, consist.WhyExporterUndecided})
			}
			if imp.und {
				want = append(want, wantFinding{consist.Undecided, consist.NoExport, consist.WhyImporterUndecided})
			}
		}
		var got []wantFinding
		for _, f := range d.Findings {
			w := wantFinding{f.Kind, 0, ""}
			if f.Kind == consist.Undecided {
				w.of, w.why = f.Of, f.Why
			}
			got = append(got, w)
		}
		if !slices.Equal(got, want) {
			fail("exporter decided %v undecided %v, importer decided %v undecided %v: want %+v", expD, exp.und, impD, imp.und, want)
		}
		switch {
		case expD:
			cm.checkWholeSide(t, r, d.Findings[0], exp.terms, d.From, d.To, af, "announced", fail)
		case impD:
			cm.checkWholeSide(t, r, d.Findings[0], imp.terms, d.From, d.From, af, "accepted", fail)
		default:
			for _, f := range d.Findings {
				if len(f.Ranges) != 0 || f.Example.IsValid() {
					fail("neither side has a decided term, yet a finding names prefixes")
				}
			}
		}
		return
	}
	for _, f := range d.Findings {
		switch {
		case f.Kind == consist.NoImport || f.Kind == consist.NoExport || f.Kind == consist.NoAutNum:
			fail("both sides have terms, yet %v", f.Kind)
		case f.Kind == consist.Undecided && (f.Of == consist.NoImport || f.Of == consist.NoExport):
			fail("both sides have terms, yet undecided %v", f.Of)
		case f.Kind == consist.NotImported && imp.und:
			fail("the importer has undecided terms, yet not-imported is not demoted")
		case f.Kind == consist.NotExported && exp.und:
			fail("the exporter has undecided terms, yet not-exported is not demoted")
		}
	}
	// decide reads rt, a route as the exporter has it, on both sides: the
	// importer reads it as it crosses the session (crossed), with the
	// announcing term's actions applied — none when no term announces it.
	decide := func(rt routemodel.Route) (announced, accepted bool, seen routemodel.Route) {
		announced, acts := cm.pg.decide(exp.terms, rt, d.To, af)
		seen = crossed(rt, d.From, acts)
		accepted, _ = cm.pg.decide(imp.terms, seen, d.From, af)
		return
	}
	// A finding's Given is read where the side it is about reads the route:
	// a not-imported finding's (the exporter's tests) on rt, a not-exported
	// one's (the importer's) on the route as received.
	givenOn := func(f consist.Finding, rt, seen routemodel.Route) bool {
		if f.Kind == consist.NotExported || f.Kind == consist.Undecided && f.Of == consist.NotExported {
			return cm.givenHolds(t, seen, f.Given, af)
		}
		return cm.givenHolds(t, rt, f.Given, af)
	}
	// Soundness: a definite finding holds for every route passing its Given
	// whose prefix is its example or any sampled prefix in its ranges: the
	// route is announced and refused (accepted and not announced).
	for _, f := range d.Findings {
		if f.Kind != consist.NotImported && f.Kind != consist.NotExported {
			continue
		}
		sp := types.SpaceOf(f.Ranges...)
		if !sp.Contains(f.Example) {
			fail("%v: the example %v is not in the ranges", f.Kind, f.Example)
		}
		prefixes := []netip.Prefix{f.Example}
		for _, q := range samplePrefixes {
			if len(prefixes) > 20 {
				break
			}
			if prefixAFI(q) == af && q != f.Example && sp.Contains(q) {
				prefixes = append(prefixes, q)
			}
		}
		for _, q := range prefixes {
			for k := 0; k < 8; k++ {
				rt := randomRoute(r, d.From)
				rt.Prefix = q
				an, ac, seen := decide(rt)
				if !givenOn(f, rt, seen) {
					continue
				}
				if f.Kind == consist.NotImported && !(an && !ac) {
					fail("not-imported, route %v: the model says announced %v, accepted %v", rt, an, ac)
				}
				if f.Kind == consist.NotExported && !(ac && !an) {
					fail("not-exported, route %v: the model says announced %v, accepted %v", rt, an, ac)
				}
			}
		}
	}
	// Completeness: every sampled route announced and refused (accepted and
	// not announced) is in a finding of that kind, or an undecided one.
	covered := func(rt, seen routemodel.Route, kind consist.Kind) bool {
		for _, f := range d.Findings {
			if (f.Kind == kind || f.Kind == consist.Undecided && f.Of == kind) &&
				types.SpaceOf(f.Ranges...).Contains(rt.Prefix) && givenOn(f, rt, seen) {
				return true
			}
		}
		return false
	}
	for k := 0; k < 200; k++ {
		rt := randomRoute(r, d.From)
		if prefixAFI(rt.Prefix) != af {
			continue
		}
		an, ac, seen := decide(rt)
		if an && !ac && !covered(rt, seen, consist.NotImported) {
			fail("route %v (received as %v) is announced and refused, and no finding covers it", rt, seen)
		}
		if ac && !an && !covered(rt, seen, consist.NotExported) {
			fail("route %v (received as %v) is accepted and not announced, and no finding covers it", rt, seen)
		}
		// Ruling R14: an undecided export term may announce any route, with
		// any of the actions; one the importer may refuse is covered.
		if exp.und {
			for _, acts := range []string{"", "community.append(1:3)", "community.append(1:2)", "community.append(1:2); community.append(1:3)"} {
				in := crossed(rt, d.From, acts)
				if ok, _ := cm.pg.decide(imp.terms, in, d.From, af); !ok && !covered(rt, in, consist.NotImported) {
					fail("route %v (received as %v) may be announced by an undecided export term and is refused, and no finding covers it", rt, in)
				}
			}
		}
		// The mirror: an undecided import term may accept any route the
		// exporter does not announce.
		if imp.und && !an && !covered(rt, seen, consist.NotExported) {
			fail("route %v is not announced and may be accepted by an undecided import term, and no finding covers it", rt)
		}
	}
	// The space of those two findings holds only prefixes the other side
	// may refuse (does not surely accept) some route with.
	for _, f := range d.Findings {
		terms, peer, what := imp.terms, d.From, "accepted"
		switch {
		case f.Kind == consist.Undecided && f.Of == consist.NotImported && f.Why == consist.WhyExporterUndecided:
		case f.Kind == consist.Undecided && f.Of == consist.NotExported && f.Why == consist.WhyImporterUndecided:
			terms, peer, what = exp.terms, d.To, "announced"
		default:
			continue
		}
		sp := types.SpaceOf(f.Ranges...)
		if !sp.Contains(f.Example) {
			fail("%v/%v: the example %v is not in the ranges", f.Kind, f.Of, f.Example)
		}
		for _, q := range samplePrefixes {
			if sp.Contains(q) && cm.mustAccept(terms, q, peer, af) {
				fail("undecided %v (%s) names %v, which every route with that prefix is %s with", f.Of, f.Why, q, what)
			}
		}
	}
}

// checkWholeSide holds a NoImport (NoExport) finding, or its Undecided form,
// to the one side that has decided terms: its ranges hold every sampled
// route that side passes, and only prefixes some route may pass with.
// peer is what the side binds PeerAS to; what names the side for a message.
func (cm *consistModel) checkWholeSide(t *testing.T, r *rand.Rand, f consist.Finding, terms []oTerm, from, peer types.ASN, af types.AFI, what string, fail func(string, ...any)) {
	t.Helper()
	sp := types.SpaceOf(f.Ranges...)
	if len(f.Ranges) > 0 && !sp.Contains(f.Example) {
		fail("%v: the example %v is not in the ranges", f.Kind, f.Example)
	}
	for _, q := range samplePrefixes {
		if sp.Contains(q) && !cm.mayAccept(terms, q, peer, af) {
			fail("%v names %v, which no route with that prefix is %s with", f.Kind, q, what)
		}
	}
	for k := 0; k < 100; k++ {
		rt := randomRoute(r, from)
		if ok, _ := cm.pg.decide(terms, rt, peer, af); ok && !sp.Contains(rt.Prefix) {
			fail("route %v is %s, and the %v finding's ranges leave it out", rt, what, f.Kind)
		}
	}
}

func (cm *consistModel) check(t *testing.T, label string, c *consist.Checker, r *rand.Rand, kc consistCounts) {
	t.Helper()
	for k := 0; k < 4; k++ {
		p := cm.pair(r)
		rep, err := c.Check(context.Background(), p)
		if err != nil {
			t.Fatalf("%s: %v: %v", label, p, err)
		}
		cm.checkDirection(t, label, rep.AtoB, p, r, kc)
		cm.checkDirection(t, label, rep.BtoA, p, r, kc)
	}
}

// requireCounts fails when the model did not exercise a kind of finding as
// often as floors asks.
func requireCounts(t *testing.T, label string, kc consistCounts, floors map[string]int) {
	t.Helper()
	t.Logf("%s: %v", label, kc)
	keys := slices.Sorted(maps.Keys(floors))
	for _, k := range keys {
		if kc[k] < floors[k] {
			t.Errorf("%s: only %d %s findings, want %d", label, kc[k], k, floors[k])
		}
	}
}

const (
	undNotImp = "undecided/not-imported/"
	undNotExp = "undecided/not-exported/"
	undNoImp  = "undecided/no-import/"
	undNoExp  = "undecided/no-export/"
)

func TestModelConsist(t *testing.T) {
	kc := consistCounts{}
	for seed := uint64(0); seed < 400; seed++ {
		r := rand.New(rand.NewPCG(seed, 41))
		cm := randomConsist(t, r, seed)
		c := &consist.Checker{Eval: peval.Evaluator{Src: resolve.NewMemSource(decodeAll(t, cm.texts), "RIPE", "RADB")}, MaxRanges: 1 << 16}
		cm.check(t, fmt.Sprintf("seed %d", seed), c, r, kc)
	}
	requireCounts(t, "memsource", kc, map[string]int{
		"not-imported": 10, "not-exported": 10, "no-import": 10, "no-export": 10, "no-aut-num": 150, "no policy": 50,
		undNotImp + consist.WhySymbolic: 10, undNotImp + consist.WhyImporterUndecided: 3, undNotImp + consist.WhyExporterUndecided: 10,
		undNotExp + consist.WhySymbolic: 25, undNotExp + consist.WhyExporterUndecided: 5, undNotExp + consist.WhyImporterUndecided: 10,
		undNoImp + consist.WhyImporterUndecided: 15, undNoImp + consist.WhyExporterUndecided: 45,
		undNoExp + consist.WhyImporterUndecided: 55, undNoExp + consist.WhyExporterUndecided: 25,
	})
}

// The same over a Corpus with IndexPeers, whose NamedBy is held to the
// model too — as loaded, after the aut-num of localAS is replaced and after
// it is deleted — and over the network backends against an IRRd-like
// server.
func TestModelConsistBackends(t *testing.T) {
	kc := consistCounts{}
	kr := consistCounts{} // rpsld, over irrd and whois
	for seed := uint64(0); seed < 150; seed++ {
		r := rand.New(rand.NewPCG(seed, 41))
		label := fmt.Sprintf("seed %d", seed)
		cm := randomConsist(t, r, seed)
		cm.checkNamedBy(t, label+" memsource", resolve.NewMemSource(decodeAll(t, cm.texts), "RIPE", "RADB"))
		l := &resolve.DumpLoader{Sources: []string{"RIPE", "RADB"}, IndexPeers: true}
		if err := l.Read(strings.NewReader(strings.Join(cm.texts, "\n"))); err != nil {
			t.Fatal(err)
		}
		src := l.Source()
		cm.checkNamedBy(t, label+" corpus", src)
		cm.check(t, "corpus "+label, &consist.Checker{Eval: peval.Evaluator{Src: src}, MaxRanges: 1 << 16}, r, kc)
		db := irrtest.New(cm.texts...).WithSources("RIPE", "RADB")
		ir := &irrd.Source{Addr: db.IRRd(t), Sources: []string{"RIPE", "RADB"}, Pipeline: 8, Timeout: 5 * time.Second}
		cm.check(t, "irrd "+label, &consist.Checker{Eval: peval.Evaluator{Src: ir}, MaxRanges: 1 << 16}, r, kc)
		ir.Close()
		wh := &whois.Source{Addr: db.Whois(t), Sources: []string{"RIPE", "RADB"}, Timeout: 5 * time.Second}
		cm.check(t, "whois "+label, &consist.Checker{Eval: peval.Evaluator{Src: wh}, MaxRanges: 1 << 16}, r, kc)
		// rpsld's legs draw their own samples, so r's later draws stay as they were.
		rr := rand.New(rand.NewPCG(seed, 43))
		rs := rpsldtest.Serve(t, rpsldtest.Snapshot(t, cm.texts, irrdq.SnapshotOptions{}, "RIPE", "RADB"))
		rp := &irrd.Source{Addr: rs, Sources: []string{"RIPE", "RADB"}, Pipeline: 8, Timeout: 5 * time.Second}
		cm.check(t, "rpsld "+label, &consist.Checker{Eval: peval.Evaluator{Src: rp}, MaxRanges: 1 << 16}, rr, kr)
		rp.Close()
		rw := &whois.Source{Addr: rs, Sources: []string{"RIPE", "RADB"}, Timeout: 5 * time.Second}
		cm.check(t, "rpsld whois "+label, &consist.Checker{Eval: peval.Evaluator{Src: rw}, MaxRanges: 1 << 16}, rr, kr)

		// The index follows a replacement and a delete.
		if err := l.Read(strings.NewReader(cm.autNum(t, r, seed, localAS))); err != nil {
			t.Fatal(err)
		}
		cm.checkNamedBy(t, label+" replaced", l.Source())
		if !l.Corpus().Delete("aut-num", localAS.String(), "RIPE") {
			t.Fatalf("%s: the aut-num of %v is not in the corpus", label, localAS)
		}
		delete(cm.imports, localAS)
		delete(cm.exports, localAS)
		cm.checkNamedBy(t, label+" deleted", l.Source())
	}
	floors := map[string]int{
		"not-imported": 6, "not-exported": 6, "no-import": 6, "no-export": 6, "no-aut-num": 6, "no policy": 6,
		undNotImp + consist.WhySymbolic: 6, undNotImp + consist.WhyImporterUndecided: 6, undNotImp + consist.WhyExporterUndecided: 6,
		undNotExp + consist.WhySymbolic: 6, undNotExp + consist.WhyExporterUndecided: 6, undNotExp + consist.WhyImporterUndecided: 6,
		undNoImp + consist.WhyImporterUndecided: 6, undNoImp + consist.WhyExporterUndecided: 6,
		undNoExp + consist.WhyImporterUndecided: 6, undNoExp + consist.WhyExporterUndecided: 6,
	}
	// corpus, irrd and whois pooled: 2 findings of each kind per backend.
	requireCounts(t, "backends", kc, floors)
	// rpsld's irrd and whois pooled apart, to the same 2 per backend.
	rf := map[string]int{}
	for k, n := range floors {
		rf[k] = n * 2 / 3
	}
	requireCounts(t, "rpsld", kr, rf)
}

// checkNamedBy holds NamedBy to the AS numbers the model's peerings name.
func (cm *consistModel) checkNamedBy(t *testing.T, label string, src *resolve.MemSource) {
	t.Helper()
	want := map[types.ASN][]types.ASN{}
	for _, as := range []types.ASN{localAS, peerAS} {
		named := map[types.ASN]bool{}
		for _, a := range append(slices.Clone(cm.imports[as]), cm.exports[as]...) {
			for _, f := range append(slices.Clone(a.left), a.right...) {
				for _, pa := range f.peers {
					switch pa.p.kind {
					case "as":
						named[pa.p.as] = true
					case "or":
						named[pa.p.as], named[pa.p.as2] = true, true
					case "except":
						named[pa.p.as] = true
					}
				}
			}
		}
		delete(named, as)
		for x := range named {
			want[x] = append(want[x], as)
		}
	}
	for _, x := range []types.ASN{localAS, peerAS, firstAS, firstAS + 1, firstAS + 2, firstAS + 3} {
		got, err := src.NamedBy(x)
		if err != nil {
			t.Fatalf("%s: NamedBy(%v): %v", label, x, err)
		}
		w := want[x]
		slices.Sort(w)
		if !slices.Equal(got, w) {
			t.Errorf("%s: NamedBy(%v) = %v, the model %v", label, x, got, w)
		}
	}
}

// TestModelConsistExact: pure prefix filters inside v4Universe, so every
// space lies inside the universe and the oracle can enumerate it. The
// findings (by kind) and lint/shadowed and lint/empty must equal the
// oracle's exactly.
func TestModelConsistExact(t *testing.T) {
	universe := moreSpecifics(v4Universe, v4Universe.Bits(), 32)
	spaceOfSet := func(ps []netip.Prefix) types.PrefixSpace {
		var rs []types.PrefixRange
		for _, p := range ps {
			r, _ := types.NewPrefixRange(p, p.Bits(), p.Bits())
			rs = append(rs, r)
		}
		return types.SpaceOf(rs...)
	}
	uniSpace := spaceOfSet(universe)
	for seed := uint64(0); seed < 400; seed++ {
		r := rand.New(rand.NewPCG(seed, 43))
		label := fmt.Sprintf("seed %d", seed)
		// Each side: 1-3 import and 1-3 export attributes toward the other,
		// the first naming it, the rest it or AS-ANY.
		type attr struct {
			export bool
			f      *xFilter
		}
		sides := map[types.ASN][]attr{}
		var texts []string
		for _, as := range []types.ASN{localAS, peerAS} {
			other := peerAS
			if as == peerAS {
				other = localAS
			}
			var b strings.Builder
			fmt.Fprintf(&b, "aut-num: %s\nas-name: X\n", as)
			for _, export := range []bool{false, true} {
				for n, k := 0, 1+r.IntN(3); n < k; n++ {
					peering := other.String()
					if n > 0 && r.IntN(3) == 0 {
						peering = "AS-ANY"
					}
					f := randomXFilter(r, universe)
					sides[as] = append(sides[as], attr{export, f})
					if export {
						fmt.Fprintf(&b, "export: to %s announce %s\n", peering, f)
					} else {
						fmt.Fprintf(&b, "import: from %s accept %s\n", peering, f)
					}
				}
			}
			b.WriteString("mnt-by: MNT-A\nsource: RIPE\n")
			texts = append(texts, b.String())
		}
		src := resolve.NewMemSource(decodeAll(t, texts))
		c := &consist.Checker{Eval: peval.Evaluator{Src: src}, MaxRanges: 1 << 16}
		accepts := func(as types.ASN, export bool, p netip.Prefix) bool {
			for _, a := range sides[as] {
				if a.export == export && a.f.contains(p) {
					return true
				}
			}
			return false
		}
		// meeting is the indexes, among as's export (import) attributes, of
		// those accepting a prefix of sp.
		meeting := func(as types.ASN, export bool, sp types.PrefixSpace) []int {
			var out []int
			i := 0
			for _, a := range sides[as] {
				if a.export != export {
					continue
				}
				for _, p := range universe {
					if a.f.contains(p) && sp.Contains(p) {
						out = append(out, i)
						break
					}
				}
				i++
			}
			return out
		}
		rep, err := c.Check(context.Background(), consist.Pair{A: localAS, B: peerAS, AF: families[0]})
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range []consist.Direction{rep.AtoB, rep.BtoA} {
			var notImp, notExp []netip.Prefix
			for _, p := range universe {
				an, ac := accepts(d.From, true, p), accepts(d.To, false, p)
				if an && !ac {
					notImp = append(notImp, p)
				}
				if ac && !an {
					notExp = append(notExp, p)
				}
			}
			got := map[consist.Kind]types.PrefixSpace{}
			for _, f := range d.Findings {
				if f.Kind != consist.NotImported && f.Kind != consist.NotExported {
					t.Fatalf("%s: %v→%v: a pure policy gave %v %+v", label, d.From, d.To, f.Kind, f)
				}
				if f.Severity != wantSeverity(f.Kind) {
					t.Fatalf("%s: %v→%v: %v has severity %v", label, d.From, d.To, f.Kind, f.Severity)
				}
				sp := types.SpaceOf(f.Ranges...)
				got[f.Kind] = got[f.Kind].Union(sp)
				// Roles: the side the finding is about lists its attributes
				// that meet the finding's prefixes; the other side none.
				gotExp, gotImp := f.Export, f.Import
				wantExp, wantImp := meeting(d.From, true, sp), []int(nil)
				if f.Kind == consist.NotExported {
					wantExp, wantImp = nil, meeting(d.To, false, sp)
				}
				if !slices.Equal(gotExp, wantExp) || !slices.Equal(gotImp, wantImp) {
					t.Fatalf("%s: %v→%v: %v names export %v, import %v; the oracle %v, %v\n%s", label, d.From, d.To, f.Kind,
						gotExp, gotImp, wantExp, wantImp, strings.Join(texts, "\n"))
				}
			}
			for _, k := range []consist.Kind{consist.NotImported, consist.NotExported} {
				want := notImp
				if k == consist.NotExported {
					want = notExp
				}
				if g := got[k].Intersect(uniSpace); !g.Equal(spaceOfSet(want)) {
					t.Fatalf("%s: %v→%v: %v %v, the oracle %v\n%s", label, d.From, d.To, k, g, want, strings.Join(texts, "\n"))
				}
				if !got[k].Subset(uniSpace) {
					t.Fatalf("%s: %v→%v: %v reaches outside the universe: %v", label, d.From, d.To, k, got[k])
				}
			}
		}
		// Lint: shadowed and empty, per attribute, exactly.
		issues, err := c.Lint(context.Background(), localAS)
		if err != nil {
			t.Fatal(err)
		}
		gotIssues := map[string]bool{}
		for _, is := range issues {
			if is.Rule != consist.RuleShadowed && is.Rule != consist.RuleEmpty {
				t.Fatalf("%s: unexpected issue %+v", label, is)
			}
			gotIssues[fmt.Sprintf("%s %s#%d", is.Rule, is.Attr, is.Index)] = true
		}
		wantIssues := map[string]bool{}
		for _, export := range []bool{false, true} {
			kind := "import"
			if export {
				kind = "export"
			}
			var before []netip.Prefix
			i := 0
			for _, a := range sides[localAS] {
				if a.export != export {
					continue
				}
				var acc []netip.Prefix
				for _, p := range universe {
					if a.f.contains(p) {
						acc = append(acc, p)
					}
				}
				switch {
				case len(acc) == 0:
					wantIssues[fmt.Sprintf("%s %s#%d", consist.RuleEmpty, kind, i)] = true
				case spaceOfSet(acc).Subset(spaceOfSet(before)):
					wantIssues[fmt.Sprintf("%s %s#%d", consist.RuleShadowed, kind, i)] = true
				}
				before = append(before, acc...)
				i++
			}
		}
		if !mapsEqual(gotIssues, wantIssues) {
			t.Fatalf("%s: lint %v, the oracle %v\n%s", label, gotIssues, wantIssues, texts[0])
		}
	}
}

func mapsEqual(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// xFilter is a pure prefix filter: a prefix list, or two joined.
type xFilter struct {
	op     string // "list", "and", "or", "andnot"
	ranges []types.PrefixRange
	l, r   *xFilter
}

func (f *xFilter) contains(p netip.Prefix) bool {
	switch f.op {
	case "list":
		for _, r := range f.ranges {
			if r.Contains(p) {
				return true
			}
		}
		return false
	case "and":
		return f.l.contains(p) && f.r.contains(p)
	case "or":
		return f.l.contains(p) || f.r.contains(p)
	}
	return f.l.contains(p) && !f.r.contains(p)
}

func (f *xFilter) String() string {
	switch f.op {
	case "list":
		var parts []string
		for _, r := range f.ranges {
			parts = append(parts, r.String())
		}
		return "{" + strings.Join(parts, ", ") + "}"
	case "and":
		return "(" + f.l.String() + " AND " + f.r.String() + ")"
	case "or":
		return "(" + f.l.String() + " OR " + f.r.String() + ")"
	}
	return "(" + f.l.String() + " AND NOT " + f.r.String() + ")"
}

func randomXList(r *rand.Rand, universe []netip.Prefix) *xFilter {
	f := &xFilter{op: "list"}
	for n := 1 + r.IntN(2); n > 0; n-- {
		p := universe[r.IntN(len(universe))]
		op := pfxOp([]string{"", "", "^+", "^-", "^31-32", "^30", "^32"}[r.IntN(7)], p)
		pr, err := types.ParsePrefixRange(p.String() + op)
		if err != nil || pr.IsEmpty() {
			pr, _ = types.NewPrefixRange(p, p.Bits(), p.Bits())
		}
		f.ranges = append(f.ranges, pr)
	}
	return f
}

func randomXFilter(r *rand.Rand, universe []netip.Prefix) *xFilter {
	switch r.IntN(4) {
	case 0:
		return randomXList(r, universe)
	case 1:
		return &xFilter{op: "and", l: randomXList(r, universe), r: randomXList(r, universe)}
	case 2:
		return &xFilter{op: "or", l: randomXList(r, universe), r: randomXList(r, universe)}
	}
	return &xFilter{op: "andnot", l: randomXList(r, universe), r: randomXList(r, universe)}
}
