package resolve_test

import (
	"context"
	"fmt"
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
	"github.com/rkolesnichenko/rpsl/resolve/irrd"
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
	given            resolve.Source         // what a finding's Given is normalized over
}

func randomConsist(t *testing.T, r *rand.Rand, seed uint64) *consistModel {
	t.Helper()
	texts, pg := newPolicyIRR(r, modelActions)
	cm := &consistModel{pg: pg, imports: map[types.ASN][]*mAttr{}, exports: map[types.ASN][]*mAttr{}}
	for _, as := range []types.ASN{localAS, peerAS} {
		pg.favour = peerAS
		if as == peerAS {
			pg.favour = localAS
		}
		var b strings.Builder
		fmt.Fprintf(&b, "aut-num: %s\nas-name: X\n", as)
		for n := 1 + r.IntN(4); n > 0; n-- {
			if r.IntN(2) == 0 {
				a := pg.attr("import")
				cm.imports[as] = append(cm.imports[as], a)
				b.WriteString(a.line() + "\n")
			} else {
				a := pg.attr("export")
				cm.exports[as] = append(cm.exports[as], a)
				b.WriteString(a.line() + "\n")
			}
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
		texts = append(texts, b.String())
	}
	pg.favour = 0
	cm.texts = texts
	cm.given = resolve.NewMemSource(decodeAll(t, texts), "RIPE", "RADB")
	return cm
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

// consistCounts tallies what the model exercised: findings by kind (and
// Undecided by reason), across directions.
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
	exp := cm.side(d.From, d.To, fromRtr, toRtr, p.AF, true)
	imp := cm.side(d.To, d.From, toRtr, fromRtr, p.AF, false)
	fail := func(format string, args ...any) {
		t.Helper()
		t.Fatalf("%s: %v→%v %v: %s\nfindings %+v\nobjects:\n%s", label, d.From, d.To, p, fmt.Sprintf(format, args...), d.Findings, strings.Join(cm.texts[len(cm.texts)-2:], "\n"))
	}
	for _, f := range d.Findings {
		key := f.Kind.String()
		if f.Kind == consist.Undecided {
			key += "/" + f.Of.String() + "/" + f.Why
		}
		kc[key]++
	}
	// A side with no decided term: the findings are fixed by which side has
	// decided terms and which has undecided ones.
	expD, impD := len(exp.terms) > 0, len(imp.terms) > 0
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
		case f.Truncated:
			fail("a finding was truncated; raise MaxRanges")
		}
	}
	decide := func(rt routemodel.Route) (announced, accepted bool) {
		announced, _ = cm.pg.decide(exp.terms, rt, d.To, p.AF.AFI)
		accepted, _ = cm.pg.decide(imp.terms, rt, d.From, p.AF.AFI)
		return
	}
	// Soundness: a definite finding's example is announced and refused (or
	// accepted and not announced) on every sampled route passing its Given.
	for _, f := range d.Findings {
		if f.Kind != consist.NotImported && f.Kind != consist.NotExported {
			continue
		}
		for k := 0; k < 40; k++ {
			rt := randomRoute(r, d.From)
			rt.Prefix = f.Example
			if !cm.givenHolds(t, rt, f.Given, p.AF.AFI) {
				continue
			}
			an, ac := decide(rt)
			if f.Kind == consist.NotImported && !(an && !ac) {
				fail("not-imported example, route %v: the model says announced %v, accepted %v", rt, an, ac)
			}
			if f.Kind == consist.NotExported && !(ac && !an) {
				fail("not-exported example, route %v: the model says announced %v, accepted %v", rt, an, ac)
			}
		}
	}
	// Completeness: every sampled route announced and refused (accepted and
	// not announced) is in a finding of that kind, or an undecided one.
	covered := func(rt routemodel.Route, kind consist.Kind) bool {
		for _, f := range d.Findings {
			if (f.Kind == kind || f.Kind == consist.Undecided && f.Of == kind) &&
				types.SpaceOf(f.Ranges...).Contains(rt.Prefix) && cm.givenHolds(t, rt, f.Given, p.AF.AFI) {
				return true
			}
		}
		return false
	}
	for k := 0; k < 200; k++ {
		rt := randomRoute(r, d.From)
		if prefixAFI(rt.Prefix) != p.AF.AFI {
			continue
		}
		an, ac := decide(rt)
		if an && !ac && !covered(rt, consist.NotImported) {
			fail("route %v is announced and refused, and no finding covers it", rt)
		}
		if ac && !an && !covered(rt, consist.NotExported) {
			fail("route %v is accepted and not announced, and no finding covers it", rt)
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

// requireCounts fails when the model did not exercise each kind of finding.
func requireCounts(t *testing.T, label string, kc consistCounts, floor int) {
	t.Helper()
	t.Logf("%s: %v", label, kc)
	for _, k := range []string{"not-imported", "not-exported", "no-import", "no-export",
		"undecided/not-imported/" + consist.WhySymbolic, "undecided/not-imported/" + consist.WhyImporterUndecided} {
		if kc[k] < floor {
			t.Errorf("%s: only %d %s findings", label, kc[k], k)
		}
	}
}

func TestModelConsist(t *testing.T) {
	kc := consistCounts{}
	for seed := uint64(0); seed < 300; seed++ {
		r := rand.New(rand.NewPCG(seed, 41))
		cm := randomConsist(t, r, seed)
		c := &consist.Checker{Eval: peval.Evaluator{Src: resolve.NewMemSource(decodeAll(t, cm.texts), "RIPE", "RADB")}, MaxRanges: 1 << 16}
		cm.check(t, fmt.Sprintf("seed %d", seed), c, r, kc)
	}
	requireCounts(t, "memsource", kc, 10)
}

// The same over a Corpus with IndexPeers, whose NamedBy is held to the
// model too, and over the network backends against an IRRd-like server.
func TestModelConsistBackends(t *testing.T) {
	kcs := map[string]consistCounts{"corpus": {}, "irrd": {}, "whois": {}}
	for seed := uint64(0); seed < 60; seed++ {
		r := rand.New(rand.NewPCG(seed, 41))
		cm := randomConsist(t, r, seed)
		l := &resolve.DumpLoader{Sources: []string{"RIPE", "RADB"}, IndexPeers: true}
		if err := l.Read(strings.NewReader(strings.Join(cm.texts, "\n"))); err != nil {
			t.Fatal(err)
		}
		src := l.Source()
		cm.checkNamedBy(t, fmt.Sprintf("seed %d", seed), src)
		cm.check(t, fmt.Sprintf("corpus seed %d", seed), &consist.Checker{Eval: peval.Evaluator{Src: src}, MaxRanges: 1 << 16}, r, kcs["corpus"])
		db := irrtest.New(cm.texts...).WithSources("RIPE", "RADB")
		ir := &irrd.Source{Addr: db.IRRd(t), Sources: []string{"RIPE", "RADB"}, Pipeline: 8, Timeout: 5 * time.Second}
		cm.check(t, fmt.Sprintf("irrd seed %d", seed), &consist.Checker{Eval: peval.Evaluator{Src: ir}, MaxRanges: 1 << 16}, r, kcs["irrd"])
		ir.Close()
		wh := &whois.Source{Addr: db.Whois(t), Sources: []string{"RIPE", "RADB"}, Timeout: 5 * time.Second}
		cm.check(t, fmt.Sprintf("whois seed %d", seed), &consist.Checker{Eval: peval.Evaluator{Src: wh}, MaxRanges: 1 << 16}, r, kcs["whois"])
	}
	for _, b := range []string{"corpus", "irrd", "whois"} {
		requireCounts(t, b, kcs[b], 2)
	}
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
				got[f.Kind] = got[f.Kind].Union(types.SpaceOf(f.Ranges...))
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
