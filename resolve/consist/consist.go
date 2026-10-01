// Package consist checks routing policy for consistency between neighbours
// and lints an aut-num's policies (design §8.12).
//
// For a BGP session between A and B in one address family, Check compares
// what A's export toward B permits announcing with what B's import from A
// accepts, and the reverse. It reads both sides through peval and decides
// the prefix parts exactly (types.PrefixSpace). AS-path and community tests
// are compared by identity only: a finding over them is stated with Given
// (any route passing those tests, with a prefix in Ranges, is refused), and
// a part that cannot be decided is an Undecided finding, never a guess. An
// AS-path regexp is never evaluated here.
//
// The package is pure: no network, all I/O through the Evaluator's
// resolve.PolicySource.
package consist

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/types"
)

// Checker compares neighbours' policies and lints aut-nums. It holds no
// per-call state, so one value serves concurrent calls; wrap Eval.Src in
// resolve.Cache to share lookups across them.
type Checker struct {
	// Eval reads both sides' policies: Src, Expander limits, Source
	// (registry). Expander.Exclude is ignored: consistency compares the
	// policies' text, and an exclusion would make accepted routes look
	// refused.
	Eval      peval.Evaluator
	MaxRanges int // cap on Finding.Ranges; 0 means 64
}

// eval is c.Eval with Expander.Exclude cleared: every evaluation consist
// makes goes through it.
func (c *Checker) eval() *peval.Evaluator {
	e := c.Eval
	e.Expander.Exclude = resolve.Exclusion{}
	return &e
}

func (c *Checker) maxRanges() int {
	if c.MaxRanges > 0 {
		return c.MaxRanges
	}
	return 64
}

// Pair is one BGP session seen from both ends, in one address family:
// ipv4.unicast or ipv6.unicast. The routers are optional: a term that needs
// one becomes Undecided, as in peval.
type Pair struct {
	A, B       types.ASN
	AF         types.AddrFamily
	ARtr, BRtr netip.Addr
}

// Report is what Check found for a Pair.
type Report struct {
	Pair       Pair
	AtoB, BtoA Direction
	missing    []types.SetRef
	routers    []string
}

// Missing lists the sets either side named that the Source does not have,
// sorted by String().
func (r Report) Missing() []types.SetRef { return r.missing }

// MissingRouters lists the inet-rtrs either side named that the Source does
// not have, sorted.
func (r Report) MissingRouters() []string { return r.routers }

// Direction is one way routes flow: From's export toward To against To's
// import from From. No findings: the two agree — or, with NoPolicy, have
// nothing to agree on.
type Direction struct {
	From, To types.ASN
	Findings []Finding
	// NoPolicy: neither side has any term, decided or undecided, toward the
	// other in this family (Findings is then empty). It is false when an
	// aut-num is missing.
	NoPolicy bool
}

// Finding is one way a Direction's two policies disagree, or could.
type Finding struct {
	Kind     Kind
	Of       Kind         // Undecided only: what it may be (NotImported, NotExported, NoImport, NoExport)
	Severity ast.Severity // Warning or Info, by Kind
	AS       types.ASN    // NoAutNum only: the AS whose aut-num is missing

	Example   netip.Prefix        // one prefix in Ranges; zero when the finding names no prefix
	Ranges    []types.PrefixRange // the prefixes concerned, canonical (types.PrefixSpace.Ranges); nil when none
	Truncated bool                // Ranges stopped at Checker.MaxRanges

	// Given lists the AS-path and community tests a route must also pass for
	// the finding to hold, as normal-form text ("<^ AS1+ $>", "NOT
	// community(1:2)"); empty, it holds for every route with a prefix in
	// Ranges.
	Given []string

	Export []int  // the exporting side's clause Index values whose terms are concerned
	Import []int  // the importing side's
	Why    string // Undecided only: one of the Why constants
}

// Kind is what a Finding says.
type Kind uint8

const (
	NotImported Kind = iota // Warning: From permits announcing routes To refuses
	NotExported             // Info: To accepts routes From does not permit announcing
	NoImport                // Warning: From exports to To; no import term of To covers From
	NoExport                // Info: To imports from From; no export term of From covers To
	NoAutNum                // Warning: From's or To's aut-num is not in the Source
	Undecided               // Info: part of the comparison cannot be decided; Of and Why say which
)

var kindNames = [...]string{"not-imported", "not-exported", "no-import", "no-export", "no-aut-num", "undecided"}

func (k Kind) String() string {
	if int(k) < len(kindNames) {
		return kindNames[k]
	}
	return fmt.Sprintf("Kind(%d)", k)
}

func (k Kind) severity() ast.Severity {
	switch k {
	case NotImported, NoImport, NoAutNum:
		return ast.Warning
	}
	return ast.Info
}

// The reasons an Undecided finding gives.
const (
	WhySymbolic          = "symbolic test on one side only" // an AS-path or community test the other side does not hold
	WhyImporterUndecided = "importer has undecided terms"   // To's import has a term peval cannot decide
	WhyExporterUndecided = "exporter has undecided terms"   // From's export has a term peval cannot decide
)

// Whys returns every Why value Check reports, as peval.Whys does.
func Whys() []string { return []string{WhySymbolic, WhyImporterUndecided, WhyExporterUndecided} }

// session is the peval.Session of local's policy toward peer.
func (c *Checker) session(local, peer types.ASN, lrtr, prtr netip.Addr, af types.AddrFamily) peval.Session {
	return peval.Session{Local: local, Peer: peer, LocalRtr: lrtr, PeerRtr: prtr, AF: af}
}

// Check compares A's export toward B with B's import from A (AtoB), and
// B's export toward A with A's import from B (BtoA). A missing aut-num is a
// NoAutNum finding in each direction, not an error. The error is an invalid
// Pair (an AS unset, A equal to B, or AF not ipv4.unicast or ipv6.unicast),
// a limit, a filter that cannot be evaluated for the session (wrapping a
// *resolve.AnySetError or *resolve.NotEnumerableError: Lint reports it as
// lint/undecided), a cancelled context, or a Source failure.
func (c *Checker) Check(ctx context.Context, p Pair) (Report, error) {
	switch {
	case p.A == 0 || p.B == 0:
		return Report{}, errors.New("consist: Pair.A and Pair.B must be set")
	case p.A == p.B:
		return Report{}, errors.New("consist: Pair.A and Pair.B are the same AS")
	case p.AF != (types.AddrFamily{AFI: types.AFIv4, SAFI: types.SAFIUnicast}) &&
		p.AF != (types.AddrFamily{AFI: types.AFIv6, SAFI: types.SAFIUnicast}):
		return Report{}, fmt.Errorf("consist: Pair.AF %v: must be ipv4.unicast or ipv6.unicast", p.AF)
	}
	r := Report{Pair: p, AtoB: Direction{From: p.A, To: p.B}, BtoA: Direction{From: p.B, To: p.A}}
	aExp, aImp, aErr := c.policies(ctx, c.session(p.A, p.B, p.ARtr, p.BRtr, p.AF))
	bExp, bImp, bErr := c.policies(ctx, c.session(p.B, p.A, p.BRtr, p.ARtr, p.AF))
	for _, err := range []error{aErr, bErr} {
		if err != nil && !errors.Is(err, resolve.ErrNotFound) {
			return Report{}, err
		}
	}
	if aErr != nil || bErr != nil {
		missing := p.B
		if aErr != nil {
			missing = p.A
		}
		f := Finding{Kind: NoAutNum, Severity: NoAutNum.severity(), AS: missing}
		r.AtoB.Findings = []Finding{f}
		r.BtoA.Findings = []Finding{f}
		return r, nil
	}
	ae, ai, be, bi := sideOf(aExp), sideOf(aImp), sideOf(bExp), sideOf(bImp)
	r.AtoB.Findings, r.AtoB.NoPolicy = c.direction(ae, bi, p.AF.AFI), ae.none() && bi.none()
	r.BtoA.Findings, r.BtoA.NoPolicy = c.direction(be, ai, p.AF.AFI), be.none() && ai.none()
	r.missing = mergeSorted(func(a, b types.SetRef) int { return cmp.Compare(a.String(), b.String()) },
		aExp.Missing(), aImp.Missing(), bExp.Missing(), bImp.Missing())
	r.routers = mergeSorted(strings.Compare, aExp.MissingRouters(), aImp.MissingRouters(), bExp.MissingRouters(), bImp.MissingRouters())
	return r, nil
}

// policies evaluates s.Local's export and import for the session. When both
// aut-nums are missing, Check reports A's: an error wrapping ErrNotFound.
func (c *Checker) policies(ctx context.Context, s peval.Session) (exp, imp peval.Policy, err error) {
	e := c.eval()
	if exp, err = e.Export(ctx, s); err != nil {
		return
	}
	imp, err = e.Import(ctx, s)
	return
}

func mergeSorted[T comparable](cmpf func(a, b T) int, lists ...[]T) []T {
	var out []T
	for _, l := range lists {
		out = append(out, l...)
	}
	slices.SortFunc(out, cmpf)
	return slices.Compact(out)
}

// conj is a decided conjunct as consistency reads it.
type conj struct {
	sig      []string // sorted symbolic tests, as text
	space    types.PrefixSpace
	index    int  // the clause's attribute Index
	path     bool // sig holds an AS-path test
	comm     bool // sig holds a community test
	commActs bool // the clause's actions change communities
}

// side is one peval.Policy, as consistency reads it.
type side struct {
	conjs     []conj
	clauses   bool  // the policy has a decided clause for the session
	undecided bool  // the policy has a term peval cannot decide
	undIdx    []int // the undecided terms' attribute Index values, ascending
}

func sideOf(p peval.Policy) side {
	s := side{clauses: len(p.Clauses) > 0, undecided: len(p.Undecided) > 0}
	for _, u := range p.Undecided {
		s.undIdx = append(s.undIdx, u.Index)
	}
	slices.Sort(s.undIdx)
	s.undIdx = slices.Compact(s.undIdx)
	for _, cl := range p.Clauses {
		acts := slices.ContainsFunc(cl.Actions, func(a policy.Action) bool { return a.Attr == "community" })
		for _, cj := range cl.Filter.Conjuncts {
			s.conjs = append(s.conjs, conj{sig: signature(cj), space: cj.Space(), index: cl.Index,
				path: len(cj.Paths) > 0, comm: len(cj.Communities) > 0, commActs: acts})
		}
	}
	return s
}

// none reports whether the side has no term at all, decided or undecided.
func (s side) none() bool { return !s.clauses && !s.undecided }

// signature returns a conjunct's AS-path and community tests as normal-form
// text, sorted and without repeats: what two conjuncts must share to be
// compared exactly.
func signature(c resolve.Conjunct) []string {
	var out []string
	for _, p := range c.Paths {
		s := "<" + p.RE.String() + ">"
		if p.Negated {
			s = "NOT " + s
		}
		out = append(out, s)
	}
	for _, m := range c.Communities {
		s := m.Test.String()
		if m.Negated {
			s = "NOT " + s
		}
		out = append(out, s)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// subset reports whether every test in a is in b (both sorted).
func subset(a, b []string) bool {
	for _, x := range a {
		if _, ok := slices.BinarySearch(b, x); !ok {
			return false
		}
	}
	return true
}

// direction compares From's export side with To's import side, in the
// session's family afi.
func (c *Checker) direction(exp, imp side, afi types.AFI) []Finding {
	var out []Finding
	// A one-sided direction whose decided side permits nothing in the
	// family is read as if that side had no decided clause (Ruling R15): a
	// NoImport (NoExport) finding would name no prefix, and the two-sided
	// path has none either. Its undecided terms still count.
	expD, impD := exp.clauses, imp.clauses
	switch {
	case expD && !impD && union(exp.conjs).IsEmpty():
		expD = false
	case impD && !expD && union(imp.conjs).IsEmpty():
		impD = false
	}
	switch {
	case !expD && !impD:
		// Neither side has a decided clause. The exporter's undecided terms
		// may export to To, so the direction may be NoImport; the importer's
		// may import from From, so it may be NoExport. Those terms name no
		// prefix Check can state: the findings have no space.
		if exp.undecided {
			out = append(out, c.finish(Finding{Kind: Undecided, Of: NoImport, Why: WhyExporterUndecided}, types.PrefixSpace{}))
		}
		if imp.undecided {
			out = append(out, c.finish(Finding{Kind: Undecided, Of: NoExport, Why: WhyImporterUndecided}, types.PrefixSpace{}))
		}
		return out
	case expD && !impD:
		f := Finding{Kind: NoImport, Export: indexes(exp.conjs, types.FullSpace(types.AFIAny))}
		if imp.undecided {
			f = Finding{Kind: Undecided, Of: NoImport, Why: WhyImporterUndecided, Export: f.Export}
		}
		return []Finding{c.finish(f, union(exp.conjs))}
	case !expD && impD:
		f := Finding{Kind: NoExport, Import: indexes(imp.conjs, types.FullSpace(types.AFIAny))}
		if exp.undecided {
			f = Finding{Kind: Undecided, Of: NoExport, Why: WhyExporterUndecided, Import: f.Import}
		}
		return []Finding{c.finish(f, union(imp.conjs))}
	}
	for _, f := range c.compare(exp, imp, NotImported) {
		if f.Kind == NotImported && imp.undecided {
			f.Kind, f.Of, f.Why, f.Severity = Undecided, NotImported, WhyImporterUndecided, Undecided.severity()
		}
		out = append(out, f)
	}
	for _, f := range c.compare(imp, exp, NotExported) {
		if f.Kind == NotExported && exp.undecided {
			f.Kind, f.Of, f.Why, f.Severity = Undecided, NotExported, WhyExporterUndecided, Undecided.severity()
		}
		out = append(out, f)
	}
	// Ruling R14: the exporter's undecided terms may announce any route of
	// the family, and the importer surely accepts only what its conjuncts
	// with no symbolic test do (any other test may read the route
	// differently across the session); the importer's undecided terms, the
	// mirror. Each finding names the undecided terms' attributes.
	if exp.undecided {
		if sp := types.FullSpace(afi).Minus(union(plain(imp.conjs))); !sp.IsEmpty() {
			out = append(out, c.finish(Finding{Kind: Undecided, Of: NotImported, Why: WhyExporterUndecided, Export: exp.undIdx}, sp))
		}
	}
	if imp.undecided {
		if sp := types.FullSpace(afi).Minus(union(plain(exp.conjs))); !sp.IsEmpty() {
			out = append(out, c.finish(Finding{Kind: Undecided, Of: NotExported, Why: WhyImporterUndecided, Import: imp.undIdx}, sp))
		}
	}
	slices.SortFunc(out, compareFindings)
	return out
}

// plain returns the conjuncts with no symbolic test.
func plain(cs []conj) []conj {
	var out []conj
	for _, cj := range cs {
		if len(cj.sig) == 0 {
			out = append(out, cj)
		}
	}
	return out
}

// compare finds what src's conjuncts accept and dst's do not (§4.3): kind
// is NotImported (src the export side) or NotExported (src the import side).
//
// A dst conjunct decides a src group's routes ("sure") only when its tests
// are among the group's and still mean the same across the session (Ruling
// R13): the importer reads a route after the exporter prepends its AS and
// applies its export actions. So a dst conjunct with an AS-path test is
// never sure, and one with a community test only when the exporter's clause
// involved changes no community: for NotImported the src group's clauses,
// for NotExported the dst conjunct's own. Every other dst conjunct is
// "maybe", and what only it may decide is Undecided (WhySymbolic).
func (c *Checker) compare(src, dst side, kind Kind) []Finding {
	groups := map[string][]conj{}
	var keys []string
	for _, cj := range src.conjs {
		k := strings.Join(cj.sig, "\x00")
		if _, ok := groups[k]; !ok {
			keys = append(keys, k)
		}
		groups[k] = append(groups[k], cj)
	}
	slices.Sort(keys)
	var out []Finding
	for _, k := range keys {
		g := groups[k]
		sig := g[0].sig
		groupActs := slices.ContainsFunc(g, func(cj conj) bool { return cj.commActs })
		var sure, maybe []conj
		for _, d := range dst.conjs {
			acts := d.commActs // NotExported: the exporter's clause is d's
			if kind == NotImported {
				acts = groupActs
			}
			if subset(d.sig, sig) && !d.path && !(d.comm && acts) {
				sure = append(sure, d)
			} else {
				maybe = append(maybe, d)
			}
		}
		rest := union(g).Minus(union(sure))
		if rest.IsEmpty() {
			continue
		}
		mb := union(maybe)
		if def := rest.Minus(mb); !def.IsEmpty() {
			out = append(out, c.finish(c.roles(Finding{Kind: kind, Given: sig}, g, nil, def, kind), def))
		}
		if und := rest.Intersect(mb); !und.IsEmpty() {
			f := Finding{Kind: Undecided, Of: kind, Why: WhySymbolic, Given: sig}
			out = append(out, c.finish(c.roles(f, g, maybe, und, kind), und))
		}
	}
	return out
}

// roles fills the finding's Export and Import from the src and dst
// conjuncts whose space meets sp: src is the export side for NotImported,
// the import side for NotExported.
func (c *Checker) roles(f Finding, src, dst []conj, sp types.PrefixSpace, kind Kind) Finding {
	s, d := indexes(src, sp), indexes(dst, sp)
	if kind == NotImported {
		f.Export, f.Import = s, d
	} else {
		f.Import, f.Export = s, d
	}
	return f
}

// indexes returns the clause Index values of the conjuncts meeting sp,
// ascending, without repeats.
func indexes(cs []conj, sp types.PrefixSpace) []int {
	var out []int
	for _, cj := range cs {
		if !cj.space.Intersect(sp).IsEmpty() {
			out = append(out, cj.index)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func union(cs []conj) types.PrefixSpace {
	var s types.PrefixSpace
	for _, cj := range cs {
		s = s.Union(cj.space)
	}
	return s
}

// finish sets the finding's severity, example and ranges from sp.
func (c *Checker) finish(f Finding, sp types.PrefixSpace) Finding {
	f.Severity = f.Kind.severity()
	f.Example, _ = sp.Example()
	for r := range sp.Ranges() {
		if len(f.Ranges) == c.maxRanges() {
			f.Truncated = true
			break
		}
		f.Ranges = append(f.Ranges, r)
	}
	return f
}

// compareFindings orders findings by Kind, Of, Given, Example, then Why.
func compareFindings(a, b Finding) int {
	if c := cmp.Compare(a.Kind, b.Kind); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Of, b.Of); c != 0 {
		return c
	}
	if c := cmp.Compare(strings.Join(a.Given, "\x00"), strings.Join(b.Given, "\x00")); c != 0 {
		return c
	}
	if a.Example.Addr().Is4() != b.Example.Addr().Is4() {
		if a.Example.Addr().Is4() {
			return -1
		}
		return 1
	}
	if c := a.Example.Addr().Compare(b.Example.Addr()); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Example.Bits(), b.Example.Bits()); c != 0 {
		return c
	}
	return cmp.Compare(a.Why, b.Why)
}
