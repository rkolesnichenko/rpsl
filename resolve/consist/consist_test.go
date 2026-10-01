package consist

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/types"
)

var (
	v4 = types.AddrFamily{AFI: types.AFIv4, SAFI: types.SAFIUnicast}
	v6 = types.AddrFamily{AFI: types.AFIv6, SAFI: types.SAFIUnicast}
)

// base is the registry every table test adds its aut-nums to: AS1's and
// AS2's routes, a customer as-set and a route-set.
const base = `route: 10.1.0.0/16
origin: AS1
mnt-by: MNT-A
source: RIPE

route: 10.2.0.0/16
origin: AS2
mnt-by: MNT-A
source: RIPE

route6: 2001:db8:1::/48
origin: AS1
mnt-by: MNT-A
source: RIPE

as-set: AS-ONE
members: AS1
mnt-by: MNT-A
source: RIPE

as-set: AS-PEERS
members: AS1, AS3
mnt-by: MNT-A
source: RIPE
`

func checker(t *testing.T, objects ...string) *Checker {
	t.Helper()
	var objs []object.Object
	for _, text := range append(strings.Split(base, "\n\n"), objects...) {
		raw, ds := rpsl.ParseObject(text)
		for _, d := range ds {
			if d.Severity >= ast.Error {
				t.Fatalf("%v\n%s", d, text)
			}
		}
		o, ds := rpsl.Decode(raw)
		for _, d := range ds {
			if d.Severity >= ast.Error {
				t.Fatalf("%v\n%s", d, text)
			}
		}
		objs = append(objs, o)
	}
	return &Checker{Eval: peval.Evaluator{Src: resolve.NewMemSource(objs)}, MaxRanges: 1000}
}

// autNum is an aut-num of as with the given policy lines (none: an aut-num
// with no policy).
func autNum(as int, lines ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "aut-num: AS%d\nas-name: X\n", as)
	for _, l := range lines {
		b.WriteString(l + "\n")
	}
	b.WriteString("mnt-by: MNT-A\nsource: RIPE\n")
	return b.String()
}

func check(t *testing.T, c *Checker, p Pair) Report {
	t.Helper()
	r, err := c.Check(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func mustRange(t *testing.T, s string) types.PrefixRange {
	t.Helper()
	r, err := types.ParsePrefixRange(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// kinds renders a direction's findings without their ranges.
func kinds(d Direction) []string {
	var out []string
	for _, f := range d.Findings {
		s := f.Kind.String()
		if f.Kind == Undecided {
			s += "[" + f.Of.String() + ":" + f.Why + "]"
		}
		if len(f.Given) > 0 {
			s += "|" + strings.Join(f.Given, " AND ")
		}
		out = append(out, s)
	}
	return out
}

// spaceOfFindings is the union of a direction's findings of one kind.
func spaceOfFindings(d Direction, k Kind) types.PrefixSpace {
	var s types.PrefixSpace
	for _, f := range d.Findings {
		if f.Kind == k {
			s = s.Union(types.SpaceOf(f.Ranges...))
		}
	}
	return s
}

func TestCheckTable(t *testing.T) {
	notOne := types.FullSpace(types.AFIv4).Minus(types.SpaceOf(mustRange(t, "10.1.0.0/16")))
	for _, c := range []struct {
		name       string
		a, b       string
		af         types.AddrFamily
		atob, btoa []string
		space      *types.PrefixSpace // when set: the union of AtoB's first finding kind equals it
	}{
		{name: "customer to provider, matching sets",
			a: autNum(1, "export: to AS2 announce AS-ONE", "import: from AS2 accept ANY"),
			b: autNum(2, "import: from AS1 accept AS-ONE", "export: to AS1 announce ANY"), af: v4},
		{name: "a customer announcing ANY: a leak the provider refuses",
			a: autNum(1, "export: to AS2 announce ANY", "import: from AS2 accept ANY"),
			b: autNum(2, "import: from AS1 accept AS-ONE", "export: to AS1 announce ANY"), af: v4,
			atob: []string{"not-imported"}, space: &notOne},
		{name: "accept ANY against a narrow export",
			a: autNum(1, "export: to AS2 announce AS-ONE"),
			b: autNum(2, "import: from AS1 accept ANY"), af: v4,
			atob: []string{"not-exported"}, space: &notOne},
		{name: "one-sided: no import",
			a: autNum(1, "export: to AS2 announce AS-ONE"),
			b: autNum(2, "import: from AS3 accept ANY"), af: v4,
			atob: []string{"no-import"}},
		{name: "one-sided: no export",
			a: autNum(1, "import: from AS2 accept ANY"),
			b: autNum(2, "import: from AS3 accept ANY"), af: v4,
			btoa: []string{"no-export"}},
		{name: "neither side: no findings",
			a: autNum(1, "import: from AS3 accept ANY"),
			b: autNum(2, "import: from AS3 accept ANY"), af: v4},
		{name: "an as-set peering on one side, an AS number on the other",
			a: autNum(1, "export: to AS2 announce AS-ONE"),
			b: autNum(2, "import: from AS-PEERS accept AS-ONE"), af: v4},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := check(t, checker(t, c.a, c.b), Pair{A: 1, B: 2, AF: c.af})
			if got := kinds(r.AtoB); !slices.Equal(got, c.atob) {
				t.Errorf("AtoB %v, want %v", got, c.atob)
			}
			if got := kinds(r.BtoA); !slices.Equal(got, c.btoa) {
				t.Errorf("BtoA %v, want %v", got, c.btoa)
			}
			if c.space != nil {
				k := r.AtoB.Findings[0].Kind
				if got := spaceOfFindings(r.AtoB, k); !got.Equal(*c.space) {
					t.Errorf("AtoB %v space %v, want %v", k, got, *c.space)
				}
			}
		})
	}
}

// Review Focus 4: ANY covers the session's family only.
func TestAnyIsPerFamily(t *testing.T) {
	c := checker(t,
		autNum(1, "export: to AS2 announce ANY", "mp-export: afi ipv6.unicast to AS2 announce ANY"),
		autNum(2, "mp-import: afi any from AS1 accept AS-ONE"))
	r := check(t, c, Pair{A: 1, B: 2, AF: v6})
	want := types.FullSpace(types.AFIv6).Minus(types.SpaceOf(mustRange(t, "2001:db8:1::/48")))
	if got := kinds(r.AtoB); !slices.Equal(got, []string{"not-imported"}) {
		t.Fatalf("AtoB %v", got)
	}
	if got := spaceOfFindings(r.AtoB, NotImported); !got.Equal(want) {
		t.Errorf("IPv6 session: not-imported %v, want every IPv6 prefix but AS1's", got)
	}
	for _, f := range r.AtoB.Findings {
		for _, rg := range f.Ranges {
			if rg.Prefix().Addr().Is4() {
				t.Errorf("IPv6 session has an IPv4 range %v", rg)
			}
		}
	}
}

// Review Focus 1: a symbolic conjunct never yields an unconditional finding.
func TestSymbolicIsConditional(t *testing.T) {
	// Export side only: the regexp is AS1's, the import has no such test.
	c := checker(t,
		autNum(1, "export: to AS2 announce <^AS1+$>"),
		autNum(2, "import: from AS1 accept AS-ONE"))
	r := check(t, c, Pair{A: 1, B: 2, AF: v4})
	if len(r.AtoB.Findings) == 0 {
		t.Fatal("no findings")
	}
	for _, f := range r.AtoB.Findings {
		if (f.Kind == NotImported || f.Kind == NotExported) && len(f.Given) == 0 {
			t.Errorf("finding %+v over a regexp is unconditional", f)
		}
	}
	// AS1's regexp-filtered announcements outside AS-ONE are refused, given
	// the regexp; whether AS1 announces AS-ONE's own route depends on its
	// path, which is never evaluated: undecided.
	if got := kinds(r.AtoB); !slices.Equal(got, []string{"not-imported|<^ AS1+ $>", "undecided[not-exported:" + WhySymbolic + "]"}) {
		t.Errorf("AtoB %v", got)
	}
	// The same regexp on both sides is not the same test (Ruling R13): AS2
	// reads the path after AS1 prepends itself, so whether AS2 accepts what
	// AS1's regexp passes is undecided, both ways.
	c = checker(t,
		autNum(1, "export: to AS2 announce <^AS1+$>"),
		autNum(2, "import: from AS1 accept <^AS1+$>"))
	r = check(t, c, Pair{A: 1, B: 2, AF: v4})
	if got := kinds(r.AtoB); !slices.Equal(got, []string{"undecided[not-imported:" + WhySymbolic + "]|<^ AS1+ $>",
		"undecided[not-exported:" + WhySymbolic + "]|<^ AS1+ $>"}) {
		t.Errorf("identical regexps: AtoB %v", got)
	}
	// A test on the import side only: AS2 may refuse what AS1 announces.
	c = checker(t,
		autNum(1, "export: to AS2 announce AS-ONE"),
		autNum(2, "import: from AS1 accept <^AS1$>"))
	r = check(t, c, Pair{A: 1, B: 2, AF: v4})
	if got := kinds(r.AtoB); !slices.Equal(got, []string{"not-exported|<^ AS1 $>", "undecided[not-imported:" + WhySymbolic + "]"}) {
		t.Errorf("import-only regexp: AtoB %v", got)
	}
}

// Review Focus 2: undecided terms demote.
func TestDemotion(t *testing.T) {
	// AS2's import names a router the session does not give: undecided.
	c := checker(t,
		autNum(1, "export: to AS2 announce ANY"),
		autNum(2, "import: from AS1 accept AS-ONE", "import: from AS1 192.0.2.1 accept ANY"))
	r := check(t, c, Pair{A: 1, B: 2, AF: v4})
	if got := kinds(r.AtoB); !slices.Equal(got, []string{"undecided[not-imported:" + WhyImporterUndecided + "]"}) {
		t.Errorf("importer undecided: AtoB %v", got)
	}
	// With the router given, it is decided, and accepts everything.
	r = check(t, c, Pair{A: 1, B: 2, AF: v4, ARtr: netip.MustParseAddr("192.0.2.1")})
	if len(r.AtoB.Findings) != 0 {
		t.Errorf("router given: AtoB %v", kinds(r.AtoB))
	}
	// The exporter's undecided term demotes not-exported.
	c = checker(t,
		autNum(1, "export: to AS2 announce AS-ONE", "export: to AS2 192.0.2.2 announce ANY"),
		autNum(2, "import: from AS1 accept ANY"))
	r = check(t, c, Pair{A: 1, B: 2, AF: v4})
	if got := kinds(r.AtoB); !slices.Equal(got, []string{"undecided[not-exported:" + WhyExporterUndecided + "]"}) {
		t.Errorf("exporter undecided: AtoB %v", got)
	}
	// An undecided importer with no decided term: may be no-import.
	c = checker(t,
		autNum(1, "export: to AS2 announce AS-ONE"),
		autNum(2, "import: from AS1 192.0.2.1 accept ANY"))
	r = check(t, c, Pair{A: 1, B: 2, AF: v4})
	if got := kinds(r.AtoB); !slices.Equal(got, []string{"undecided[no-import:" + WhyImporterUndecided + "]"}) {
		t.Errorf("only undecided import: AtoB %v", got)
	}
}

func TestNoAutNum(t *testing.T) {
	c := checker(t, autNum(1, "export: to AS2 announce AS-ONE"))
	r := check(t, c, Pair{A: 1, B: 2, AF: v4})
	for _, d := range []Direction{r.AtoB, r.BtoA} {
		if len(d.Findings) != 1 || d.Findings[0].Kind != NoAutNum || d.Findings[0].AS != 2 || d.Findings[0].Severity != ast.Warning {
			t.Errorf("%v→%v: %+v, want one no-aut-num for AS2", d.From, d.To, d.Findings)
		}
	}
}

func TestFindingDetails(t *testing.T) {
	c := checker(t,
		autNum(1, "export: to AS2 announce AS-ONE", "export: to AS2 announce {192.0.2.0/24}"),
		autNum(2, "import: from AS1 accept AS-ONE"))
	r := check(t, c, Pair{A: 1, B: 2, AF: v4})
	if len(r.AtoB.Findings) != 1 {
		t.Fatalf("AtoB %v", kinds(r.AtoB))
	}
	f := r.AtoB.Findings[0]
	if f.Kind != NotImported || f.Severity != ast.Warning || f.Example.String() != "192.0.2.0/24" {
		t.Errorf("finding %+v", f)
	}
	if !slices.Equal(f.Export, []int{1}) || len(f.Import) != 0 {
		t.Errorf("Export %v Import %v, want [1] []", f.Export, f.Import)
	}
	if r.AtoB.From != 1 || r.AtoB.To != 2 || r.BtoA.From != 2 || r.BtoA.To != 1 {
		t.Errorf("directions %v→%v, %v→%v", r.AtoB.From, r.AtoB.To, r.BtoA.From, r.BtoA.To)
	}
}

func TestMaxRanges(t *testing.T) {
	c := checker(t,
		autNum(1, "export: to AS2 announce ANY"),
		autNum(2, "import: from AS1 accept AS-ONE"))
	c.MaxRanges = 3
	r := check(t, c, Pair{A: 1, B: 2, AF: v4})
	if len(r.AtoB.Findings) == 0 {
		t.Fatal("no findings")
	}
	f := r.AtoB.Findings[0]
	if len(f.Ranges) != 3 || !f.Truncated {
		t.Errorf("%d ranges, truncated %v; want 3, true", len(f.Ranges), f.Truncated)
	}
	c.MaxRanges = 0 // the default, 64
	r = check(t, c, Pair{A: 1, B: 2, AF: v4})
	if len(r.AtoB.Findings) == 0 {
		t.Fatal("default cap: no findings")
	}
	if f := r.AtoB.Findings[0]; f.Truncated || len(f.Ranges) > 64 {
		t.Errorf("default cap: %d ranges, truncated %v", len(f.Ranges), f.Truncated)
	}
}

func TestMissingSets(t *testing.T) {
	c := checker(t,
		autNum(1, "export: to AS2 announce AS-NOPE"),
		autNum(2, "import: from AS1 accept AS-ONE"))
	r := check(t, c, Pair{A: 1, B: 2, AF: v4})
	if got := fmt.Sprint(r.Missing()); got != "[AS-NOPE]" {
		t.Errorf("Missing %s", got)
	}
}

func TestCheckRejectsBadPairs(t *testing.T) {
	c := checker(t)
	for _, p := range []Pair{{A: 0, B: 2, AF: v4}, {A: 1, B: 0, AF: v4}, {A: 1, B: 1, AF: v4}, {A: 1, B: 2},
		{A: 1, B: 2, AF: types.AddrFamily{AFI: types.AFIAny, SAFI: types.SAFIUnicast}},
		{A: 1, B: 2, AF: types.AddrFamily{AFI: types.AFIv4, SAFI: types.SAFIMulticast}},
		{A: 1, B: 2, AF: types.AddrFamily{AFI: types.AFIv4}},
	} {
		if _, err := c.Check(context.Background(), p); err == nil {
			t.Errorf("%+v: no error", p)
		}
	}
}

func TestWhysAndKinds(t *testing.T) {
	if got := Whys(); !slices.Equal(got, []string{WhySymbolic, WhyImporterUndecided, WhyExporterUndecided}) {
		t.Errorf("Whys %v", got)
	}
	for k, want := range map[Kind]string{NotImported: "not-imported", NotExported: "not-exported", NoImport: "no-import",
		NoExport: "no-export", NoAutNum: "no-aut-num", Undecided: "undecided"} {
		if k.String() != want {
			t.Errorf("%d.String() = %q, want %q", k, k.String(), want)
		}
	}
}

// Ruling R4: Expander.Exclude never applies; consistency compares the
// policies' text, and an exclusion would make accepted routes look refused.
func TestExcludeIgnored(t *testing.T) {
	c := checker(t,
		autNum(1, "export: to AS2 announce {10.1.0.0/16}"),
		autNum(2, "import: from AS1 accept AS-ONE"))
	c.Eval.Expander.Exclude = resolve.Exclusion{ASNs: []types.ASN{1}}
	r := check(t, c, Pair{A: 1, B: 2, AF: v4})
	if len(r.AtoB.Findings) != 0 || len(r.BtoA.Findings) != 0 {
		t.Errorf("with Exclude: AtoB %v, BtoA %v; want none", kinds(r.AtoB), kinds(r.BtoA))
	}
	if got := c.Eval.Expander.Exclude.ASNs; !slices.Equal(got, []types.ASN{1}) {
		t.Errorf("Check changed the caller's Exclude: %v", got)
	}
}

// Ruling R6: a side whose only terms are undecided is reported, never dropped.
func TestUndecidedSides(t *testing.T) {
	const (
		expUnd = "export: to AS2 192.0.2.9 announce ANY" // router not given
		impUnd = "import: from AS1 192.0.2.1 accept ANY" // router not given
	)
	for _, c := range []struct {
		name string
		a, b string
		atob []string
	}{
		{name: "exporter only undecided, importer has no term",
			a: autNum(1, expUnd), b: autNum(2, "import: from AS3 accept ANY"),
			atob: []string{"undecided[no-import:" + WhyExporterUndecided + "]"}},
		{name: "importer only undecided, exporter has no term",
			a: autNum(1, "export: to AS3 announce ANY"), b: autNum(2, impUnd),
			atob: []string{"undecided[no-export:" + WhyImporterUndecided + "]"}},
		{name: "both only undecided",
			a: autNum(1, expUnd), b: autNum(2, impUnd),
			atob: []string{"undecided[no-import:" + WhyExporterUndecided + "]", "undecided[no-export:" + WhyImporterUndecided + "]"}},
		{name: "exporter decided, importer only undecided",
			a: autNum(1, "export: to AS2 announce AS-ONE"), b: autNum(2, impUnd),
			atob: []string{"undecided[no-import:" + WhyImporterUndecided + "]"}},
		{name: "importer decided, exporter only undecided",
			a: autNum(1, expUnd), b: autNum(2, "import: from AS1 accept AS-ONE"),
			atob: []string{"undecided[no-export:" + WhyExporterUndecided + "]"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := check(t, checker(t, c.a, c.b), Pair{A: 1, B: 2, AF: v4})
			if got := kinds(r.AtoB); !slices.Equal(got, c.atob) {
				t.Errorf("AtoB %v, want %v", got, c.atob)
			}
			for _, f := range r.AtoB.Findings {
				if f.Severity != ast.Info {
					t.Errorf("%v: severity %v, want Info", f.Kind, f.Severity)
				}
				if c.name == "both only undecided" && (f.Ranges != nil || f.Example.IsValid()) {
					t.Errorf("finding with no space: Ranges %v Example %v", f.Ranges, f.Example)
				}
			}
		})
	}
}

// Ruling R13: a test is never assumed equal across the session boundary.
// The importer sees the route after the exporter prepends its AS and applies
// its export actions, so an identical AS-path test, or an identical community
// test where the exporter's clause changes communities, is undecided.
func TestSessionBoundary(t *testing.T) {
	und := func(of Kind, given string) string {
		return "undecided[" + of.String() + ":" + WhySymbolic + "]|" + given
	}
	for _, c := range []struct {
		name string
		a, b string
		atob []string
	}{
		{name: "identical AS-path regexps",
			a:    autNum(1, "export: to AS2 announce <^AS3>"),
			b:    autNum(2, "import: from AS1 accept <^AS3>"),
			atob: []string{und(NotImported, "<^ AS3>"), und(NotExported, "<^ AS3>")}},
		{name: "identical negated AS-path regexps",
			a:    autNum(1, "export: to AS2 announce NOT <^AS3>"),
			b:    autNum(2, "import: from AS1 accept NOT <^AS3>"),
			atob: []string{und(NotImported, "NOT <^ AS3>"), und(NotExported, "NOT <^ AS3>")}},
		{name: "identical community tests, the exporter appends the community",
			a:    autNum(1, "export: to AS2 action community.append(65000:666); announce NOT community(65000:666)"),
			b:    autNum(2, "import: from AS1 accept NOT community(65000:666)"),
			atob: []string{und(NotImported, "NOT community(65000:666)"), und(NotExported, "NOT community(65000:666)")}},
		{name: "identical community tests, the exporter sets communities",
			a:    autNum(1, "export: to AS2 action community = {1:2}; announce community(1:2)"),
			b:    autNum(2, "import: from AS1 accept community(1:2)"),
			atob: []string{und(NotImported, "community(1:2)"), und(NotExported, "community(1:2)")}},
		{name: "identical community tests, no community action: exact",
			a: autNum(1, "export: to AS2 action med = 5; announce community(1:2)"),
			b: autNum(2, "import: from AS1 accept community(1:2)")},
		{name: "an exporter's regexp against a pure prefix import: exact",
			a:    autNum(1, "export: to AS2 announce <^AS1+$>"),
			b:    autNum(2, "import: from AS1 accept ANY"),
			atob: []string{"undecided[not-exported:" + WhySymbolic + "]"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := check(t, checker(t, c.a, c.b), Pair{A: 1, B: 2, AF: v4})
			if got := kinds(r.AtoB); !slices.Equal(got, c.atob) {
				t.Errorf("AtoB %v, want %v", got, c.atob)
			}
		})
	}
}

// Ruling R14: when both sides have decided clauses, the other side's
// undecided terms may still make a finding: what they may announce (accept)
// the importer (exporter) is not sure to accept (announce), so the
// direction is Undecided over the family's space less the other side's
// conjuncts with no symbolic test — never "consistent".
func TestUndecidedBesideDecided(t *testing.T) {
	notOne := types.FullSpace(types.AFIv4).Minus(types.SpaceOf(mustRange(t, "10.1.0.0/16")))
	for _, c := range []struct {
		name  string
		a, b  string
		atob  []string
		space types.PrefixSpace
	}{
		{name: "exporter has an undecided term",
			a:     autNum(1, "export: to AS2 announce AS-ONE", "export: to AS2 192.0.2.9 announce ANY"),
			b:     autNum(2, "import: from AS1 accept AS-ONE"),
			atob:  []string{"undecided[not-imported:" + WhyExporterUndecided + "]"},
			space: notOne},
		{name: "importer has an undecided term",
			a:     autNum(1, "export: to AS2 announce AS-ONE"),
			b:     autNum(2, "import: from AS1 accept AS-ONE", "import: from AS1 192.0.2.1 accept ANY"),
			atob:  []string{"undecided[not-exported:" + WhyImporterUndecided + "]"},
			space: notOne},
		{name: "exporter undecided, the importer accepts every route: no may-be not-imported",
			a:     autNum(1, "export: to AS2 announce AS-ONE", "export: to AS2 192.0.2.9 announce ANY"),
			b:     autNum(2, "import: from AS1 accept ANY"),
			atob:  []string{"undecided[not-exported:" + WhyExporterUndecided + "]"},
			space: notOne},
		{name: "the importer's only test is symbolic: the whole family",
			a: autNum(1, "export: to AS2 announce AS-ONE", "export: to AS2 192.0.2.9 announce ANY"),
			b: autNum(2, "import: from AS1 accept community(1:2)"),
			atob: []string{"undecided[not-imported:" + WhyExporterUndecided + "]", "undecided[not-imported:" + WhySymbolic + "]",
				"undecided[not-exported:" + WhyExporterUndecided + "]|community(1:2)"},
			space: types.FullSpace(types.AFIv4)},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := check(t, checker(t, c.a, c.b), Pair{A: 1, B: 2, AF: v4})
			if got := kinds(r.AtoB); !slices.Equal(got, c.atob) {
				t.Fatalf("AtoB %v, want %v", got, c.atob)
			}
			if len(c.atob) > 0 {
				f := r.AtoB.Findings[0]
				if got := types.SpaceOf(f.Ranges...); !got.Equal(c.space) {
					t.Errorf("space %v, want %v", got, c.space)
				}
				if f.Severity != ast.Info || f.Truncated {
					t.Errorf("severity %v, truncated %v", f.Severity, f.Truncated)
				}
			}
		})
	}
}

// Ruling R15: a one-sided direction whose decided side permits nothing in
// the family has no NoImport (NoExport) finding, as the two-sided path has
// none; that side's undecided terms still count.
func TestOneSidedEmpty(t *testing.T) {
	for _, c := range []struct {
		name string
		a, b string
		atob []string
	}{
		{name: "the exporter announces nothing in the family",
			a: autNum(1, "mp-export: to AS2 announce AS3"),
			b: autNum(2, "import: from AS1 accept ANY")},
		{name: "the importer accepts nothing in the family",
			a: autNum(1, "export: to AS2 announce ANY"),
			b: autNum(2, "mp-import: from AS1 accept AS3")},
		{name: "the exporter announces nothing decided, and has an undecided term",
			a:    autNum(1, "mp-export: to AS2 announce AS3", "mp-export: to AS2 192.0.2.9 announce ANY"),
			b:    autNum(2, "import: from AS1 accept ANY"),
			atob: []string{"undecided[no-import:" + WhyExporterUndecided + "]"}},
		{name: "the importer accepts nothing decided, and has an undecided term",
			a:    autNum(1, "export: to AS2 announce ANY"),
			b:    autNum(2, "mp-import: from AS1 accept AS3", "mp-import: from AS1 192.0.2.1 accept ANY"),
			atob: []string{"undecided[no-export:" + WhyImporterUndecided + "]"}},
		{name: "the exporter announces something: no-import as before",
			a:    autNum(1, "mp-export: to AS2 announce AS1"),
			b:    autNum(2, "import: from AS1 accept ANY"),
			atob: []string{"no-import"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := check(t, checker(t, c.a, c.b), Pair{A: 1, B: 2, AF: v6})
			if got := kinds(r.AtoB); !slices.Equal(got, c.atob) {
				t.Errorf("AtoB %v, want %v", got, c.atob)
			}
		})
	}
}

// Ruling R15: a direction where neither side has any term toward the other
// in the family is NoPolicy, not merely without findings.
func TestNoPolicy(t *testing.T) {
	for _, c := range []struct {
		name       string
		a, b       string
		af         types.AddrFamily
		atob, btoa bool
	}{
		{name: "neither side names the other",
			a: autNum(1, "import: from AS3 accept ANY"), b: autNum(2, "import: from AS3 accept ANY"), af: v4,
			atob: true, btoa: true},
		{name: "matching sets: consistent, with policy",
			a: autNum(1, "export: to AS2 announce AS-ONE"), b: autNum(2, "import: from AS1 accept AS-ONE"), af: v4,
			btoa: true},
		{name: "legacy policy only: no policy in IPv6",
			a: autNum(1, "export: to AS2 announce AS-ONE"), b: autNum(2, "import: from AS1 accept AS-ONE"), af: v6,
			atob: true, btoa: true},
		{name: "an undecided term is a term",
			a: autNum(1, "export: to AS2 192.0.2.9 announce ANY"), b: autNum(2), af: v4,
			btoa: true},
		{name: "a decided term that permits nothing is a term",
			a: autNum(1, "mp-export: to AS2 announce AS3"), b: autNum(2), af: v6,
			btoa: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := check(t, checker(t, c.a, c.b), Pair{A: 1, B: 2, AF: c.af})
			if r.AtoB.NoPolicy != c.atob || r.BtoA.NoPolicy != c.btoa {
				t.Errorf("NoPolicy AtoB %v BtoA %v, want %v %v", r.AtoB.NoPolicy, r.BtoA.NoPolicy, c.atob, c.btoa)
			}
			for _, d := range []Direction{r.AtoB, r.BtoA} {
				if d.NoPolicy && len(d.Findings) > 0 {
					t.Errorf("%v→%v: no policy, yet findings %v", d.From, d.To, kinds(d))
				}
			}
		})
	}
	// A missing aut-num is not "no policy".
	r := check(t, checker(t, autNum(1)), Pair{A: 1, B: 2, AF: v4})
	if r.AtoB.NoPolicy || r.BtoA.NoPolicy {
		t.Error("a missing aut-num is reported as no policy")
	}
}
