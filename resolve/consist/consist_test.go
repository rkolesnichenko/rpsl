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
	// The same regexp on both sides compares exactly: AS2 accepts every route
	// the regexp passes, so nothing is left.
	c = checker(t,
		autNum(1, "export: to AS2 announce <^AS1+$>"),
		autNum(2, "import: from AS1 accept <^AS1+$>"))
	if r := check(t, c, Pair{A: 1, B: 2, AF: v4}); len(r.AtoB.Findings) != 0 {
		t.Errorf("identical regexps: AtoB %v", kinds(r.AtoB))
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
	f := r.AtoB.Findings[0]
	if len(f.Ranges) != 3 || !f.Truncated {
		t.Errorf("%d ranges, truncated %v; want 3, true", len(f.Ranges), f.Truncated)
	}
	c.MaxRanges = 0 // the default, 64
	r = check(t, c, Pair{A: 1, B: 2, AF: v4})
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
	for _, p := range []Pair{{A: 0, B: 2, AF: v4}, {A: 1, B: 0, AF: v4}, {A: 1, B: 1, AF: v4}, {A: 1, B: 2}} {
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
