package policy

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl/types"
)

// termStrings renders a flattened policy for comparison.
func termStrings(ts []Term) []string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = t.String()
	}
	return out
}

// mustFlatten flattens e for ipv4.unicast, failing the test on an error.
func mustFlatten(t *testing.T, e Expr) []Term {
	t.Helper()
	ts, err := Flatten(e, v4u)
	if err != nil {
		t.Fatalf("Flatten: %v", err)
	}
	return ts
}

func flattenImport(t *testing.T, value string) []Term {
	t.Helper()
	imp, ds := ParseImport(value)
	clean(t, "ParseImport("+value+")", ds)
	return mustFlatten(t, imp.Expr)
}

// A plain policy flattens to one term per peering clause, in document order.
func TestFlattenFactor(t *testing.T) {
	got := termStrings(flattenImport(t, "from AS1 action pref = 1; from AS2 accept AS-FOO"))
	want := []string{
		"AS1 action pref = 1; | AS-FOO",
		"AS2 | AS-FOO",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("Flatten =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestFlattenExprList(t *testing.T) {
	got := termStrings(flattenImport(t, "{ from AS1 accept AS1; from AS2 accept AS2; }"))
	want := []string{"AS1 | AS1", "AS2 | AS2"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("Flatten = %v, want %v", got, want)
	}
}

// RFC 2622 §6.5: refine is the cartesian product over intersecting peerings,
// with the filters ANDed and the actions concatenated. AS-ANY meets every peer.
func TestFlattenRefine(t *testing.T) {
	got := termStrings(flattenImport(t,
		"{ from AS-ANY action pref = 1; accept community(3560:10); } "+
			"refine { from AS1 accept AS1; from AS2 accept AS2; }"))
	want := []string{
		"AS1 action pref = 1; | community(3560:10) AND AS1",
		"AS2 action pref = 1; | community(3560:10) AND AS2",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("Flatten =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// Peerings that do not intersect produce no term.
	if got := flattenImport(t, "{ from AS1 accept ANY; } refine { from AS2 accept AS2; }"); len(got) != 0 {
		t.Errorf("disjoint peerings refined to %v, want none", termStrings(got))
	}
	// Two identical peerings intersect, and both actions are kept in order.
	got = termStrings(flattenImport(t,
		"{ from AS1 action pref = 1; accept ANY; } refine { from AS1 action med = 2; accept AS1; }"))
	want = []string{"AS1 action pref = 1; med = 2; | ANY AND AS1"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("Flatten = %v, want %v", got, want)
	}
}

// RFC 2622 §6.6 states an except policy and its expansion. Both must flatten to
// the same terms — the strongest check available that the semantics are right,
// since the RFC itself supplies both sides.
func TestFlattenExceptMatchesRFCExpansion(t *testing.T) {
	nested := "from AS1 action pref = 1; accept as-foo; except " +
		"{ from AS2 action pref = 2; accept AS226; except " +
		"{ from AS3 action pref = 3; accept {128.9.0.0/16}; } }"
	expanded := "from AS1 action pref = 1; accept as-foo; except " +
		"{ from AS3 action pref = 3; accept AS226 AND {128.9.0.0/16}; " +
		"from AS2 action pref = 2; accept AS226 AND NOT {128.9.0.0/16}; }"

	a := termStrings(flattenImport(t, nested))
	b := termStrings(flattenImport(t, expanded))
	if strings.Join(a, "\n") != strings.Join(b, "\n") {
		t.Errorf("RFC 2622 §6.6's two spellings flatten differently:\nnested:\n%s\nexpanded:\n%s",
			strings.Join(a, "\n"), strings.Join(b, "\n"))
	}
	if len(a) != 3 {
		t.Fatalf("want 3 terms, got %d: %v", len(a), a)
	}
	// The right-hand peerings override; the left keeps what they did not take.
	for i, want := range []string{"AS3 ", "AS2 ", "AS1 "} {
		if !strings.HasPrefix(a[i], want) {
			t.Errorf("term %d = %q, want it to start %q", i, a[i], want)
		}
	}
	if !strings.Contains(a[2], "NOT") {
		t.Errorf("the left-hand term %q does not exclude what the right took", a[2])
	}
}

// An except with nothing on the right leaves the left alone.
func TestFlattenExceptEmpty(t *testing.T) {
	imp, _ := ParseImport("from AS1 accept ANY")
	var f flattener
	got := termStrings(unweigh(f.exceptTerms(f.flatten(imp.Expr, 0), nil)))
	if len(got) != 1 || got[0] != "AS1 | ANY" {
		t.Errorf("exceptTerms(l, nil) = %v", got)
	}
}

func TestFlattenNilAndDepth(t *testing.T) {
	if got, err := Flatten(nil, v4u); got != nil || err != nil {
		t.Errorf("Flatten(nil) = %v, %v", got, err)
	}
	// A hand-built chain deeper than the cap stops rather than overflowing.
	var e Expr = Factor{Filter: FilterAny{}}
	for i := 0; i < maxFlattenDepth+10; i++ {
		e = Refine{Left: e, Right: Factor{Filter: FilterAny{}}}
	}
	if got, err := Flatten(e, v4u); got != nil || !errors.Is(err, ErrFlattenTooLarge) {
		t.Errorf("Flatten of an over-deep chain returned %d terms and %v, want ErrFlattenTooLarge", len(got), err)
	}
}

func TestAndOrFilterHelpers(t *testing.T) {
	any := FilterAny{}
	if got := andFilters(nil, any); got != Filter(any) {
		t.Errorf("andFilters(nil, x) = %#v", got)
	}
	if got := andFilters(any, nil); got != Filter(any) {
		t.Errorf("andFilters(x, nil) = %#v", got)
	}
	// AND chains stay flat, as the parser builds them.
	nested := andFilters(andFilters(any, any), any)
	and, ok := nested.(FilterAnd)
	if !ok || len(and.Terms) != 3 {
		t.Errorf("andFilters did not flatten: %#v", nested)
	}
	if got := orFilters(nil); got != nil {
		t.Errorf("orFilters(nil) = %#v", got)
	}
	if got := orFilters([]Filter{any}); got != Filter(any) {
		t.Errorf("orFilters(one) = %#v", got)
	}
	flat := orFilters([]Filter{FilterOr{Terms: []Filter{any, any}}, any})
	or, ok := flat.(FilterOr)
	if !ok || len(or.Terms) != 3 {
		t.Errorf("orFilters did not flatten: %#v", flat)
	}
}

// Except and Refine carry their own afi scope, inheriting the enclosing
// policy's when they have none (RFC 4012 §2.5).
func TestExceptRefineAFIScope(t *testing.T) {
	imp, ds := ParseMPImport("afi any from AS1 accept ANY; except afi ipv6.unicast { from AS2 accept ANY; }")
	clean(t, "mp-import", ds)
	ex, ok := imp.Expr.(Except)
	if !ok {
		t.Fatalf("Expr = %#v, want Except", imp.Expr)
	}
	if ex.Unscoped() {
		t.Error("Except.Unscoped() = true, want false")
	}
	v6 := mustAF(t, "ipv6.unicast")
	v4 := mustAF(t, "ipv4.unicast")
	if !ex.AppliesTo(v6) {
		t.Error("the ipv6.unicast exception does not apply to ipv6.unicast")
	}
	if ex.AppliesTo(v4) {
		t.Error("the ipv6.unicast exception applies to ipv4.unicast")
	}
	// With no afi clause of its own, an mp- exception applies everywhere.
	imp, ds = ParseMPImport("from AS1 accept ANY; except { from AS2 accept ANY; }")
	clean(t, "mp-import", ds)
	ex = imp.Expr.(Except)
	if !ex.Unscoped() || !ex.AppliesTo(v4) || !ex.AppliesTo(v6) {
		t.Errorf("an unscoped mp- exception does not apply to both families")
	}
	// A legacy import: is ipv4.unicast only.
	imp, ds = ParseImport("from AS1 accept ANY; except { from AS2 accept ANY; }")
	clean(t, "import", ds)
	ex = imp.Expr.(Except)
	if !ex.AppliesTo(v4) || ex.AppliesTo(v6) {
		t.Error("a legacy exception is not ipv4.unicast only")
	}
	// Refine takes the same scope.
	imp, ds = ParseMPImport("afi any from AS1 accept ANY; refine afi ipv6.unicast { from AS1 accept ANY; }")
	clean(t, "mp-import", ds)
	rf := imp.Expr.(Refine)
	if rf.Unscoped() || !rf.AppliesTo(v6) || rf.AppliesTo(v4) {
		t.Errorf("Refine scope = %v", rf.AFIs)
	}
}

// mustAF parses an address family or fails the test.
func mustAF(t *testing.T, s string) types.AddrFamily {
	t.Helper()
	af, err := types.ParseAddrFamily(s)
	if err != nil {
		t.Fatal(err)
	}
	return af
}

func unweigh(ts []wterm) []Term {
	out := make([]Term, len(ts))
	for i, t := range ts {
		out[i] = t.Term
	}
	return out
}

// RFC 4012 §2.5: an afi clause on EXCEPT or REFINE scopes its right-hand
// policy. For a family it does not cover, the left-hand policy stands alone.
func TestFlattenAFIScope(t *testing.T) {
	cases := []struct {
		value  string
		v4, v6 []string
	}{{
		value: "afi any.unicast from AS65001 accept as-foo; except afi ipv6.unicast { from AS65002 accept AS65002:AS-FOO; }",
		v4:    []string{"AS65001 | AS-FOO"},
		v6:    []string{"AS65002 | AS-FOO AND AS65002:AS-FOO", "AS65001 | AS-FOO AND NOT AS65002:AS-FOO"},
	}, {
		value: "afi any.unicast from AS-ANY accept ANY refine afi ipv6.unicast from AS1 accept AS1",
		v4:    []string{"AS-ANY | ANY"},
		v6:    []string{"AS1 | ANY AND AS1"},
	}, {
		// An except with no afi clause of its own takes effect wherever the
		// policy does, and the policy is not in effect for ipv4 at all.
		value: "afi ipv6.unicast from AS1 accept ANY except from AS2 accept AS2",
		v4:    nil,
		v6:    []string{"AS2 | ANY AND AS2", "AS1 | ANY AND NOT AS2"},
	}, {
		// A nested scope narrower than the outer one.
		value: "afi any from AS1 accept ANY except afi any.unicast { from AS2 accept AS2 except afi ipv4.unicast from AS3 accept AS3; }",
		v4:    []string{"AS3 | ANY AND AS2 AND AS3", "AS2 | ANY AND AS2 AND NOT AS3", "AS1 | ANY AND NOT (AS2 AND AS3 OR AS2 AND NOT AS3)"},
		v6:    []string{"AS2 | ANY AND AS2", "AS1 | ANY AND NOT AS2"},
	}}
	for _, c := range cases {
		imp, ds := ParseMPImport(c.value)
		clean(t, c.value, ds)
		for _, fam := range []struct {
			af   types.AddrFamily
			want []string
		}{{v4u, c.v4}, {v6u, c.v6}} {
			ts, err := imp.Terms(fam.af)
			if err != nil {
				t.Fatalf("%s: %v", c.value, err)
			}
			if got := termStrings(ts); strings.Join(got, "\n") != strings.Join(fam.want, "\n") {
				t.Errorf("%s for %s:\n got %q\nwant %q", c.value, fam.af, got, fam.want)
			}
		}
	}
}

// A few hundred bytes of nested EXCEPT double the filters at every level, and
// n factors except n factors make n*n terms: Flatten refuses both promptly.
func TestFlattenTooLarge(t *testing.T) {
	var list strings.Builder
	list.WriteString("{ ")
	for i := 0; i < 2000; i++ {
		fmt.Fprintf(&list, "from AS%d accept AS%d; ", i+1, i+1)
	}
	list.WriteString("}")
	for _, value := range []string{
		strings.Repeat("from AS1 accept AS1 except ", 22) + "from AS1 accept AS1",
		list.String() + " except " + list.String(),
	} {
		imp, ds := ParseImport(value)
		clean(t, "ParseImport", ds)
		start := time.Now()
		ts, err := imp.Terms(v4u)
		if !errors.Is(err, ErrFlattenTooLarge) || ts != nil {
			t.Errorf("%.60s…: got %d terms, %v; want ErrFlattenTooLarge", value, len(ts), err)
		}
		if d := time.Since(start); d > 5*time.Second {
			t.Errorf("%.60s…: refusing took %v", value, d)
		}
	}
	// A chain within the budget still flattens.
	imp, _ := ParseImport(strings.Repeat("from AS1 accept AS1 except ", 8) + "from AS1 accept AS1")
	if ts, err := imp.Terms(v4u); err != nil || len(ts) == 0 {
		t.Errorf("an 8-level chain: %d terms, %v", len(ts), err)
	}
}
