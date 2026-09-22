package resolve

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/types"
)

// rtrSet renders an rtr-set object for the corpus helper.
func rtrSet(name string, members ...string) string {
	return "rtr-set: " + name + "\nmembers: " + strings.Join(members, ", ") + "\nsource: RIPE\n"
}

func prngSet(name string, peerings ...string) string {
	var b strings.Builder
	b.WriteString("peering-set: " + name + "\n")
	for _, p := range peerings {
		b.WriteString("peering: " + p + "\n")
	}
	b.WriteString("source: RIPE\n")
	return b.String()
}

func fltrSet(name, filter string) string {
	return "filter-set: " + name + "\nfilter: " + filter + "\nsource: RIPE\n"
}

func routerList(s RouterSet) []string {
	out := make([]string, 0, s.Len())
	for _, r := range s.List() {
		out = append(out, r.String())
	}
	return out
}

func TestExpandRouters(t *testing.T) {
	src := corpus(t,
		rtrSet("RTRS-TOP", "rtr1.example.net", "192.0.2.1", "RTRS-INNER"),
		rtrSet("RTRS-INNER", "rtr2.example.net", "2001:db8::1"),
	)
	e := &Expander{Src: src}
	got, err := e.ExpandRouters(context.Background(), mustSet(t, "RTRS-TOP"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.1", "2001:db8::1", "rtr1.example.net", "rtr2.example.net"}
	if strings.Join(routerList(got), " ") != strings.Join(want, " ") {
		t.Errorf("ExpandRouters = %v, want %v", routerList(got), want)
	}
	if !got.Has(mustRouter(t, "rtr2.example.net")) {
		t.Error("Has missed a nested member")
	}
	if got.Len() != 4 || len(got.Missing()) != 0 {
		t.Errorf("Len %d, Missing %v", got.Len(), got.Missing())
	}
	if got.String() == "" {
		t.Error("String() is empty")
	}
}

// A cycle between rtr-sets terminates, and a missing nested set is reported
// rather than failing the expansion — the same rules as an as-set.
func TestExpandRoutersCyclesAndMissing(t *testing.T) {
	src := corpus(t,
		rtrSet("RTRS-A", "a.example.net", "RTRS-B"),
		rtrSet("RTRS-B", "b.example.net", "RTRS-A", "RTRS-GONE"),
	)
	e := &Expander{Src: src}
	got, err := e.ExpandRouters(context.Background(), mustSet(t, "RTRS-A"))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"a.example.net", "b.example.net"}; strings.Join(routerList(got), " ") != strings.Join(want, " ") {
		t.Errorf("ExpandRouters = %v, want %v", routerList(got), want)
	}
	if ms := got.Missing(); len(ms) != 1 || ms[0].String() != "RTRS-GONE" {
		t.Errorf("Missing = %v, want [RTRS-GONE]", ms)
	}
	// A missing top-level set is an error, as everywhere else.
	if _, err := e.ExpandRouters(context.Background(), mustSet(t, "RTRS-NOPE")); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing top set err = %v, want ErrNotFound", err)
	}
	// Only an rtr-set expands to routers.
	if _, err := e.ExpandRouters(context.Background(), mustSet(t, "AS-FOO")); !errors.Is(err, ErrSetClass) {
		t.Errorf("ExpandRouters of an as-set err = %v, want ErrSetClass", err)
	}
}

// An inet-rtr that claims member-of joins the set, but only when mbrs-by-ref
// and the maintainer agree — the same hijack-relevant rule as everywhere else.
func TestExpandRoutersIndirectMembers(t *testing.T) {
	set := "rtr-set: RTRS-REF\nmembers: direct.example.net\nmbrs-by-ref: MNT-OK\nsource: RIPE\n"
	good := "inet-rtr: claimed.example.net\nlocal-as: AS1\nmember-of: RTRS-REF\nmnt-by: MNT-OK\nsource: RIPE\n"
	badMnt := "inet-rtr: wrongmnt.example.net\nlocal-as: AS1\nmember-of: RTRS-REF\nmnt-by: MNT-OTHER\nsource: RIPE\n"
	badSrc := "inet-rtr: wrongsrc.example.net\nlocal-as: AS1\nmember-of: RTRS-REF\nmnt-by: MNT-OK\nsource: RADB\n"
	e := &Expander{Src: corpus(t, set, good, badMnt, badSrc)}
	got, err := e.ExpandRouters(context.Background(), mustSet(t, "RTRS-REF"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"claimed.example.net", "direct.example.net"}
	if strings.Join(routerList(got), " ") != strings.Join(want, " ") {
		t.Errorf("ExpandRouters = %v, want %v", routerList(got), want)
	}
}

func TestExpandPeerings(t *testing.T) {
	src := corpus(t,
		prngSet("PRNG-TOP", "AS1", "AS2 at 192.0.2.1", "PRNG-INNER"),
		prngSet("PRNG-INNER", "AS3", "AS1"),
	)
	e := &Expander{Src: src}
	got, err := e.ExpandPeerings(context.Background(), mustSet(t, "PRNG-TOP"))
	if err != nil {
		t.Fatal(err)
	}
	// The nested reference is replaced by what it denotes, and AS1 appears once.
	want := []string{"AS1", "AS2 at 192.0.2.1", "AS3"}
	if strings.Join(got.Strings(), " | ") != strings.Join(want, " | ") {
		t.Errorf("ExpandPeerings = %v, want %v", got.Strings(), want)
	}
	if got.Len() != 3 || !got.Has("AS1") || got.Has("AS9") {
		t.Errorf("Len %d, Has = %v/%v", got.Len(), got.Has("AS1"), got.Has("AS9"))
	}
	if len(got.List()) != 3 || got.String() == "" {
		t.Errorf("List %v, String %q", got.List(), got.String())
	}
	if _, err := e.ExpandPeerings(context.Background(), mustSet(t, "AS-FOO")); !errors.Is(err, ErrSetClass) {
		t.Errorf("ExpandPeerings of an as-set err = %v, want ErrSetClass", err)
	}
}

func TestExpandPeeringsCycle(t *testing.T) {
	e := &Expander{Src: corpus(t,
		prngSet("PRNG-A", "AS1", "PRNG-B"),
		prngSet("PRNG-B", "AS2", "PRNG-A", "PRNG-GONE"),
	)}
	got, err := e.ExpandPeerings(context.Background(), mustSet(t, "PRNG-A"))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"AS1", "AS2"}; strings.Join(got.Strings(), " ") != strings.Join(want, " ") {
		t.Errorf("ExpandPeerings = %v, want %v", got.Strings(), want)
	}
	if ms := got.Missing(); len(ms) != 1 || ms[0].String() != "PRNG-GONE" {
		t.Errorf("Missing = %v", ms)
	}
}

func TestEvalFilterEnumerable(t *testing.T) {
	src := corpus(t,
		routeSet("RS-A", "10.0.0.0/8", "192.0.2.0/24"),
		"route: 198.51.100.0/24\norigin: AS64500\nsource: RIPE\n",
		asSet("AS-X", "AS64500"),
		fltrSet("FLTR-INNER", "{203.0.113.0/24}"),
	)
	e := &Expander{Src: src}
	ctx := context.Background()
	for _, c := range []struct {
		filter string
		want   []string
	}{
		{"{10.0.0.0/8, 192.0.2.0/24}", []string{"10.0.0.0/8", "192.0.2.0/24"}},
		{"RS-A", []string{"10.0.0.0/8", "192.0.2.0/24"}},
		{"AS64500", []string{"198.51.100.0/24"}},
		{"AS-X", []string{"198.51.100.0/24"}},
		{"FLTR-INNER", []string{"203.0.113.0/24"}},
		{"{10.0.0.0/8} OR {192.0.2.0/24}", []string{"10.0.0.0/8", "192.0.2.0/24"}},
		{"RS-A OR AS64500", []string{"10.0.0.0/8", "192.0.2.0/24", "198.51.100.0/24"}},
		// AND is the intersection of what the two sides denote.
		{"{10.0.0.0/8^+} AND {10.1.0.0/16}", []string{"10.1.0.0/16"}},
		{"RS-A AND {10.0.0.0/8}", []string{"10.0.0.0/8"}},
		{"{10.0.0.0/8} AND {192.0.2.0/24}", nil},
		// A range operator composes into what the term denotes.
		{"RS-A^24-24", []string{"10.0.0.0/8^24", "192.0.2.0/24"}},
		{"AS64500^+", []string{"198.51.100.0/24^+"}},
	} {
		f := mustFilter(t, c.filter)
		got, err := e.EvalFilter(ctx, f)
		if err != nil {
			t.Errorf("EvalFilter(%s): %v", c.filter, err)
			continue
		}
		if strings.Join(rangeList(got), " ") != strings.Join(c.want, " ") {
			t.Errorf("EvalFilter(%s) = %v, want %v", c.filter, rangeList(got), c.want)
		}
	}
	// ANY is finite as ranges, even though it is not as prefixes.
	got, err := e.EvalFilter(ctx, mustFilter(t, "ANY"))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"0.0.0.0/0^+", "::/0^+"}; strings.Join(rangeList(got), " ") != strings.Join(want, " ") {
		t.Errorf("EvalFilter(ANY) = %v, want %v", rangeList(got), want)
	}
}

// The terms with no finite answer in prefixes are reported, not silently
// treated as empty.
func TestEvalFilterNotEnumerable(t *testing.T) {
	e := &Expander{Src: corpus(t, routeSet("RS-A", "10.0.0.0/8"))}
	for _, filter := range []string{
		"NOT RS-A",
		"PeerAS",
		"community(65000:1)",
		"<^AS1$>",
		"AS1:RS-X:PeerAS",
		"RS-A AND NOT {10.0.0.0/8}",
	} {
		_, err := e.EvalFilter(context.Background(), mustFilter(t, filter))
		var ne *NotEnumerableError
		if !errors.As(err, &ne) {
			t.Errorf("EvalFilter(%s) err = %v, want *NotEnumerableError", filter, err)
			continue
		}
		if ne.Term == "" || ne.Why == "" || ne.Error() == "" {
			t.Errorf("EvalFilter(%s) error is not descriptive: %+v", filter, ne)
		}
	}
	// AS-ANY inside a filter is refused, as it is at the top level.
	var anyErr *AnySetError
	if _, err := e.EvalFilter(context.Background(), mustFilter(t, "AS-ANY")); !errors.As(err, &anyErr) {
		t.Errorf("EvalFilter(AS-ANY) err = %v, want *AnySetError", err)
	}
}

// An AS expression resolves at the AS level, so AND and EXCEPT mean what
// RFC 2622 §5.6 says rather than something about prefixes.
func TestEvalFilterASExpressions(t *testing.T) {
	src := corpus(t,
		"route: 10.1.0.0/16\norigin: AS1\nsource: RIPE\n",
		"route: 10.2.0.0/16\norigin: AS2\nsource: RIPE\n",
		"route: 10.3.0.0/16\norigin: AS3\nsource: RIPE\n",
		asSet("AS-12", "AS1", "AS2"),
		asSet("AS-23", "AS2", "AS3"),
	)
	e := &Expander{Src: src}
	// RFC 2622's filter grammar takes a single AS or as-set per term, so a
	// binary AS expression reaches the evaluator from an aggr-bndry: value or a
	// peering rather than from a parsed filter. Build it directly.
	l, r := policy.ASSetRef{Name: mustSet(t, "AS-12")}, policy.ASSetRef{Name: mustSet(t, "AS-23")}
	for _, c := range []struct {
		name string
		op   policy.ASOp
		want []string
	}{
		{"OR", policy.ASOr, []string{"10.1.0.0/16", "10.2.0.0/16", "10.3.0.0/16"}},
		{"AND", policy.ASAnd, []string{"10.2.0.0/16"}},
		{"EXCEPT", policy.ASExcept, []string{"10.1.0.0/16"}},
	} {
		f := policy.FilterASExpr{AS: policy.ASExprBinary{Op: c.op, L: l, R: r}}
		got, err := e.EvalFilter(context.Background(), f)
		if err != nil {
			t.Errorf("EvalFilter(AS-12 %s AS-23): %v", c.name, err)
			continue
		}
		if strings.Join(rangeList(got), " ") != strings.Join(c.want, " ") {
			t.Errorf("EvalFilter(AS-12 %s AS-23) = %v, want %v", c.name, rangeList(got), c.want)
		}
	}
	// A plain as-set term still works through the parser.
	got, err := e.EvalFilter(context.Background(), mustFilter(t, "AS-12"))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"10.1.0.0/16", "10.2.0.0/16"}; strings.Join(rangeList(got), " ") != strings.Join(want, " ") {
		t.Errorf("EvalFilter(AS-12) = %v, want %v", rangeList(got), want)
	}
}

func TestExpandFilterSet(t *testing.T) {
	src := corpus(t,
		fltrSet("FLTR-TOP", "{10.0.0.0/8} OR FLTR-INNER"),
		fltrSet("FLTR-INNER", "{192.0.2.0/24}"),
		// A cycle must terminate at what the two sets jointly denote.
		fltrSet("FLTR-A", "{10.1.0.0/16} OR FLTR-B"),
		fltrSet("FLTR-B", "{10.2.0.0/16} OR FLTR-A"),
		"filter-set: FLTR-MP\nmp-filter: {2001:db8::/32}\nsource: RIPE\n",
	)
	e := &Expander{Src: src}
	ctx := context.Background()

	got, err := e.ExpandFilterSet(ctx, mustSet(t, "FLTR-TOP"))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"10.0.0.0/8", "192.0.2.0/24"}; strings.Join(rangeList(got), " ") != strings.Join(want, " ") {
		t.Errorf("ExpandFilterSet(FLTR-TOP) = %v, want %v", rangeList(got), want)
	}

	got, err = e.ExpandFilterSet(ctx, mustSet(t, "FLTR-A"))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"10.1.0.0/16", "10.2.0.0/16"}; strings.Join(rangeList(got), " ") != strings.Join(want, " ") {
		t.Errorf("a cycle of filter-sets gave %v, want %v", rangeList(got), want)
	}

	// mp-filter: carries the IPv6 form, and is used when there is no filter:.
	got, err = e.ExpandFilterSet(ctx, mustSet(t, "FLTR-MP"))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"2001:db8::/32"}; strings.Join(rangeList(got), " ") != strings.Join(want, " ") {
		t.Errorf("ExpandFilterSet(FLTR-MP) = %v, want %v", rangeList(got), want)
	}

	if _, err := e.ExpandFilterSet(ctx, mustSet(t, "FLTR-GONE")); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing filter-set err = %v, want ErrNotFound", err)
	}
	if _, err := e.ExpandFilterSet(ctx, mustSet(t, "AS-FOO")); !errors.Is(err, ErrSetClass) {
		t.Errorf("ExpandFilterSet of an as-set err = %v, want ErrSetClass", err)
	}
}

// The AFI constraint reaches filter evaluation too.
func TestEvalFilterAFI(t *testing.T) {
	src := corpus(t, routeSet("RS-MIX", "10.0.0.0/8", "2001:db8::/32"))
	for _, c := range []struct {
		afi  types.AFI
		want []string
	}{
		{types.AFIv4, []string{"10.0.0.0/8"}},
		{types.AFIv6, []string{"2001:db8::/32"}},
		{types.AFIAny, []string{"10.0.0.0/8", "2001:db8::/32"}},
	} {
		e := &Expander{Src: src, AFI: c.afi}
		got, err := e.EvalFilter(context.Background(), mustFilter(t, "RS-MIX"))
		if err != nil {
			t.Fatalf("afi %v: %v", c.afi, err)
		}
		if strings.Join(rangeList(got), " ") != strings.Join(c.want, " ") {
			t.Errorf("afi %v: EvalFilter = %v, want %v", c.afi, rangeList(got), c.want)
		}
	}
}

// A filter that would denote more than MaxPrefixes ranges is refused, not
// truncated.
func TestEvalFilterLimits(t *testing.T) {
	e := &Expander{Src: corpus(t, routeSet("RS-A", "10.0.0.0/8", "11.0.0.0/8")), MaxPrefixes: 1}
	_, err := e.EvalFilter(context.Background(), mustFilter(t, "RS-A"))
	var too *SetTooLargeError
	if !errors.As(err, &too) || too.Limit != LimitPrefixes {
		t.Errorf("err = %v, want a LimitPrefixes SetTooLargeError", err)
	}
}

// mustFilter parses a filter or fails the test.
func mustFilter(t *testing.T, s string) policy.Filter {
	t.Helper()
	f, ds := policy.ParseFilter(s)
	if len(ds) != 0 {
		t.Fatalf("ParseFilter(%q): %v", s, ds)
	}
	return f
}

// mustRouter parses a router id or fails the test.
func mustRouter(t *testing.T, s string) types.RouterID {
	t.Helper()
	r, err := types.ParseRouterID(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
