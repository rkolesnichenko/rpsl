package resolve

import (
	"context"
	"fmt"
	"net/netip"
	"reflect"
	"testing"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/types"
)

// The standard RPSL list form (RFC 2622 §2) — comma-separated members,
// mbrs-by-ref, member-of and mnt-by — must expand exactly like one-per-line.
func TestExpandCommaSeparatedMembership(t *testing.T) {
	src := corpus(t,
		"as-set: AS-FOO\nmembers: AS1, AS2, AS-BAR\nmbrs-by-ref: MNT-A, MNT-B\nsource: TEST\n",
		asSet("AS-BAR", "AS3"),
		"aut-num: AS9\nas-name: NINE\nmember-of: AS-OTHER, AS-FOO\nmnt-by: MNT-X, MNT-B\nsource: TEST\n",
	)
	got, err := (&Expander{Src: src}).ExpandAS(context.Background(), mustSet(t, "AS-FOO"))
	if err != nil {
		t.Fatal(err)
	}
	if want := []uint32{1, 2, 3, 9}; !reflect.DeepEqual(asnList(got), want) {
		t.Errorf("ExpandAS(AS-FOO) = %v, want %v", asnList(got), want)
	}
}

// An unparseable member is skipped: it must never surface as AS0 (the old
// zero-valued MemberAS) or pull in AS0's routes.
func TestInvalidMembersAreSkipped(t *testing.T) {
	src := corpus(t,
		asSet("AS-X", "AS1, garbage!!"),
		routeSet("RS-X", "garbage!!, 192.0.2.0/24"),
		"route: 198.51.100.0/24\norigin: AS0\nsource: TEST\n",
	)
	e := &Expander{Src: src}
	asns, err := e.ExpandAS(context.Background(), mustSet(t, "AS-X"))
	if err != nil || !reflect.DeepEqual(asnList(asns), []uint32{1}) {
		t.Errorf("ExpandAS(AS-X) = %v, %v; want [1]", asnList(asns), err)
	}
	pfx, err := e.ExpandPrefixes(context.Background(), mustSet(t, "RS-X"))
	if err != nil || !reflect.DeepEqual(pfx.List(), []netip.Prefix{netipMust("192.0.2.0/24")}) {
		t.Errorf("ExpandPrefixes(RS-X) = %v, %v; want [192.0.2.0/24]", pfx.List(), err)
	}
}

func TestClaimAllowed(t *testing.T) {
	claimant := decode(t, "route: 192.0.2.0/24\norigin: AS1\nmember-of: RS-X, rs-y\nmnt-by: MNT-C, MNT-B,\nsource: TEST\n")
	unclaimed := decode(t, "route: 192.0.2.0/24\norigin: AS1\nmnt-by: MNT-B\nsource: TEST\n")
	cases := []struct {
		name   string
		obj    object.Object
		set    string
		source string
		refs   []string
		want   bool
	}{
		{"listed mntner", claimant, "RS-Y", "TEST", []string{"MNT-B"}, true},
		{"mntner match is case-insensitive", claimant, "RS-Y", "TEST", []string{"mnt-b"}, true},
		{"set match is case-insensitive", claimant, "rs-x", "TEST", []string{"MNT-C"}, true},
		{"ANY admits any maintainer", claimant, "RS-Y", "TEST", []string{"ANY"}, true},
		{"any is case-insensitive", claimant, "RS-Y", "TEST", []string{"any"}, true},
		{"mntner not listed", claimant, "RS-Y", "TEST", []string{"MNT-Q"}, false},
		{"no mbrs-by-ref", claimant, "RS-Y", "TEST", nil, false},
		{"empty mbrs-by-ref item", claimant, "RS-Y", "TEST", []string{"", " "}, false},
		{"set not claimed", claimant, "RS-Z", "TEST", []string{"ANY"}, false},
		{"no member-of at all", unclaimed, "RS-Y", "TEST", []string{"ANY"}, false},
		{"source is case-insensitive", claimant, "RS-Y", "test", []string{"MNT-B"}, true},
		{"claim from another source", claimant, "RS-Y", "RADB", []string{"ANY"}, false},
		{"set without a source", claimant, "RS-Y", "", []string{"ANY"}, false},
	}
	for _, c := range cases {
		set := object.RouteSet{Name: mustSet(t, c.set), MbrsByRef: c.refs, Common: object.Common{Source: c.source}}
		if got := ClaimAllowed(c.obj, set); got != c.want {
			t.Errorf("%s: ClaimAllowed = %v, want %v", c.name, got, c.want)
		}
	}
	if ClaimAllowed(nil, object.RouteSet{}) || ClaimAllowed(claimant, nil) {
		t.Error("ClaimAllowed with a nil object or set = true, want false")
	}
}

// lyingSource returns extra objects from MembersByRef that fail the RFC 2622
// mbrs-by-ref rules; the engine must re-check every claim itself.
type lyingSource struct {
	*MemSource
	extra []object.Object
}

func (l lyingSource) MembersByRef(ctx context.Context, set object.NamedSet) ([]object.Object, error) {
	objs, err := l.MemSource.MembersByRef(ctx, set)
	return append(objs, l.extra...), err
}

func TestEngineRechecksIndirectClaims(t *testing.T) {
	mem := corpus(t,
		"as-set: AS-FOO\nmembers: AS1\nmbrs-by-ref: MNT-A\nsource: TEST\n",
		"route-set: RS-FOO\nmembers: 192.0.2.0/24\nmbrs-by-ref: MNT-A\nsource: TEST\n",
		"aut-num: AS2\nas-name: OK\nmember-of: AS-FOO\nmnt-by: MNT-A\nsource: TEST\n",
		"route: 198.51.100.0/24\norigin: AS1\nmember-of: RS-FOO\nmnt-by: MNT-A\nsource: TEST\n",
	)
	src := lyingSource{MemSource: mem, extra: []object.Object{
		decode(t, "aut-num: AS666\nas-name: EVIL\nmember-of: AS-FOO\nmnt-by: MNT-EVIL\nsource: TEST\n"), // wrong mntner
		decode(t, "aut-num: AS667\nas-name: EVIL\nmnt-by: MNT-A\nsource: TEST\n"),                       // claims nothing
		decode(t, "route: 203.0.113.0/24\norigin: AS1\nmember-of: RS-FOO\nmnt-by: MNT-EVIL\nsource: TEST\n"),
		decode(t, "aut-num: AS668\nas-name: EVIL\nmember-of: AS-FOO\nmnt-by: MNT-A\nsource: RADB\n"), // other source
		decode(t, "route: 233.252.0.0/24\norigin: AS1\nmember-of: RS-FOO\nmnt-by: MNT-A\nsource: RADB\n"),
	}}
	e := &Expander{Src: src}
	asns, err := e.ExpandAS(context.Background(), mustSet(t, "AS-FOO"))
	if err != nil || !reflect.DeepEqual(asnList(asns), []uint32{1, 2}) {
		t.Errorf("ExpandAS(AS-FOO) = %v, %v; want [1 2]", asnList(asns), err)
	}
	pfx, err := e.ExpandPrefixes(context.Background(), mustSet(t, "RS-FOO"))
	want := []netip.Prefix{netipMust("192.0.2.0/24"), netipMust("198.51.100.0/24")}
	if err != nil || !reflect.DeepEqual(pfx.List(), want) {
		t.Errorf("ExpandPrefixes(RS-FOO) = %v, %v; want %v", pfx.List(), err, want)
	}
}

// Result sets print as their sorted contents (the README's "// [AS1 AS2]").
func TestResultSetsString(t *testing.T) {
	src := corpus(t, asSet("AS-X", "AS2, AS1"), routeSet("RS-X", "192.0.2.0/24^+, 10.0.0.0/8"),
		"route: 198.51.100.0/24\norigin: AS1\nsource: TEST\n")
	e := &Expander{Src: src, MaxPrefixes: 1000}
	ctx := context.Background()
	asns, _ := e.ExpandAS(ctx, mustSet(t, "AS-X"))
	pfx, _ := e.ExpandPrefixes(ctx, mustSet(t, "AS-X"))
	ranges, _ := e.ExpandPrefixRanges(ctx, mustSet(t, "RS-X"))
	for got, want := range map[string]string{
		asns.String():          "[AS1 AS2]",
		pfx.String():           "[198.51.100.0/24]",
		ranges.String():        "[10.0.0.0/8 192.0.2.0/24^+]",
		(ASNSet{}).String():    "[]",
		(PrefixSet{}).String(): "[]",
		(RangeSet{}).String():  "[]",
	} {
		if got != want {
			t.Errorf("String() = %q, want %q", got, want)
		}
	}
}

// A real RIPE route whose key line is followed by "+" continuation lines must
// still expand (its decoded prefix was "…/24\n\n" and silently dropped).
func TestRouteWithBlankContinuationExpands(t *testing.T) {
	src := corpus(t,
		"route:   91.207.181.0/24\n+\n+\norigin:  AS48275\nsource:  RIPE\n",
		asSet("AS-X", "AS48275"),
	)
	got, err := (&Expander{Src: src}).ExpandPrefixes(context.Background(), mustSet(t, "AS-X"))
	if want := []netip.Prefix{netipMust("91.207.181.0/24")}; err != nil || !reflect.DeepEqual(got.List(), want) {
		t.Errorf("ExpandPrefixes(AS-X) = %v, %v; want %v", got.List(), err, want)
	}
}

// Maintainer names are unique only within one registry, so an indirect member
// must come from the set's own source (as IRRd requires): a RADB route whose
// mnt-by happens to name the RIPE set's mbrs-by-ref maintainer must not join it.
// Sources compare case-insensitively; an absent source matches only an absent
// source.
func TestClaimsRequireSameSource(t *testing.T) {
	src := corpus(t,
		"route-set: RS-FOO\nmembers: 192.0.2.0/24\nmbrs-by-ref: MNT-FOO\nsource: RIPE\n",
		"route: 198.51.100.0/24\norigin: AS1\nmember-of: RS-FOO\nmnt-by: MNT-FOO\nsource: ripe\n",
		"route: 203.0.113.0/24\norigin: AS666\nmember-of: RS-FOO\nmnt-by: MNT-FOO\nsource: RADB\n",
		"route: 233.252.0.0/24\norigin: AS667\nmember-of: RS-FOO\nmnt-by: MNT-FOO\n",
		"as-set: AS-FOO\nmembers: AS1\nmbrs-by-ref: ANY\nsource: RIPE\n",
		"aut-num: AS2\nas-name: TWO\nmember-of: AS-FOO\nmnt-by: MNT-X\nsource: RIPE\n",
		"aut-num: AS666\nas-name: EVIL\nmember-of: AS-FOO\nmnt-by: MNT-X\nsource: RADB\n",
		"as-set: AS-NOSRC\nmembers: AS1\nmbrs-by-ref: ANY\n",
		"aut-num: AS3\nas-name: THREE\nmember-of: AS-NOSRC\nmnt-by: MNT-X\n",
		"aut-num: AS668\nas-name: EVIL\nmember-of: AS-NOSRC\nmnt-by: MNT-X\nsource: RADB\n",
	)
	ctx := context.Background()
	e := &Expander{Src: src}
	pfx, err := e.ExpandPrefixes(ctx, mustSet(t, "RS-FOO"))
	if want := []netip.Prefix{netipMust("192.0.2.0/24"), netipMust("198.51.100.0/24")}; err != nil ||
		!reflect.DeepEqual(pfx.List(), want) {
		t.Errorf("ExpandPrefixes(RS-FOO) = %v, %v; want %v", pfx.List(), err, want)
	}
	for set, want := range map[string][]uint32{"AS-FOO": {1, 2}, "AS-NOSRC": {1, 3}} {
		asns, err := e.ExpandAS(ctx, mustSet(t, set))
		if err != nil || !reflect.DeepEqual(asnList(asns), want) {
			t.Errorf("ExpandAS(%s) = %v, %v; want %v", set, asnList(asns), err, want)
		}
	}
}

// Maintainer and source names compare with ASCII case folding only: Unicode
// folding would let "MAINT-KX" (a Kelvin sign) pass for "MAINT-KX", in the
// one check that stands between a claim and a set.
func TestClaimAllowedASCIIFold(t *testing.T) {
	set := decode(t, "route-set: RS-VICTIM\nmbrs-by-ref: MAINT-KX\nsource: KSRC\n").(object.NamedSet)
	for _, c := range []struct {
		mnt, src string
		want     bool
	}{
		{"MAINT-KX", "KSRC", true},
		{"maint-kx", "ksrc", true}, // ASCII case still folds
		{"MAINT-KX", "KSRC", false},
		{"MAINT-KX", "KSRC", false},
	} {
		claim := decode(t, "route: 192.0.2.0/24\norigin: AS1\nmember-of: RS-VICTIM\nmnt-by: "+c.mnt+"\nsource: "+c.src+"\n")
		if got := ClaimAllowed(claim, set); got != c.want {
			t.Errorf("mnt-by %q, source %q: ClaimAllowed = %v, want %v", c.mnt, c.src, got, c.want)
		}
	}
}

// An aut-num whose key does not decode is no AS at all: it must not claim
// membership as AS0, nor a route whose origin does not decode be AS0's. A real
// AS0 is still AS0.
func TestUndecodableKeysDoNotClaim(t *testing.T) {
	src := corpus(t,
		"as-set: AS-TOP\nmembers: AS1\nmbrs-by-ref: ANY\nsource: TEST\n",
		"aut-num: ASXYZ\nas-name: BAD\nmember-of: AS-TOP\nsource: TEST\n",
		"route: 192.0.2.0/24\norigin: AS1\nsource: TEST\n",
		"route: 198.51.100.0/24\norigin: ASBAD\nsource: TEST\n",
		"route: 203.0.113.0/24\norigin: AS0\nsource: OTHER\n",
	)
	e := &Expander{Src: src}
	got, err := e.ExpandAS(context.Background(), mustSet(t, "AS-TOP"))
	if err != nil || fmt.Sprint(asnList(got)) != "[1]" {
		t.Errorf("ExpandAS(AS-TOP) = %v, %v; want [1]", asnList(got), err)
	}
	routes, err := src.OriginatedRoutes(context.Background(), 0, types.AFIAny)
	if err != nil || fmt.Sprint(routes) != "[203.0.113.0/24]" {
		t.Errorf("OriginatedRoutes(AS0) = %v, %v; want only the route whose origin is AS0", routes, err)
	}
}
