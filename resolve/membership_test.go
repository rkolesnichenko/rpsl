package resolve

import (
	"context"
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
	claimant := decode(t, "route: 192.0.2.0/24\norigin: AS1\nmember-of: RS-X, rs-y\nmnt-by: MNT-C, MNT-B\nsource: TEST\n")
	unclaimed := decode(t, "route: 192.0.2.0/24\norigin: AS1\nmnt-by: MNT-B\nsource: TEST\n")
	cases := []struct {
		name string
		obj  object.Object
		set  string
		refs []string
		want bool
	}{
		{"listed mntner", claimant, "RS-Y", []string{"MNT-B"}, true},
		{"mntner match is case-insensitive", claimant, "RS-Y", []string{"mnt-b"}, true},
		{"set match is case-insensitive", claimant, "rs-x", []string{"MNT-C"}, true},
		{"ANY admits any maintainer", claimant, "RS-Y", []string{"ANY"}, true},
		{"any is case-insensitive", claimant, "RS-Y", []string{"any"}, true},
		{"mntner not listed", claimant, "RS-Y", []string{"MNT-Q"}, false},
		{"no mbrs-by-ref", claimant, "RS-Y", nil, false},
		{"set not claimed", claimant, "RS-Z", []string{"ANY"}, false},
		{"no member-of at all", unclaimed, "RS-Y", []string{"ANY"}, false},
	}
	for _, c := range cases {
		if got := ClaimAllowed(c.obj, mustSet(t, c.set), c.refs); got != c.want {
			t.Errorf("%s: ClaimAllowed = %v, want %v", c.name, got, c.want)
		}
	}
}

// lyingSource returns extra objects from MembersByRef that fail the RFC 2622
// mbrs-by-ref rules; the engine must re-check every claim itself.
type lyingSource struct {
	*MemSource
	extra []object.Object
}

func (l lyingSource) MembersByRef(ctx context.Context, set types.SetName, refs []string) ([]object.Object, error) {
	objs, err := l.MemSource.MembersByRef(ctx, set, refs)
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
		(ASSet{}).String():     "[]",
		(PrefixSet{}).String(): "[]",
		(RangeSet{}).String():  "[]",
	} {
		if got != want {
			t.Errorf("String() = %q, want %q", got, want)
		}
	}
}
