package rtconfig

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/resolve/internal/cfgsim"
	"github.com/rkolesnichenko/rpsl/types"
)

func TestJunosImport(t *testing.T) {
	s, p := fixturePolicy(t,
		"from AS2 action pref = 10; community.append(1:100); accept AS2 AND NOT {10.2.128.0/17}",
		"from AS2 accept ANY AND NOT community(2:666) AND <^AS2 AS-FOO*$>",
	)
	var b bytes.Buffer
	if err := (&Generator{Vendor: Junos}).WriteImport(&b, s, p); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"policy-statement policy_2_1 {",
		"route-filter 10.2.0.0/16 exact;",
		`as-path policy_2_1-path-1 "2 (10|11)*";`,
		"local-preference 990;",
		"import policy_2_1;",
		"peer-as 2;",
	} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("missing %q in\n%s", want, b.String())
		}
	}
	for _, x := range []struct {
		r      cfgsim.Route
		accept bool
		attrs  cfgsim.Attrs
	}{
		{rt("10.2.0.0/16", []types.ASN{2}), true, cfgsim.Attrs{LocalPref: 990, MED: -1, Communities: []string{"1:100"}}},
		{rt("10.2.128.0/17", []types.ASN{2, 10}), true, cfgsim.Attrs{LocalPref: -1, MED: -1}},
		{rt("10.2.128.0/17", []types.ASN{2, 12}), false, cfgsim.Attrs{}},
		{rt("192.0.2.0/24", []types.ASN{2, 11}, "2:666"), false, cfgsim.Attrs{}},
	} {
		ok, a := simulate(t, Junos, b.String(), s, false, x.r)
		if ok != x.accept || ok && !reflect.DeepEqual(a, x.attrs) {
			t.Errorf("%v: %v %+v; want %v %+v\n%s", x.r, ok, a, x.accept, x.attrs, b.String())
		}
	}
}

// Nested ranges go into separate route-filter terms, so Junos's longest match
// cannot hide a shorter range that would accept.
func TestJunosNestedRanges(t *testing.T) {
	s, p := fixturePolicy(t, "from AS2 accept {10.0.0.0/8^16-24, 10.2.0.0/16, 10.2.3.0/24^+}")
	var b bytes.Buffer
	if err := (&Generator{Vendor: Junos}).WriteImport(&b, s, p); err != nil {
		t.Fatal(err)
	}
	for _, r := range []cfgsim.Route{
		rt("10.2.0.0/16", []types.ASN{2}),
		rt("10.2.3.0/24", []types.ASN{2}),
		rt("10.2.3.128/25", []types.ASN{2}),
		rt("10.2.9.0/24", []types.ASN{2}),
		rt("10.9.0.0/16", []types.ASN{2}),
	} {
		if ok, _ := simulate(t, Junos, b.String(), s, false, r); !ok {
			t.Errorf("%v refused:\n%s", r, b.String())
		}
	}
	if ok, _ := simulate(t, Junos, b.String(), s, false, rt("10.2.9.128/25", []types.ASN{2})); ok {
		t.Errorf("10.2.9.128/25 accepted")
	}
	if n := strings.Count(b.String(), "term permit-"); n < 2 {
		t.Errorf("%d permit terms; nested ranges need separate terms", n)
	}
}

func TestJunosGroups(t *testing.T) {
	rs := []types.PrefixRange{
		mustRange(t, "10.0.0.0/8^16-24"), mustRange(t, "10.2.0.0/16"), mustRange(t, "10.3.0.0/16"),
		mustRange(t, "10.2.3.0/24^+"), mustRange(t, "192.0.2.0/24"),
	}
	groups := junosGroups(rs)
	for _, g := range groups {
		for i := range g {
			for j := i + 1; j < len(g); j++ {
				if g[i].Prefix().Overlaps(g[j].Prefix()) {
					t.Errorf("group %v holds nested %v and %v", g, g[i], g[j])
				}
			}
		}
	}
	if len(groups) != 3 {
		t.Errorf("%d groups, want 3: %v", len(groups), groups)
	}
}

func mustRange(t *testing.T, s string) types.PrefixRange {
	t.Helper()
	r, err := types.ParsePrefixRange(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
