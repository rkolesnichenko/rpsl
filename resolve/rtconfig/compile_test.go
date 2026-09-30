package rtconfig

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/resolve/internal/cfgsim"
	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/types"
)

// planSummary renders a plan compactly: one line per entry.
func planSummary(p plan) string {
	var lines []string
	for _, e := range p.entries {
		var parts []string
		parts = append(parts, fmt.Sprintf("#%d", e.clause))
		if e.prefix != nil {
			parts = append(parts, fmt.Sprintf("deny%v permit%v any=%v", e.prefix.deny, e.prefix.permit, e.prefix.any))
		}
		for _, pc := range e.paths {
			parts = append(parts, fmt.Sprintf("path(%v %s)", pc.negated, pc.re))
		}
		if !e.comm.empty() {
			parts = append(parts, fmt.Sprintf("comm(all=%v none=%v eq=%v)", e.comm.all, e.comm.none, e.comm.equal))
		}
		parts = append(parts, e.ops.summary())
		lines = append(lines, strings.TrimSpace(strings.Join(parts, " ")))
	}
	return strings.Join(lines, "\n")
}

func TestCompile(t *testing.T) {
	g := &Generator{Vendor: IOS}
	s, p := fixturePolicy(t,
		"from AS2 action pref = 10; accept AS2 AND NOT {10.2.128.0/17}",
		"from AS2 accept ANY AND NOT community(2:666) AND <^AS2 AS-FOO*$>",
		"from AS3 accept ANY",
		"from AS2 accept NOT ANY",
	)
	pl, err := g.compile(s, p)
	if err != nil {
		t.Fatal(err)
	}
	// AS2's routes are 10.2.0.0/16 and 10.2.128.0/17, both exact-length
	// literals; NOT {10.2.128.0/17} exactly cancels the matching literal from
	// AS2's expansion rather than leaving a NotPrefixes entry, since a plain
	// prefix literal denotes only that one length, and the /16 and /17
	// literals never intersect as ranges (types.PrefixRange.Intersect: same
	// base address, disjoint length windows). Verified against
	// resolve.Expander.NormalizeFilter's actual output.
	want := "#0 deny[] permit[10.2.0.0/16] any=false lp=990\n" +
		"#1 path(false ^_2(_(10|11))*$) comm(all=[] none=[[2:666]] eq=[])"
	if got := planSummary(pl); got != want {
		t.Errorf("plan =\n%s\nwant\n%s", got, want)
	}
	if pl.family != types.AFIv4 {
		t.Errorf("family %v", pl.family)
	}
}

func TestCompileRefuses(t *testing.T) {
	for _, c := range []struct {
		v      Vendor
		filter string
		cause  string
	}{
		{IOS, "<AS2> AND <AS3>", CauseTwoPaths},
		{Junos, "<AS2> AND <AS3>", CauseTwoPaths},
		{Junos, "community == {1:1}", CauseCommunityEquals},
		{IOSXR, "community == {1:1}", CauseCommunityEquals},
		{IOS, "community == {1:1} AND community(1:2)", CauseCommunityEquals},
		{IOS, "NOT community == {1:1}", CauseCommunityEquals},
		{IOS, "<[^AS1]>", CauseNegatedClass},
		{BIRD2, "<AS1 | AS2>", CausePathShape},
		{IOS, "community(1:2:3)", CauseCommunityForm},
	} {
		g := &Generator{Vendor: c.v}
		s, p := fixturePolicy(t, "from AS2 accept "+c.filter)
		_, err := g.compile(s, p)
		var ue *UnsupportedError
		if !errors.As(err, &ue) || ue.Cause != c.cause {
			t.Errorf("%v %s: err %v, want cause %q", c.v, c.filter, err, c.cause)
		}
	}
	for _, v := range []Vendor{IOSXR, BIRD2} {
		s, p := fixturePolicy(t, "from AS2 accept <AS2> AND <AS3>")
		if _, err := (&Generator{Vendor: v}).compile(s, p); err != nil {
			t.Errorf("%v two paths: %v", v, err)
		}
	}
	s, p := fixturePolicy(t, "from AS2 accept community == {1:1} AND NOT community == {1:2}")
	if _, err := (&Generator{Vendor: BIRD2}).compile(s, p); err != nil {
		t.Errorf("bird mixed equals: %v", err)
	}
	mc := v4Session
	mc.AF.SAFI = types.SAFIMulticast
	_, p = fixturePolicyFor(t, v4Session, "from AS2 accept ANY")
	var ue *UnsupportedError
	if _, err := (&Generator{Vendor: IOS}).compile(mc, p); !errors.As(err, &ue) || ue.Cause != CauseSAFI {
		t.Errorf("multicast session: %v", err)
	}
}

// Every Capability row agrees with what compile does, for the features compile
// decides. Default, Networks, Via and Multicast are held to the writers by
// TestCapabilitiesMatchWriters (Task 14), once every writer exists.
func TestCapabilitiesMatchCompile(t *testing.T) {
	probes := map[Feature]string{
		FeatureTwoPaths:             "from AS2 accept <AS2> AND <AS3>",
		FeatureAlternation:          "from AS2 accept <AS2 | AS3>",
		FeatureInnerAnchor:          "from AS2 accept <AS3 ^AS2>",
		FeatureNegatedClass:         "from AS2 accept <[^AS1]>",
		FeatureCommunityEquals:      "from AS2 accept community == {1:1}",
		FeatureCommunityEqualsMixed: "from AS2 accept community == {1:1} AND community(1:2)",
		FeatureMEDIGP:               "from AS2 action med = igp_cost; accept ANY",
		FeatureNextHopSelf:          "from AS2 action next-hop = self; accept ANY",
	}
	for _, c := range Capabilities() {
		probe, ok := probes[c.Feature]
		if !ok {
			continue
		}
		for _, v := range Vendors() {
			s, p := fixturePolicy(t, probe)
			_, err := (&Generator{Vendor: v}).compile(s, p)
			want := contains(c.Vendors, v)
			var ue *UnsupportedError
			switch {
			case want && err != nil:
				t.Errorf("%v %s: table says supported, compile says %v", v, c.Feature, err)
			case !want && (!errors.As(err, &ue) || ue.Cause != c.Cause):
				t.Errorf("%v %s: table says refused with %q, compile says %v", v, c.Feature, c.Cause, err)
			}
		}
	}
}

func contains(vs []Vendor, v Vendor) bool {
	for _, x := range vs {
		if x == v {
			return true
		}
	}
	return false
}

// A next-hop of the other family than the session's is refused: IOS, for one,
// rejects "set ipv6 next-hop 192.0.2.1" on load but keeps the entry, which then
// accepts routes with their next-hop unchanged. next-hop = self has no family.
func TestCompileNextHopFamily(t *testing.T) {
	for _, c := range []struct {
		s    peval.Session
		imp  string
		want bool // compiles
	}{
		{v6Session, "mp-import: afi any.unicast from AS2 action next-hop = 192.0.2.1; accept ANY", false},
		{v4Session, "mp-import: afi any.unicast from AS2 action next-hop = 2001:db8::1; accept ANY", false},
		{v4Session, "mp-import: afi any.unicast from AS2 action next-hop = 192.0.2.1; accept ANY", true},
		{v6Session, "mp-import: afi any.unicast from AS2 action next-hop = 2001:db8::1; accept ANY", true},
		{v6Session, "mp-import: afi any.unicast from AS2 action next-hop = ::ffff:192.0.2.1; accept ANY", true},
	} {
		for _, v := range Vendors() {
			s, p := fixturePolicyFor(t, c.s, c.imp)
			_, err := (&Generator{Vendor: v}).compile(s, p)
			var ue *UnsupportedError
			switch {
			case c.want && err != nil:
				t.Errorf("%v %v %s: %v", v, c.s.AF, c.imp, err)
			case !c.want && (!errors.As(err, &ue) || ue.Cause != CauseActionValue || ue.Vendor != v):
				t.Errorf("%v %v %s: err %v, want cause %q", v, c.s.AF, c.imp, err, CauseActionValue)
			}
		}
	}
	for _, v := range []Vendor{Junos, IOSXR} {
		s, p := fixturePolicyFor(t, v6Session, "mp-import: afi any.unicast from AS2 action next-hop = self; accept ANY")
		if _, err := (&Generator{Vendor: v}).compile(s, p); err != nil {
			t.Errorf("%v next-hop = self on ipv6: %v", v, err)
		}
	}
}

// A contains-test of no communities holds for every route, so its negation
// holds for none (ruling R21): a conjunct with NOT community() matches
// nothing and gets no entry, and a positive community() adds no condition.
// community == {} (the route carries no community at all) is a real test:
// BIRD writes it, the others refuse it as an exact match.
func TestCompileEmptyCommunityTests(t *testing.T) {
	r2 := rt("10.2.0.0/16", []types.ASN{2})
	r2c := rt("10.2.0.0/16", []types.ASN{2}, "1:1")
	r3 := rt("10.3.0.0/16", []types.ASN{2, 3})
	for _, c := range []struct {
		filter  string
		entries int
		accept  map[*cfgsim.Route]bool
	}{
		{"NOT community()", 0, map[*cfgsim.Route]bool{&r2: false, &r2c: false, &r3: false}},
		{"NOT community.contains()", 0, map[*cfgsim.Route]bool{&r2: false, &r2c: false, &r3: false}},
		{"AS2 AND NOT community()", 0, map[*cfgsim.Route]bool{&r2: false, &r2c: false, &r3: false}},
		{"AS3 OR NOT community()", 1, map[*cfgsim.Route]bool{&r2: false, &r2c: false, &r3: true}},
		{"community()", 1, map[*cfgsim.Route]bool{&r2: true, &r2c: true, &r3: true}},
	} {
		for _, v := range Vendors() {
			g := &Generator{Vendor: v}
			s, p := fixturePolicy(t, "from AS2 accept "+c.filter)
			pl, err := g.compile(s, p)
			if err != nil || len(pl.entries) != c.entries {
				t.Errorf("%v %s: %d entries, %v; want %d", v, c.filter, len(pl.entries), err, c.entries)
				continue
			}
			var b bytes.Buffer
			if err := writeImport(g, &b, s, p); err != nil {
				t.Fatalf("%v %s: %v", v, c.filter, err)
			}
			for r, want := range c.accept {
				if ok, _ := simulate(t, v, b.String(), s, false, *r); ok != want {
					t.Errorf("%v %s over %v: %v, want %v\n%s", v, c.filter, *r, ok, want, b.String())
				}
			}
		}
	}
	for _, v := range Vendors() {
		s, p := fixturePolicy(t, "from AS2 accept community == {}")
		var b bytes.Buffer
		err := writeImport(&Generator{Vendor: v}, &b, s, p)
		var ue *UnsupportedError
		switch {
		case v == BIRD2 && err != nil:
			t.Errorf("bird community == {}: %v", err)
		case v == BIRD2:
			for r, want := range map[*cfgsim.Route]bool{&r2: true, &r2c: false} {
				if ok, _ := simulate(t, v, b.String(), s, false, *r); ok != want {
					t.Errorf("bird community == {} over %v: %v, want %v\n%s", *r, ok, want, b.String())
				}
			}
		case !errors.As(err, &ue) || ue.Cause != CauseCommunityEquals:
			t.Errorf("%v community == {}: %v, want cause %q", v, err, CauseCommunityEquals)
		}
	}
}
