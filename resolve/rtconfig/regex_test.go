package rtconfig

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/types"
)

// pathMatch parses a regexp and gives each as-set it names the members listed.
func pathMatch(t *testing.T, re string, sets map[string][]types.ASN) resolve.PathMatch {
	t.Helper()
	r, err := policy.ParseASPathRegexp(re)
	if err != nil {
		t.Fatal(err)
	}
	m := resolve.PathMatch{RE: r, Sets: map[types.SetName]resolve.ASNSet{}}
	for name, asns := range sets {
		n, err := types.ParseSetName(name)
		if err != nil {
			t.Fatal(err)
		}
		m.Sets[n] = resolve.NewASNSet(asns...)
	}
	return m
}

var fooSet = map[string][]types.ASN{"AS-FOO": {10, 11}, "AS-EMPTY": {}}

func TestTranslatePath(t *testing.T) {
	for _, c := range []struct {
		re               string
		ios, junos, bird string // "" means refused (tested below)
	}{
		{"AS1", "_1_", ".* 1 .*", "[= * 1 * =]"},
		{"^AS1$", "^_1$", "1", "[= 1 =]"},
		{"^AS1 .* AS2$", "^_1(_[0-9]+)*_2$", "1 .* 2", "[= 1 * 2 =]"},
		{"^AS1 AS-FOO$", "^_1_(10|11)$", "1 (10|11)", "[= 1 [10, 11] =]"},
		{"^AS-EMPTY", "^_0_", "0 .*", "[= 0 * =]"},
		{"^AS1+$", "^(_1)+$", "1+", ""},
		{"^(AS1 | AS2) .+$", "^(_1|_2)(_[0-9]+)+$", "(1|2) .+", ""},
		{"^[AS1 AS5 - AS7]$", "^_(1|5|6|7)$", "(1|5-7)", "[= [1, 5..7] =]"},
		{"^AS1{2,3}$", "^_1_1(_1)?$", "1{2,3}", ""},
		{"^AS1~*$", "^(_1)*$", "1*", ""},
		{"^$", "^$", "()", "[= =]"},
		{"^. .* AS-ANY$", "^_[0-9]+(_[0-9]+)*_[0-9]+$", ". .* .", "[= ? * ? =]"},
		{"(AS1 | ^AS2)", "(_1|^_2)_", "", ""},
		// FuzzTranslateRegexp found this shape ("^AS1{2,3}*0"): a repeat
		// nested directly under another repeat. Junos wrote "1{2,3}*" (no
		// group around the nested quantifier), which Junos's as-path-regex
		// rejects as a stacked quantifier the same way Go's regexp package
		// does ("invalid nested repetition operator").
		{"AS1{2,3}*", "(_1_1(_1)?)*_", ".* (1{2,3})* .*", ""},
	} {
		for _, v := range []struct {
			vendor Vendor
			want   string
		}{{IOS, c.ios}, {IOSXR, c.ios}, {Junos, c.junos}, {BIRD2, c.bird}} {
			g := &Generator{Vendor: v.vendor}
			got, err := g.translatePath(pathMatch(t, c.re, fooSet), c.re)
			if v.want == "" {
				if !errors.Is(err, ErrUnsupported) {
					t.Errorf("%v <%s> = %q, %v; want refused", v.vendor, c.re, got, err)
				}
				continue
			}
			if err != nil || got != v.want {
				t.Errorf("%v <%s> = %q, %v; want %q", v.vendor, c.re, got, err, v.want)
			}
		}
	}
}

func TestTranslatePathRefuses(t *testing.T) {
	for _, c := range []struct {
		re    string
		v     Vendor
		cause string
	}{
		{"[^AS1]", IOS, CauseNegatedClass},
		{"[^AS1]", Junos, CauseNegatedClass},
		{"[^AS1]", BIRD2, CauseNegatedClass},
		{"AS-FOO~*", IOS, CauseSameAS},
		{"AS-FOO~*", Junos, CauseSameAS},
		{"AS1 ^AS2", Junos, CausePathShape},
		{"(AS1 | AS2)", BIRD2, CausePathShape},
		{"AS1*", BIRD2, CausePathShape},
		{"AS1{40}", IOS, CausePathShape},
		{"[AS1 - AS5000]", IOS, CausePathShape},
	} {
		g := &Generator{Vendor: c.v}
		_, err := g.translatePath(pathMatch(t, c.re, fooSet), c.re)
		var ue *UnsupportedError
		if !errors.As(err, &ue) || ue.Cause != c.cause {
			t.Errorf("%v <%s>: err %v, want cause %q", c.v, c.re, err, c.cause)
		}
	}
}

// anySetText is an as-set reaching AS-ANY: in an AS-path regexp it is every
// AS (resolve.ASNSet.Any), which no printer writes.
const anySetText = "as-set: AS-R\nmembers: AS-ANY, AS9\nsource: TEST\n"

// A regexp naming a set that reaches AS-ANY is refused with CauseAnySet,
// in both polarities, on every vendor, and nothing is written: an any-set
// lists no AS, so writing its List() would give "_0" — under NOT, a list
// that permits every route.
func TestTranslateAnySet(t *testing.T) {
	asR, err := types.ParseSetName("AS-R")
	if err != nil {
		t.Fatal(err)
	}
	anyR := map[types.SetName]resolve.ASNSet{asR: resolve.NewAnyASNSet()}
	for _, v := range Vendors() {
		for _, re := range []string{"AS-R$", "[AS-R AS1]", "^AS1 AS-R$", "[AS-ANY AS-R]"} {
			r, err := policy.ParseASPathRegexp(re)
			if err != nil {
				t.Fatal(err)
			}
			for _, neg := range []bool{false, true} {
				m := resolve.PathMatch{RE: r, Sets: anyR, Negated: neg}
				g := &Generator{Vendor: v}
				got, err := g.translatePath(m, re)
				var ue *UnsupportedError
				if !errors.As(err, &ue) || ue.Cause != CauseAnySet || !strings.Contains(ue.Term, "AS-R") {
					t.Errorf("%v <%s>: %q, %v; want refused with %q naming AS-R", v, re, got, err, CauseAnySet)
				}
				var b bytes.Buffer
				if err := g.WriteASPathList(&b, m); !errors.As(err, &ue) || ue.Cause != CauseAnySet || b.Len() != 0 {
					t.Errorf("%v WriteASPathList <%s> (negated %v): %v, wrote %q", v, re, neg, err, b.String())
				}
			}
		}
		for _, imp := range []string{"from AS2 accept <AS-R$>", "from AS2 accept <[AS-R AS1]>", "from AS2 accept ANY AND NOT <AS-R>",
			"from AS2 accept AS2 AND NOT <^AS2 AS-R>"} {
			s, p := anySetPolicy(t, imp)
			if !p.Clauses[0].Filter.Conjuncts[0].Paths[0].Sets[asR].Any() {
				t.Fatalf("%s: AS-R is not any: %+v", imp, p.Clauses[0].Filter)
			}
			g := &Generator{Vendor: v}
			var b bytes.Buffer
			var ue *UnsupportedError
			if err := g.WriteImport(&b, s, p); !errors.As(err, &ue) || ue.Cause != CauseAnySet || b.Len() != 0 {
				t.Errorf("%v WriteImport %q: %v, wrote %q; want refused with %q, nothing written", v, imp, err, b.String(), CauseAnySet)
			}
		}
	}
}

// anySetPolicy is fixturePolicy with AS-R (anySetText) in the source.
func anySetPolicy(t *testing.T, imp string) (peval.Session, peval.Policy) {
	t.Helper()
	an := "aut-num: AS1\nas-name: ONE\nimport: " + imp + "\nsource: TEST\n"
	ev := &peval.Evaluator{Src: fixtureSource(t, an, anySetText)}
	p, err := ev.Import(context.Background(), v4Session)
	if err != nil {
		t.Fatalf("peval %q: %v", imp, err)
	}
	return v4Session, p
}
