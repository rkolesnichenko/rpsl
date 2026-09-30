package rtconfig

import (
	"errors"
	"testing"

	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/resolve"
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
