package routemodel

import (
	"errors"
	"testing"

	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

func re(t *testing.T, s string) *policy.ASPathRE {
	t.Helper()
	r, err := policy.ParseASPathRegexp(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// matchPathCases is TestMatchPath's table; TestWriteVectors writes it into
// the vectors file as well.
var matchPathCases = []struct {
	re   string
	path []types.ASN
	want bool
	sets bool // the regexp names vectorSets and vectorAnySets (AS-ALL: every AS)
}{
	{"AS1", []types.ASN{2, 1, 3}, true, false}, // unanchored: anywhere
	{"^AS1", []types.ASN{2, 1}, false, false},
	{"^AS2 AS1$", []types.ASN{2, 1}, true, false},
	{"^AS2 .* AS3$", []types.ASN{2, 9, 9, 3}, true, false},
	{"^AS2+$", []types.ASN{2, 2, 2}, true, false},
	{"^AS2+$", []types.ASN{2, 3}, false, false},
	{"[AS1 - AS3]", []types.ASN{7, 2}, true, false},
	{"^[^AS1 AS2]$", []types.ASN{3}, true, false},
	{"^[^AS1 AS2]$", []types.ASN{2}, false, false},
	{"^.~*$", []types.ASN{5, 5, 5}, true, false},
	{"^.~*$", []types.ASN{5, 6}, false, false},
	{"^AS1{2,3}$", []types.ASN{1, 1, 1, 1}, false, false},
	{"^(AS1 | AS2 AS3)$", []types.ASN{2, 3}, true, false},
	// AS-ALL reaches AS-ANY: a negated class over it holds no AS, so it
	// matches no one-AS path; the positive class matches any.
	{"[^AS-ALL]", []types.ASN{7}, false, true},
	{"[AS-ALL]", []types.ASN{7}, true, true},
}

func TestMatchPath(t *testing.T) {
	for _, c := range matchPathCases {
		pm := resolve.PathMatch{RE: re(t, c.re)}
		if c.sets {
			pm.Sets = map[types.SetName]resolve.ASNSet{}
			add := func(name string, s resolve.ASNSet) {
				sn, err := types.ParseSetName(name)
				if err != nil {
					t.Fatal(err)
				}
				pm.Sets[sn] = s
			}
			for name, members := range vectorSets {
				add(name, resolve.NewASNSet(members...))
			}
			for _, name := range vectorAnySets {
				add(name, resolve.NewAnyASNSet())
			}
		}
		got, err := MatchPath(pm, c.path)
		if err != nil || got != c.want {
			t.Errorf("<%s> on %v = %v, %v; want %v", c.re, c.path, got, err, c.want)
		}
	}
}

// TestMatchPathNotSingleAS pins a fuzz-found input (testdata/fuzz/FuzzNormalizeFilter/106dd5b5f56a746e,
// "<000000*~{00}"): a same-AS repetition chained directly onto another
// quantifier ("AS0*~{0}") has no single AS to be "the same" as, so MatchPath
// declines with ErrNotSingleAS rather than guessing.
func TestMatchPathNotSingleAS(t *testing.T) {
	_, err := MatchPath(resolve.PathMatch{RE: re(t, "AS0*~{0}")}, []types.ASN{0})
	if !errors.Is(err, ErrNotSingleAS) {
		t.Errorf("AS0*~{0}: err = %v, want ErrNotSingleAS", err)
	}
}

// TestMatchPathTooComplex pins two rtconfig-fuzz-found inputs (task 16, fix
// round 1: FuzzTranslateRegexp found "0{1000}{1000}" and "0{700}{700}" against
// an empty path, minimized here to a matchable AS): a repeat nested inside
// another repeat multiplies out past what Go's regexp package can compile —
// building a million (or 490,000) copies of the inner group — even though
// each level's own Min/Max passes quant's 1000 cap on its own. MatchPath must
// report an error wrapping ErrTooComplex, not a bare compile error, and an
// ordinary regexp must still match.
func TestMatchPathTooComplex(t *testing.T) {
	for _, c := range []string{"AS1{700}{700}", "AS1{1000}{1000}"} {
		if _, err := MatchPath(resolve.PathMatch{RE: re(t, c)}, []types.ASN{1}); !errors.Is(err, ErrTooComplex) {
			t.Errorf("<%s>: err = %v, want ErrTooComplex", c, err)
		}
	}
	if got, err := MatchPath(resolve.PathMatch{RE: re(t, "^AS1$")}, []types.ASN{1}); err != nil || !got {
		t.Errorf("<^AS1$> on [1] = %v, %v; want true, nil", got, err)
	}
}

func TestMatchCommunity(t *testing.T) {
	has := []string{"1:1", "NO_EXPORT"}
	for _, c := range []struct {
		test policy.FilterCommunity
		want bool
	}{
		{policy.FilterCommunity{Op: policy.CommunityContains, Values: []string{"1:1"}}, true},
		{policy.FilterCommunity{Op: policy.CommunityContains, Values: []string{"1:1", "no_export"}}, true},
		{policy.FilterCommunity{Op: policy.CommunityContains, Values: []string{"1:2"}}, false},
		{policy.FilterCommunity{Op: policy.CommunityEquals, Values: []string{"1:1"}}, false},
		{policy.FilterCommunity{Op: policy.CommunityEquals, Values: []string{"no_export", "1:1"}}, true},
	} {
		if got := MatchCommunity(c.test, has); got != c.want {
			t.Errorf("%s on %v = %v, want %v", c.test, has, got, c.want)
		}
	}
}
