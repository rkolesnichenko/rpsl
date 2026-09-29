package routemodel

import (
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

func TestMatchPath(t *testing.T) {
	for _, c := range []struct {
		re   string
		path []types.ASN
		want bool
	}{
		{"AS1", []types.ASN{2, 1, 3}, true}, // unanchored: anywhere
		{"^AS1", []types.ASN{2, 1}, false},
		{"^AS2 AS1$", []types.ASN{2, 1}, true},
		{"^AS2 .* AS3$", []types.ASN{2, 9, 9, 3}, true},
		{"^AS2+$", []types.ASN{2, 2, 2}, true},
		{"^AS2+$", []types.ASN{2, 3}, false},
		{"[AS1 - AS3]", []types.ASN{7, 2}, true},
		{"^[^AS1 AS2]$", []types.ASN{3}, true},
		{"^[^AS1 AS2]$", []types.ASN{2}, false},
		{"^.~*$", []types.ASN{5, 5, 5}, true},
		{"^.~*$", []types.ASN{5, 6}, false},
		{"^AS1{2,3}$", []types.ASN{1, 1, 1, 1}, false},
		{"^(AS1 | AS2 AS3)$", []types.ASN{2, 3}, true},
	} {
		got, err := MatchPath(resolve.PathMatch{RE: re(t, c.re)}, c.path)
		if err != nil || got != c.want {
			t.Errorf("<%s> on %v = %v, %v; want %v", c.re, c.path, got, err, c.want)
		}
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
