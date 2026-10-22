package consist

import (
	"testing"

	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

func TestRejectsEveryPath(t *testing.T) {
	asR, err := types.ParseSetName("AS-R")
	if err != nil {
		t.Fatal(err)
	}
	asS, err := types.ParseSetName("AS-S")
	if err != nil {
		t.Fatal(err)
	}
	sets := map[types.SetName]resolve.ASNSet{asR: resolve.NewAnyASNSet(), asS: resolve.NewASNSet(1)}
	for _, c := range []struct {
		re   string
		want bool
	}{
		{".", true}, {"AS-ANY", true}, {"AS-R", true}, {".* AS-R .*", true},
		{"[AS1 AS-ANY]", true}, {"[AS-R]", true},
		{"AS1*", true}, {"AS1? AS2?", true},
		{".+", true}, {"(AS1|.)", true}, {"AS1? .", true},
		{"AS1 AS-R", false}, {".* AS64512 .*", false}, {"^AS-R", false}, {"^.$", false}, {"AS-R$", false},
		{".{2}", false}, {"[^AS1]", false}, {"AS-S", false}, {"PeerAS", false}, {"AS1", false},
	} {
		re, err := policy.ParseASPathRegexp(c.re)
		if err != nil {
			t.Fatalf("%q: %v", c.re, err)
		}
		if got := rejectsEveryPath(resolve.PathMatch{Negated: true, RE: re, Sets: sets}); got != c.want {
			t.Errorf("rejectsEveryPath(<%s>) = %v, want %v", c.re, got, c.want)
		}
	}
}
