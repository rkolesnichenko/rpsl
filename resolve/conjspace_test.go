package resolve

import (
	"context"
	"testing"

	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/types"
)

// A conjunct NormalizeFilter built computes its space once, and its copies
// share it; one built by hand still answers.
func TestConjunctSpaceShared(t *testing.T) {
	src := corpus(t,
		"as-set: AS-A\nmembers: AS65001\nsource: TEST\n",
		"route: 10.1.0.0/16\norigin: AS65001\nsource: TEST\n",
		"route: 10.2.0.0/16\norigin: AS65001\nsource: TEST\n",
	)
	f, _ := policy.ParseFilter("AS-A AND NOT {10.2.0.0/16}")
	nf, err := (&Expander{Src: src}).NormalizeFilter(context.Background(), f)
	if err != nil || len(nf.Conjuncts) != 1 {
		t.Fatalf("%v, %v", nf, err)
	}
	c := nf.Conjuncts[0]
	if c.space == nil {
		t.Fatal("NormalizeFilter left the conjunct without its space cache")
	}
	want := types.SpaceOf(c.Prefixes.List()...).Minus(types.SpaceOf(c.NotPrefixes.List()...))
	copy1 := c
	if got := copy1.Space(); !got.Equal(want) {
		t.Fatalf("Space %v, want %v", got, want)
	}
	if copy1.space != c.space {
		t.Fatal("a copy does not share the cache")
	}
	if got := c.Space(); !got.Equal(want) {
		t.Fatalf("Space again %v, want %v", got, want)
	}
	byHand := Conjunct{Prefixes: c.Prefixes, NotPrefixes: c.NotPrefixes}
	if got := byHand.Space(); !got.Equal(want) {
		t.Fatalf("hand-built Space %v, want %v", got, want)
	}
}
