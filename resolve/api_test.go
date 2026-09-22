package resolve

import (
	"context"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/types"
)

// A custom Source may build typed objects itself, with no source text
// (Raw() == nil), and as values or pointers. Claims on them are checked through
// their typed fields, and nothing panics.
func TestSynthesizedAndPointerObjects(t *testing.T) {
	set := mustSet(t, "AS-P")
	common := object.Common{MntBy: []string{"MNT-X"}, Source: "TEST"}
	objs := []object.Object{
		object.AsSet{Name: set, Members: []object.SetMember{{Kind: object.MemberAS, AS: 1}},
			MbrsByRef: []string{"MNT-X"}, Common: object.Common{Source: "TEST"}},
		object.AutNum{AS: 5, MemberOf: []types.SetName{set}, Common: common},
		&object.AutNum{AS: 6, MemberOf: []types.SetName{set}, Common: common},
		object.AutNum{AS: 7, MemberOf: []types.SetName{set}, Common: object.Common{MntBy: []string{"MNT-EVIL"}, Source: "TEST"}},
	}
	got, err := (&Expander{Src: NewMemSource(objs)}).ExpandAS(context.Background(), set)
	if err != nil || !reflect.DeepEqual(asnList(got), []uint32{1, 5, 6}) {
		t.Errorf("ExpandAS(AS-P) = %v, %v; want [1 5 6]", asnList(got), err)
	}
	if !ClaimAllowed(&object.AutNum{AS: 6, MemberOf: []types.SetName{set}, Common: common}, &object.AsSet{Name: set, MbrsByRef: []string{"ANY"}, Common: object.Common{Source: "TEST"}}) {
		t.Error("ClaimAllowed rejects pointer forms")
	}
}

// Error types are returned as pointers, as in the standard library, and their
// messages name the cap and the value reached separately.
func TestErrorTypes(t *testing.T) {
	ctx := context.Background()
	src := corpus(t, asSet("AS-A", "AS-B"), asSet("AS-B", "AS1"), asSet("AS-ANYHOLDER", "AS-ANY"))
	_, err := (&Expander{Src: src, MaxVisited: 1}).ExpandAS(ctx, mustSet(t, "AS-A"))
	var tl *SetTooLargeError
	if !errors.As(err, &tl) || tl.Limit != LimitVisited || tl.Max != 1 || tl.Count != 2 ||
		!strings.Contains(err.Error(), "MaxVisited (1)") {
		t.Errorf("err = %v (%+v), want *SetTooLargeError naming MaxVisited (1), count 2", err, tl)
	}
	_, err = (&Expander{Src: src}).ExpandAS(ctx, mustSet(t, "AS-ANYHOLDER"))
	var any *AnySetError
	if !errors.As(err, &any) || any.Name.String() != "AS-ANY" {
		t.Errorf("err = %v, want *AnySetError{AS-ANY}", err)
	}
	_, err = (&Expander{Src: src}).ExpandAS(ctx, mustSet(t, "AS-NOPE"))
	if !errors.Is(err, ErrNotFound) || strings.Count(err.Error(), "resolve:") != 1 {
		t.Errorf("err = %q, want one wrapping ErrNotFound without a doubled prefix", err)
	}
}

// Every limit follows one rule: zero means the default, negative unlimited.
func TestNegativeLimitsAreUnlimited(t *testing.T) {
	e := &Expander{MaxDepth: -1, MaxPrefixes: -1, MaxVisited: -1}
	if e.maxDepth() != math.MaxInt || e.maxPrefixes() != math.MaxInt || e.maxVisited() != math.MaxInt {
		t.Errorf("negative limits = %d %d %d, want unlimited", e.maxDepth(), e.maxPrefixes(), e.maxVisited())
	}
	var chain []string
	for i := 0; i < 40; i++ { // deeper than the default MaxDepth of 32
		chain = append(chain, asSet(fmt.Sprintf("AS-C%d", i), fmt.Sprintf("AS-C%d, AS%d", i+1, i+1)))
	}
	src := corpus(t, append(chain, asSet("AS-C40", "AS41"))...)
	if _, err := (&Expander{Src: src}).ExpandAS(context.Background(), mustSet(t, "AS-C0")); err == nil {
		t.Error("a 40-deep chain passed the default MaxDepth")
	}
	if got, err := (&Expander{Src: src, MaxDepth: -1}).ExpandAS(context.Background(), mustSet(t, "AS-C0")); err != nil || got.Len() != 41 {
		t.Errorf("MaxDepth -1: %d ASNs, %v; want 41", got.Len(), err)
	}
}
