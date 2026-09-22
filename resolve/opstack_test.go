package resolve

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"testing"

	"github.com/rkolesnichenko/rpsl/types"
)

// An opStack applies exactly what applying its operators one by one does,
// innermost first, for ranges of both families.
func TestOpStackMatchesSequentialApply(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	randOp := func() types.RangeOperator {
		switch r.IntN(5) {
		case 0:
			return types.RangeOperator{Op: types.RangePlus}
		case 1:
			return types.RangeOperator{Op: types.RangeMinus}
		case 2:
			n := uint8(r.IntN(130))
			return types.RangeOperator{Op: types.RangeLength, N: n, M: n}
		case 3:
			n := uint8(r.IntN(130))
			return types.RangeOperator{Op: types.RangeRange, N: n, M: n + uint8(r.IntN(130-int(n)))}
		}
		return types.RangeOperator{}
	}
	bases := []string{"10.0.0.0/8", "192.0.2.0/24", "192.0.2.1/32", "0.0.0.0/0", "2001:db8::/32", "2001:db8::1/128", "::/0"}
	for i := 0; i < 20000; i++ {
		ops := make([]types.RangeOperator, r.IntN(5)) // ops[0] outermost
		for j := range ops {
			ops[j] = randOp()
		}
		var stack opStack
		for _, o := range ops {
			stack = stack.push(o)
		}
		base := netip.MustParsePrefix(bases[r.IntN(len(bases))])
		hi := base.Addr().BitLen()
		if r.IntN(2) == 0 {
			hi = base.Bits()
		}
		in, _ := types.NewPrefixRange(base, base.Bits(), hi)

		want, wantOK := in, true
		for j := len(ops) - 1; j >= 0 && wantOK; j-- {
			want, wantOK = ops[j].Apply(want)
		}
		got, ok := stack.apply(in)
		if ok != wantOK || (ok && got != want) {
			t.Fatalf("%s under %v: stack gives %v,%v; sequential Apply %v,%v", in, fmt.Sprint(ops), got, ok, want, wantOK)
		}
	}
}

// Stacks that do the same thing are the same value.
func TestOpStackEquivalentStacksAreEqual(t *testing.T) {
	plus, minus := types.RangeOperator{Op: types.RangePlus}, types.RangeOperator{Op: types.RangeMinus}
	var empty opStack
	cases := []struct {
		name string
		a, b opStack
	}{
		{"^+^+ = ^+", empty.push(plus).push(plus), empty.push(plus)},
		{"^-^+ = ^-", empty.push(minus).push(plus), empty.push(minus)},
		{"^+^- = ^-", empty.push(plus).push(minus), empty.push(minus)},
		{"zero operator", empty.push(types.RangeOperator{}), empty},
	}
	for _, c := range cases {
		if c.a != c.b {
			t.Errorf("%s: stacks differ", c.name)
		}
	}
	if empty.push(minus).push(minus) == empty.push(minus) {
		t.Error("^-^- must differ from ^- (it is ^(k+2)-32)")
	}
}
