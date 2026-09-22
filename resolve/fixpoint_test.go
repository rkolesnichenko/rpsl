package resolve

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"math"
	"math/rand/v2"
	"net/netip"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl/types"
)

// ---- a brute-force reference for route-sets with operators and cycles ----

// opGraph is a random route-set graph whose members carry range operators. The
// oracle evaluates it by the RFC 2622 definition, independently of the engine:
// a set denotes a set of concrete prefixes; an operator applies to each prefix
// of its operand (§5.2); a set's value is the union of its members' values; and
// cycles are resolved by iterating from the empty set to the least fixpoint.
type opGraph struct {
	prefixes [][]member // set i's prefix-range members
	sets     [][]member // set i's nested route-set members (index in pfx)
}

type member struct {
	pfx string // a prefix-range text, or "" for a set member
	set int
	op  string // "", "^+", "^-", "^n", "^n-m"
}

// universe is a small tree of prefixes per family, so every operator result is
// enumerable: 10.0.0.0/28 (lengths 28-32) and 2001:db8::/126 (126-128).
var universe = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/28"), netip.MustParsePrefix("2001:db8::/126")}

func randomOpGraph(r *rand.Rand, n int) opGraph {
	g := opGraph{prefixes: make([][]member, n), sets: make([][]member, n)}
	randOp := func(base netip.Prefix) string {
		lo, hi := base.Bits(), base.Addr().BitLen()
		switch r.IntN(6) {
		case 0:
			return "^+"
		case 1:
			return "^-"
		case 2:
			return fmt.Sprintf("^%d", lo+r.IntN(hi-lo+1))
		case 3:
			a := lo + r.IntN(hi-lo+1)
			return fmt.Sprintf("^%d-%d", a, a+r.IntN(hi-a+1))
		}
		return ""
	}
	for i := 0; i < n; i++ {
		for k := r.IntN(3); k > 0; k-- {
			u := universe[r.IntN(len(universe))]
			p := netip.PrefixFrom(u.Addr(), u.Bits()+r.IntN(u.Addr().BitLen()-u.Bits()+1)).Masked()
			op := randOp(p) // ^n and ^n-m bounds are drawn from p's own length up
			if op == "^-" && p.Bits() == p.Addr().BitLen() {
				op = "" // a host route with ^- denotes nothing; covered elsewhere
			}
			g.prefixes[i] = append(g.prefixes[i], member{pfx: p.String(), op: op})
		}
		for k := r.IntN(4); k > 0; k-- {
			g.sets[i] = append(g.sets[i], member{set: r.IntN(n), op: randOp(universe[r.IntN(len(universe))])})
		}
	}
	return g
}

// apply is the RFC's operator on one exact prefix: the more-specifics of p with
// lengths in the operator's window, clamped to p's family.
func apply(op string, p netip.Prefix) []netip.Prefix {
	bits, maxBits := p.Bits(), p.Addr().BitLen()
	lo, hi := bits, bits
	switch {
	case op == "":
	case op == "^+":
		hi = maxBits
	case op == "^-":
		lo, hi = bits+1, maxBits
	default:
		var n, m int
		if _, err := fmt.Sscanf(op, "^%d-%d", &n, &m); err != nil {
			fmt.Sscanf(op, "^%d", &n)
			m = n
		}
		lo, hi = max(n, bits), min(m, maxBits)
	}
	var out []netip.Prefix
	for l := lo; l <= hi; l++ {
		r, _ := types.NewPrefixRange(p, l, l)
		for q := range r.All() {
			out = append(out, q)
		}
	}
	return out
}

func (g opGraph) oracle() []map[netip.Prefix]bool {
	val := make([]map[netip.Prefix]bool, len(g.sets))
	for i := range val {
		val[i] = map[netip.Prefix]bool{}
	}
	for changed := true; changed; {
		changed = false
		for i := range val {
			next := map[netip.Prefix]bool{}
			for _, m := range g.prefixes[i] {
				for _, q := range apply(m.op, netip.MustParsePrefix(m.pfx)) {
					next[q] = true
				}
			}
			for _, m := range g.sets[i] {
				for p := range val[m.set] {
					for _, q := range apply(m.op, p) {
						next[q] = true
					}
				}
			}
			if !maps.Equal(next, val[i]) {
				val[i], changed = next, true
			}
		}
	}
	return val
}

func (g opGraph) corpus(t *testing.T) *MemSource {
	var texts []string
	for i := range g.sets {
		var members []string
		for _, m := range g.prefixes[i] {
			members = append(members, m.pfx+m.op)
		}
		for _, m := range g.sets[i] {
			members = append(members, fmt.Sprintf("RS-S%d%s", m.set, m.op))
		}
		texts = append(texts, routeSet(fmt.Sprintf("RS-S%d", i), members...))
	}
	return corpus(t, texts...)
}

// Route-sets with operators along cycles expand to the RFC's least fixpoint,
// for every set of every random graph.
func TestPropertyOperatorFixpoint(t *testing.T) {
	for seed := uint64(1); seed <= 400; seed++ {
		r := rand.New(rand.NewPCG(seed, 7))
		g := randomOpGraph(r, 2+r.IntN(7))
		want := g.oracle()
		src := g.corpus(t)
		for i := range g.sets {
			got, err := (&Expander{Src: src}).ExpandPrefixes(context.Background(), mustSet(t, fmt.Sprintf("RS-S%d", i)))
			if err != nil {
				t.Fatalf("seed %d RS-S%d: %v\n%+v", seed, i, err, g)
			}
			if w := sortPrefixes(slices.Collect(maps.Keys(want[i]))); !reflect.DeepEqual(got.List(), w) {
				t.Fatalf("seed %d RS-S%d: engine %v\noracle %v\ngraph %+v", seed, i, got.List(), w, g)
			}
		}
	}
}

func sortPrefixes(ps []netip.Prefix) []netip.Prefix {
	out := append([]netip.Prefix{}, ps...)
	slices.SortFunc(out, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	return out
}

// ---- operators through cycles, and operator-stack blow-up ----

func TestOperatorCyclesReachAFixpoint(t *testing.T) {
	ctx := context.Background()
	// RS-A = 192.0.2.0/24 ∪ RS-B^+, RS-B = 198.51.100.0/24 ∪ RS-A: the operator
	// applies to everything RS-B denotes, including RS-A itself.
	cyc := corpus(t, routeSet("RS-A", "RS-B^+, 192.0.2.0/24"), routeSet("RS-B", "RS-A, 198.51.100.0/24"))
	got, err := (&Expander{Src: cyc}).ExpandPrefixRanges(ctx, mustSet(t, "RS-A"))
	if want := []string{"192.0.2.0/24", "192.0.2.0/24^+", "198.51.100.0/24^+"}; err != nil || !reflect.DeepEqual(rangeList(got), want) {
		t.Errorf("operator cycle = %v, %v; want %v", rangeList(got), err, want)
	}
	self := corpus(t, routeSet("RS-O", "RS-O^+, 192.0.2.0/24"))
	got, err = (&Expander{Src: self}).ExpandPrefixRanges(ctx, mustSet(t, "RS-O"))
	if want := []string{"192.0.2.0/24", "192.0.2.0/24^+"}; err != nil || !reflect.DeepEqual(rangeList(got), want) {
		t.Errorf("self-reference = %v, %v; want %v", rangeList(got), err, want)
	}
}

// A chain of sets that each list the next under both ^+ and ^- used to walk
// 2^k literal operator stacks; equivalent stacks are now one state. Repeated ^-
// yields every window /24^k-32, so the result is /24^+, ^-, ^26-32 … ^32.
func TestOperatorStacksDoNotMultiply(t *testing.T) {
	const k = 18
	var texts []string
	for i := 0; i < k; i++ {
		texts = append(texts, routeSet(fmt.Sprintf("RS-L%d", i), fmt.Sprintf("RS-L%d^+, RS-L%d^-", i+1, i+1)))
	}
	texts = append(texts, routeSet(fmt.Sprintf("RS-L%d", k), "192.0.2.0/24"))
	start := time.Now()
	got, err := (&Expander{Src: corpus(t, texts...)}).ExpandPrefixRanges(context.Background(), mustSet(t, "RS-L0"))
	want := []string{"192.0.2.0/24^+", "192.0.2.0/24^-"}
	for k := 26; k < 32; k++ {
		want = append(want, fmt.Sprintf("192.0.2.0/24^%d-32", k))
	}
	want = append(want, "192.0.2.0/24^32")
	if err != nil || !reflect.DeepEqual(rangeList(got), want) {
		t.Errorf("chain = %v, %v; want %v", rangeList(got), err, want)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("chain took %v", d)
	}
}

// Cancellation reaches inside the enumeration of a single range: a /11^+ is four
// million prefixes, and a raised MaxPrefixes must not let it ignore a deadline.
func TestExpandPrefixesHonorsContextWithinARange(t *testing.T) {
	src := corpus(t, routeSet("RS-BIG", "10.0.0.0/11^+"))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := (&Expander{Src: src, MaxPrefixes: math.MaxInt}).ExpandPrefixes(ctx, mustSet(t, "RS-BIG"))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want context.DeadlineExceeded", err)
	}
	if d := time.Since(start); d > 300*time.Millisecond {
		t.Errorf("returned after %v, want promptly after the 10ms deadline", d)
	}
}
