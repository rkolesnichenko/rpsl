package resolve

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/types"
)

// A filter-set named twice denotes the same thing both times: the second
// reference used to be taken for a cycle and denote nothing.
func TestFilterSetReferencedTwice(t *testing.T) {
	src := corpus(t,
		fltrSet("FLTR-A", "{10.0.0.0/8}"),
		fltrSet("FLTR-C", "FLTR-A"),
		fltrSet("FLTR-TOP", "FLTR-A AND FLTR-C"),
	)
	e := &Expander{Src: src}
	ctx := context.Background()
	got, err := e.ExpandFilterSet(ctx, mustSet(t, "FLTR-TOP"))
	if want := "10.0.0.0/8"; err != nil || strings.Join(rangeList(got), " ") != want {
		t.Errorf("ExpandFilterSet(FLTR-TOP) = %v, %v; want %s", rangeList(got), err, want)
	}
	for filter, want := range map[string]string{
		"FLTR-A AND FLTR-A": "10.0.0.0/8",
		"FLTR-A AND FLTR-C": "10.0.0.0/8",
	} {
		got, err := e.EvalFilter(ctx, mustFilter(t, filter))
		if err != nil || strings.Join(rangeList(got), " ") != want {
			t.Errorf("EvalFilter(%s) = %v, %v; want %s", filter, rangeList(got), err, want)
		}
	}
}

// A cycle of filter-sets denotes the least fixpoint: FLTR-A and FLTR-B each
// denote both /16s. Evaluated in one pass, the set entered second is computed
// while the first is still open, and denotes only part of it; referenced again
// (here by the AND), that partial value must not be what it contributes.
func TestFilterSetCycleFixpoint(t *testing.T) {
	src := corpus(t,
		fltrSet("FLTR-A", "{10.1.0.0/16} OR FLTR-B"),
		fltrSet("FLTR-B", "{10.2.0.0/16} OR FLTR-A"),
		fltrSet("FLTR-TOP", "FLTR-A AND FLTR-B"),
	)
	e := &Expander{Src: src}
	want := "10.1.0.0/16 10.2.0.0/16"
	for _, n := range []string{"FLTR-A", "FLTR-B", "FLTR-TOP"} {
		got, err := e.ExpandFilterSet(context.Background(), mustSet(t, n))
		if err != nil || strings.Join(rangeList(got), " ") != want {
			t.Errorf("ExpandFilterSet(%s) = %v, %v; want %s", n, rangeList(got), err, want)
		}
	}
}

// getSetCounter counts GetSet calls.
type getSetCounter struct {
	*MemSource
	mu sync.Mutex
	n  int
}

func (c *getSetCounter) GetSet(ctx context.Context, name types.SetName) (object.NamedSet, error) {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
	return c.MemSource.GetSet(ctx, name)
}

// MaxVisited bounds one EvalFilter call as a whole: each set reference used to
// run its own expansion with a fresh budget, so the sets fetched grew with the
// product of references and depth.
func TestEvalFilterVisitedBudget(t *testing.T) {
	var texts []string
	for i := 0; i < 30; i++ {
		texts = append(texts, routeSet(fmt.Sprintf("RS-C%d", i), fmt.Sprintf("RS-C%d", i+1)))
	}
	texts = append(texts, routeSet("RS-C30", "10.0.0.0/8"))
	var refs, distinct []string
	for i := 0; i < 200; i++ {
		refs = append(refs, "RS-C0")
		name := fmt.Sprintf("RS-D%d", i)
		texts = append(texts, routeSet(name, "RS-C0"))
		distinct = append(distinct, name)
	}
	src := &getSetCounter{MemSource: corpus(t, texts...)}
	e := &Expander{Src: src, MaxVisited: 250}
	ctx := context.Background()

	// 200 references to one route-set: one expansion.
	got, err := e.EvalFilter(ctx, mustFilter(t, strings.Join(refs, " OR ")))
	if err != nil || strings.Join(rangeList(got), " ") != "10.0.0.0/8" {
		t.Fatalf("EvalFilter(RS-C0 OR …) = %v, %v", rangeList(got), err)
	}
	if src.n > 40 {
		t.Errorf("200 references to one 31-set chain fetched %d sets, want it expanded once", src.n)
	}

	// 200 distinct route-sets, each over the chain: 200*32 sets > MaxVisited.
	src.n = 0
	_, err = e.EvalFilter(ctx, mustFilter(t, strings.Join(distinct, " OR ")))
	var tl *SetTooLargeError
	if !errors.As(err, &tl) || tl.Limit != LimitVisited {
		t.Errorf("EvalFilter over 200 distinct chains: %v, want MaxVisited", err)
	}
	if src.n > 2*250 {
		t.Errorf("fetched %d sets under MaxVisited 250", src.n)
	}
}

// failingRoutes fails OriginatedRoutes, naming the AS.
type failingRoutes struct{ *MemSource }

func (failingRoutes) OriginatedRoutes(_ context.Context, as types.ASN, _ types.AFI) ([]netip.Prefix, error) {
	return nil, fmt.Errorf("routes of %s: unavailable", as)
}

// Which error EvalFilter returns does not depend on map iteration order.
func TestEvalFilterErrorDeterministic(t *testing.T) {
	src := failingRoutes{corpus(t, asSet("AS-X", "AS1, AS2, AS3, AS4, AS5, AS6, AS7, AS8"))}
	e := &Expander{Src: src}
	f := policy.FilterASExpr{AS: policy.ASSetRef{Name: mustSet(t, "AS-X")}}
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		_, err := e.EvalFilter(context.Background(), f)
		if err == nil {
			t.Fatal("EvalFilter succeeded over a failing Source")
		}
		seen[err.Error()] = true
	}
	if len(seen) != 1 {
		t.Errorf("EvalFilter returned %d different errors: %v", len(seen), seen)
	}
}

// intersectSlow is the definition intersectRanges must agree with: every pair.
func intersectSlow(a, b rangeSetOf) rangeSetOf {
	out := rangeSetOf{}
	for x := range a {
		for y := range b {
			if c, ok := x.Intersect(y); ok {
				out[c] = struct{}{}
			}
		}
	}
	return out
}

func randomRanges(r *rand.Rand, n int) rangeSetOf {
	out := rangeSetOf{}
	for i := 0; i < n; i++ {
		var p netip.Prefix
		if r.Intn(4) == 0 {
			bits := 28 + r.Intn(9)
			a := [16]byte{0x20, 0x01, 0x0d, 0xb8, byte(r.Intn(4) << 4)}
			p = netip.PrefixFrom(netip.AddrFrom16(a), bits).Masked()
		} else {
			bits := 6 + r.Intn(9)
			a := [4]byte{10, byte(r.Intn(4) << 6), 0, 0}
			if r.Intn(8) == 0 {
				a[0] = 0
			}
			p = netip.PrefixFrom(netip.AddrFrom4(a), bits).Masked()
		}
		lo := p.Bits() + r.Intn(4)
		hi := lo + r.Intn(4)
		if pr, ok := types.NewPrefixRange(p, lo, hi); ok {
			out[pr] = struct{}{}
		}
	}
	return out
}

func sortedRanges(s rangeSetOf) []string {
	var out []string
	for r := range s {
		out = append(out, r.String())
	}
	sort.Strings(out)
	return out
}

// intersectRanges finds the same ranges as the pairwise definition.
func TestIntersectRangesOracle(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	ev := newFilterEval(&Expander{}, context.Background())
	for i := 0; i < 500; i++ {
		a, b := randomRanges(r, r.Intn(30)), randomRanges(r, r.Intn(30))
		got, err := ev.intersect(a, b)
		if err != nil {
			t.Fatal(err)
		}
		if g, w := sortedRanges(got), sortedRanges(intersectSlow(a, b)); strings.Join(g, " ") != strings.Join(w, " ") {
			t.Fatalf("intersect(%v, %v)\n got %v\nwant %v", sortedRanges(a), sortedRanges(b), g, w)
		}
	}
}

// A large AND stops when its context is cancelled rather than running on.
func TestIntersectHonoursContext(t *testing.T) {
	a := rangeSetOf{}
	for k := 9; k <= 23; k++ {
		r, _ := types.NewPrefixRange(netip.MustParsePrefix("10.0.0.0/8"), k, k)
		a[r] = struct{}{}
	}
	b := rangeSetOf{}
	for i := 0; i < 1<<12; i++ {
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 4), byte(i << 4), 0}), 24)
		r, _ := types.NewPrefixRange(p, 24, 24)
		b[r] = struct{}{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ev := newFilterEval(&Expander{}, ctx)
	if _, err := ev.intersect(a, b); !errors.Is(err, context.Canceled) {
		t.Errorf("intersect under a cancelled context: %v, want context.Canceled", err)
	}
	// Disjoint sets of 20,000 ranges each intersect at once, to nothing.
	a, b = rangeSetOf{}, rangeSetOf{}
	for i := 0; i < 20000; i++ {
		pa := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}), 24)
		pb := netip.PrefixFrom(netip.AddrFrom4([4]byte{11, byte(i >> 8), byte(i), 0}), 24)
		ra, _ := types.NewPrefixRange(pa, 24, 24)
		rb, _ := types.NewPrefixRange(pb, 24, 24)
		a[ra], b[rb] = struct{}{}, struct{}{}
	}
	ev = newFilterEval(&Expander{}, context.Background())
	if got, err := ev.intersect(a, b); err != nil || len(got) != 0 {
		t.Errorf("disjoint intersect = %d ranges, %v", len(got), err)
	}
}
