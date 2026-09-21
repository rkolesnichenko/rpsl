package resolve

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/types"
)

// ---- order independence (the depth-limit bug) ----

// A set first reached along a long path must still be expanded fully when it is
// also reachable within MaxDepth: the result may not depend on member order.
func TestExpansionIndependentOfMemberOrder(t *testing.T) {
	for _, order := range [][]string{{"AS-X", "AS-C1"}, {"AS-C1", "AS-X"}} {
		src := corpus(t,
			asSet("AS-TOP", order...),
			asSet("AS-C1", "AS-C2"),
			asSet("AS-C2", "AS-X"),
			asSet("AS-X", "AS-Y"),
			asSet("AS-Y", "AS100"),
		)
		got, err := (&Expander{Src: src, MaxDepth: 3}).ExpandAS(context.Background(), mustSet(t, "AS-TOP"))
		if err != nil || !reflect.DeepEqual(asnList(got), []uint32{100}) {
			t.Errorf("order %v: ExpandAS = %v, %v; want [100]", order, asnList(got), err)
		}
	}
}

// graph is a random as-set graph plus the independent BFS oracle used to check
// the engine against.
type graph struct {
	asns  [][]uint32 // set i's direct ASN members
	edges [][]int    // set i's nested set members
}

func randomGraph(r *rand.Rand, n int) graph {
	g := graph{asns: make([][]uint32, n), edges: make([][]int, n)}
	for i := 0; i < n; i++ {
		for k := r.IntN(3); k > 0; k-- {
			g.asns[i] = append(g.asns[i], uint32(1000+r.IntN(4*n)))
		}
		for k := r.IntN(4); k > 0; k-- {
			g.edges[i] = append(g.edges[i], r.IntN(n)) // cycles and self-loops allowed
		}
	}
	return g
}

// oracle returns the ASNs reachable from set 0 and the largest shortest-path
// distance of any reachable set.
func (g graph) oracle() (asns []uint32, maxDist int) {
	dist := map[int]int{0: 0}
	queue := []int{0}
	seen := map[uint32]bool{}
	for len(queue) > 0 {
		i := queue[0]
		queue = queue[1:]
		maxDist = max(maxDist, dist[i])
		for _, a := range g.asns[i] {
			seen[a] = true
		}
		for _, j := range g.edges[i] {
			if _, ok := dist[j]; !ok {
				dist[j] = dist[i] + 1
				queue = append(queue, j)
			}
		}
	}
	asns = []uint32{} // non-nil, like asnList, so an empty expansion compares equal
	for a := range seen {
		asns = append(asns, a)
	}
	sort.Slice(asns, func(i, j int) bool { return asns[i] < asns[j] })
	return asns, maxDist
}

// corpus builds the graph as RPSL, listing each set's members in the order
// chosen by perm (so the same graph can be presented in different orders).
func (g graph) corpus(t *testing.T, r *rand.Rand) *MemSource {
	var texts []string
	for i := range g.asns {
		var members []string
		for _, a := range g.asns[i] {
			members = append(members, fmt.Sprintf("AS%d", a))
		}
		for _, j := range g.edges[i] {
			members = append(members, fmt.Sprintf("AS-S%d", j))
		}
		r.Shuffle(len(members), func(a, b int) { members[a], members[b] = members[b], members[a] })
		texts = append(texts, asSet(fmt.Sprintf("AS-S%d", i), members...))
	}
	return corpus(t, texts...)
}

func TestPropertyExpansionMatchesOracle(t *testing.T) {
	for seed := uint64(1); seed <= 300; seed++ {
		r := rand.New(rand.NewPCG(seed, 42))
		g := randomGraph(r, 5+r.IntN(25))
		want, maxDist := g.oracle()
		for _, maxDepth := range []int{0, 1, 2, 3, 100} { // 0 = default (32)
			limit := maxDepth
			if limit == 0 {
				limit = 32
			}
			for attempt := 0; attempt < 2; attempt++ { // two member orders
				e := &Expander{Src: g.corpus(t, r), MaxDepth: maxDepth}
				got, err := e.ExpandAS(context.Background(), mustSet(t, "AS-S0"))
				if maxDist > limit {
					var tl ErrSetTooLarge
					if !errors.As(err, &tl) || tl.Limit != LimitDepth {
						t.Fatalf("seed %d MaxDepth %d: err = %v, want ErrSetTooLarge{LimitDepth} (oracle depth %d)",
							seed, maxDepth, err, maxDist)
					}
					continue
				}
				if err != nil || !reflect.DeepEqual(asnList(got), want) {
					t.Fatalf("seed %d MaxDepth %d: ExpandAS = %v, %v; oracle %v", seed, maxDepth, asnList(got), err, want)
				}
			}
		}
	}
}

// ---- range operators on members (RFC 2622 §5.2) ----

func rangeList(s RangeSet) []string {
	var out []string
	for _, r := range s.List() {
		out = append(out, r.String())
	}
	return out
}

func TestExpandPrefixRangesMemberOperators(t *testing.T) {
	src := corpus(t,
		routeSet("RS-A", "RS-B^+, AS5^24, 192.0.2.0/24"),
		routeSet("RS-B", "198.51.100.0/30, 10.0.0.0/30^31"),
		"route: 203.0.112.0/22\norigin: AS5\nsource: TEST\n",
	)
	e := &Expander{Src: src}
	ranges, err := e.ExpandPrefixRanges(context.Background(), mustSet(t, "RS-A"))
	want := []string{
		"10.0.0.0/30^-",     // {…^31}^+ = ^31-32 = ^- on a /30
		"192.0.2.0/24",      // plain member
		"198.51.100.0/30^+", // {exact}^+
		"203.0.112.0/22^24", // AS5's route ^24
	}
	if err != nil || !reflect.DeepEqual(rangeList(ranges), want) {
		t.Fatalf("ExpandPrefixRanges = %v, %v; want %v", rangeList(ranges), err, want)
	}
	pfx, err := e.ExpandPrefixes(context.Background(), mustSet(t, "RS-A"))
	if err != nil || pfx.Len() != 6+1+7+4 {
		t.Errorf("ExpandPrefixes = %d prefixes, %v; want 18", pfx.Len(), err)
	}
}

func TestOperatorsComposeAlongPath(t *testing.T) {
	src := corpus(t, routeSet("RS-TOP", "RS-MID^-"), routeSet("RS-MID", "192.0.2.0/24^+"))
	got, err := (&Expander{Src: src}).ExpandPrefixRanges(context.Background(), mustSet(t, "RS-TOP"))
	if err != nil || !reflect.DeepEqual(rangeList(got), []string{"192.0.2.0/24^-"}) {
		t.Errorf("{{192.0.2.0/24^+}}^- = %v, %v; want [192.0.2.0/24^-]", rangeList(got), err)
	}
}

// A set reached once plainly and once through an operator contributes both.
func TestSameSetThroughTwoPaths(t *testing.T) {
	src := corpus(t, routeSet("RS-TOP", "RS-X, RS-Y"), routeSet("RS-Y", "RS-X^+"), routeSet("RS-X", "192.0.2.0/24"))
	got, err := (&Expander{Src: src}).ExpandPrefixRanges(context.Background(), mustSet(t, "RS-TOP"))
	if err != nil || !reflect.DeepEqual(rangeList(got), []string{"192.0.2.0/24", "192.0.2.0/24^+"}) {
		t.Errorf("ranges = %v, %v; want [192.0.2.0/24 192.0.2.0/24^+]", rangeList(got), err)
	}
}

func TestCyclesAndOperators(t *testing.T) {
	ctx := context.Background()
	// An operator-free cycle is skipped exactly.
	plain := corpus(t, routeSet("RS-A", "RS-B, 192.0.2.0/24"), routeSet("RS-B", "RS-A, 198.51.100.0/24"))
	if got, err := (&Expander{Src: plain}).ExpandPrefixRanges(ctx, mustSet(t, "RS-A")); err != nil ||
		!reflect.DeepEqual(rangeList(got), []string{"192.0.2.0/24", "198.51.100.0/24"}) {
		t.Errorf("plain cycle = %v, %v", rangeList(got), err)
	}
	// A cycle re-entered under the same operators is also exact.
	same := corpus(t, routeSet("RS-A", "RS-B^+"), routeSet("RS-B", "RS-C"), routeSet("RS-C", "RS-B, 10.0.0.0/30"))
	if got, err := (&Expander{Src: same}).ExpandPrefixRanges(ctx, mustSet(t, "RS-A")); err != nil ||
		!reflect.DeepEqual(rangeList(got), []string{"10.0.0.0/30^+"}) {
		t.Errorf("same-operator cycle = %v, %v; want [10.0.0.0/30^+]", rangeList(got), err)
	}
	// Re-entering an ancestor under different operators cannot be composed
	// without a fixpoint: refuse rather than return an undersized result.
	opCycle := corpus(t, routeSet("RS-A", "RS-B^+, 192.0.2.0/24"), routeSet("RS-B", "RS-A, 198.51.100.0/24"))
	_, err := (&Expander{Src: opCycle}).ExpandPrefixRanges(ctx, mustSet(t, "RS-A"))
	var cyc ErrCyclicOperator
	if !errors.As(err, &cyc) || cyc.Set.Canonical() != "RS-B" || cyc.Member != "RS-A" {
		t.Errorf("operator cycle err = %v (%+v), want ErrCyclicOperator{RS-B, RS-A}", err, cyc)
	}
}

// ---- budgets and limits ----

func TestExpandPrefixesDuplicatesAreFree(t *testing.T) {
	src := corpus(t, routeSet("RS-A", "10.0.0.0/25, 10.0.0.0/25, 10.0.0.0/24^25"))
	got, err := (&Expander{Src: src, MaxPrefixes: 2}).ExpandPrefixes(context.Background(), mustSet(t, "RS-A"))
	if err != nil || got.Len() != 2 {
		t.Errorf("ExpandPrefixes = %v, %v; want the 2 distinct /25s", got.List(), err)
	}
}

func TestMaxPrefixesMaxInt(t *testing.T) {
	src := corpus(t, routeSet("RS-A", "192.0.2.0/24"))
	got, err := (&Expander{Src: src, MaxPrefixes: math.MaxInt}).ExpandPrefixes(context.Background(), mustSet(t, "RS-A"))
	if err != nil || got.Len() != 1 {
		t.Errorf("ExpandPrefixes = %v, %v; want [192.0.2.0/24]", got.List(), err)
	}
}

func TestErrSetTooLargeNamesItsLimit(t *testing.T) {
	ctx := context.Background()
	var wide []string
	var texts []string
	for i := 0; i < 20; i++ {
		wide = append(wide, fmt.Sprintf("AS-C%d", i))
		texts = append(texts, asSet(fmt.Sprintf("AS-C%d", i), fmt.Sprintf("AS%d", i+1)))
	}
	texts = append(texts, asSet("AS-WIDE", wide...), routeSet("RS-BIG", "0.0.0.0/0^+"),
		routeSet("RS-SIX", "10.0.0.0/8, 11.0.0.0/8, 12.0.0.0/8, 13.0.0.0/8, 14.0.0.0/8, 15.0.0.0/8"),
		asSet("AS-A", "AS-B"), asSet("AS-B", "AS-C"), asSet("AS-C", "AS1"))
	src := corpus(t, texts...)
	cases := []struct {
		name  string
		run   func() error
		limit Limit
		word  string
	}{
		{"prefixes", func() error {
			_, err := (&Expander{Src: src, MaxPrefixes: 10}).ExpandPrefixes(ctx, mustSet(t, "RS-BIG"))
			return err
		}, LimitPrefixes, "MaxPrefixes"},
		{"ranges", func() error {
			_, err := (&Expander{Src: src, MaxPrefixes: 5}).ExpandPrefixRanges(ctx, mustSet(t, "RS-SIX"))
			return err
		}, LimitPrefixes, "MaxPrefixes"},
		{"visited", func() error {
			_, err := (&Expander{Src: src, MaxVisited: 5}).ExpandAS(ctx, mustSet(t, "AS-WIDE"))
			return err
		}, LimitVisited, "MaxVisited"},
		{"depth", func() error {
			_, err := (&Expander{Src: src, MaxDepth: 1}).ExpandAS(ctx, mustSet(t, "AS-A"))
			return err
		}, LimitDepth, "MaxDepth"},
	}
	for _, c := range cases {
		err := c.run()
		var tl ErrSetTooLarge
		if !errors.As(err, &tl) || tl.Limit != c.limit || !strings.Contains(err.Error(), c.word) {
			t.Errorf("%s: err = %v, want ErrSetTooLarge naming %s", c.name, err, c.word)
		}
	}
	// Within the limit the same chain expands completely.
	if got, err := (&Expander{Src: src, MaxDepth: 2}).ExpandAS(ctx, mustSet(t, "AS-A")); err != nil ||
		!reflect.DeepEqual(asnList(got), []uint32{1}) {
		t.Errorf("MaxDepth 2 = %v, %v; want [1]", asnList(got), err)
	}
}

// ---- errors and reporting ----

func TestTopLevelNotFound(t *testing.T) {
	e := &Expander{Src: corpus(t, asSet("AS-OTHER", "AS1"))}
	ctx, n := context.Background(), mustSet(t, "AS-MISSING")
	_, err1 := e.ExpandAS(ctx, n)
	_, err2 := e.ExpandPrefixes(ctx, n)
	_, err3 := e.ExpandPrefixRanges(ctx, n)
	for i, err := range []error{err1, err2, err3} {
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("call %d: err = %v, want ErrNotFound", i, err)
		}
	}
}

func TestMissingNestedSetsAreReported(t *testing.T) {
	src := corpus(t, asSet("AS-TOP", "AS1, AS-GONE, as-lost"), "route: 192.0.2.0/24\norigin: AS1\nsource: TEST\n")
	e := &Expander{Src: src}
	ctx, n := context.Background(), mustSet(t, "AS-TOP")
	asns, err := e.ExpandAS(ctx, n)
	want := []string{"AS-GONE", "AS-LOST"}
	if err != nil || !reflect.DeepEqual(asnList(asns), []uint32{1}) || !reflect.DeepEqual(canonList(asns.Missing()), want) {
		t.Errorf("ExpandAS = %v missing %v, %v", asnList(asns), canonList(asns.Missing()), err)
	}
	pfx, _ := e.ExpandPrefixes(ctx, n)
	ranges, _ := e.ExpandPrefixRanges(ctx, n)
	if !reflect.DeepEqual(canonList(pfx.Missing()), want) || !reflect.DeepEqual(canonList(ranges.Missing()), want) {
		t.Errorf("Missing: prefixes %v, ranges %v; want %v", canonList(pfx.Missing()), canonList(ranges.Missing()), want)
	}
}

func canonList(ns []types.SetName) []string {
	var out []string
	for _, n := range ns {
		out = append(out, n.Canonical())
	}
	return out
}

func TestAnySetIsNotExpandable(t *testing.T) {
	src := corpus(t, asSet("AS-X", "AS1, AS-ANY"), routeSet("RS-X", "RS-ANY"))
	ctx := context.Background()
	e := &Expander{Src: src}
	for _, run := range []func() error{
		func() error { _, err := e.ExpandAS(ctx, mustSet(t, "AS-ANY")); return err },
		func() error { _, err := e.ExpandAS(ctx, mustSet(t, "AS-X")); return err },
		func() error { _, err := e.ExpandPrefixes(ctx, mustSet(t, "RS-X")); return err },
	} {
		var anyErr ErrAnySet
		if err := run(); !errors.As(err, &anyErr) {
			t.Errorf("err = %v, want ErrAnySet", err)
		}
	}
}

// RFC 2622 §5.1-5.2: an as-set's indirect members are aut-nums; a route-set's
// are routes. Other claimants are ignored.
func TestIndirectMembershipClassRules(t *testing.T) {
	src := corpus(t,
		"as-set: AS-FOO\nmbrs-by-ref: ANY\nsource: TEST\n",
		"aut-num: AS7\nas-name: SEVEN\nmember-of: AS-FOO\nmnt-by: M\nsource: TEST\n",
		"route: 198.51.100.0/24\norigin: AS7\nsource: TEST\n",
		"route: 203.0.113.0/24\norigin: AS9\nmember-of: AS-FOO\nmnt-by: M\nsource: TEST\n", // not an aut-num
		"route-set: RS-FOO\nmbrs-by-ref: ANY\nsource: TEST\n",
		"route: 192.0.2.0/24\norigin: AS9\nmember-of: RS-FOO\nmnt-by: M\nsource: TEST\n",
		"aut-num: AS8\nas-name: EIGHT\nmember-of: RS-FOO\nmnt-by: M\nsource: TEST\n", // not a route
		"route: 10.0.0.0/8\norigin: AS8\nsource: TEST\n",
	)
	e := &Expander{Src: src}
	ctx := context.Background()
	asPfx, err := e.ExpandPrefixes(ctx, mustSet(t, "AS-FOO"))
	if err != nil || !reflect.DeepEqual(asPfx.List(), []netip.Prefix{netipMust("198.51.100.0/24")}) {
		t.Errorf("AS-FOO prefixes = %v, %v; want only AS7's route", asPfx.List(), err)
	}
	rsPfx, err := e.ExpandPrefixes(ctx, mustSet(t, "RS-FOO"))
	if err != nil || !reflect.DeepEqual(rsPfx.List(), []netip.Prefix{netipMust("192.0.2.0/24")}) {
		t.Errorf("RS-FOO prefixes = %v, %v; want only the claiming route", rsPfx.List(), err)
	}
}

// countingSource counts OriginatedRoutes calls per AS.
type countingSource struct {
	*MemSource
	mu    sync.Mutex
	calls map[types.ASN]int
}

func (c *countingSource) OriginatedRoutes(ctx context.Context, as types.ASN, afi types.AFI) ([]netip.Prefix, error) {
	c.mu.Lock()
	c.calls[as]++
	c.mu.Unlock()
	return c.MemSource.OriginatedRoutes(ctx, as, afi)
}

func TestOriginatedRoutesFetchedOncePerAS(t *testing.T) {
	src := &countingSource{MemSource: corpus(t,
		asSet("AS-TOP", "AS1, AS-B, AS-C"), asSet("AS-B", "AS1"), asSet("AS-C", "AS1, AS2"),
		"route: 192.0.2.0/24\norigin: AS1\nsource: TEST\n",
		"route: 198.51.100.0/24\norigin: AS2\nsource: TEST\n",
	), calls: map[types.ASN]int{}}
	got, err := (&Expander{Src: src}).ExpandPrefixes(context.Background(), mustSet(t, "AS-TOP"))
	if err != nil || got.Len() != 2 {
		t.Fatalf("ExpandPrefixes = %v, %v", got.List(), err)
	}
	if !reflect.DeepEqual(src.calls, map[types.ASN]int{1: 1, 2: 1}) {
		t.Errorf("OriginatedRoutes calls = %v, want once per AS", src.calls)
	}
}

// One Expander serves concurrent expansions (design §13: embeddable in servers).
func TestConcurrentExpansions(t *testing.T) {
	src := corpus(t, routeSet("RS-A", "RS-B^+, AS5"), routeSet("RS-B", "10.0.0.0/30"),
		"route: 192.0.2.0/24\norigin: AS5\nsource: TEST\n")
	e := &Expander{Src: src}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := e.ExpandPrefixRanges(context.Background(), mustSet(t, "RS-A"))
			if err != nil || got.Len() != 2 {
				t.Errorf("concurrent expansion = %v, %v", rangeList(got), err)
			}
		}()
	}
	wg.Wait()
}

var _ = object.MemberAS // keep the object import for helpers shared with other files
