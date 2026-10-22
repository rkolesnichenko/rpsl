package resolve

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/types"
)

// claimCounter counts MembersByRef calls. MembersByRef on the set named
// failOn fails with errClaims; onClaims, when set, runs before each call.
type claimCounter struct {
	*MemSource
	failOn   string
	failWith error // returned instead of errClaims, when set
	onClaims func()
	mu       sync.Mutex
	calls    int
}

var errClaims = errors.New("claims: MembersByRef failed")

func (c *claimCounter) MembersByRef(ctx context.Context, set object.NamedSet) ([]object.Object, error) {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	if c.onClaims != nil {
		c.onClaims()
	}
	if c.failOn != "" && set.SetName().String() == c.failOn {
		if c.failWith != nil {
			return nil, c.failWith
		}
		return nil, errClaims
	}
	return c.MemSource.MembersByRef(ctx, set)
}

func (c *claimCounter) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// claimsGraph is the F8 probe's graph: AS-X reaches AS-ANY at once and AS-Y,
// AS-Z (both mbrs-by-ref) below it; AS-W reaches the same sets without
// AS-ANY; AS-V reaches AS-ANY on the same level as AS-Y, through AS-U.
func claimsGraph(t *testing.T, failOn string) *claimCounter {
	t.Helper()
	return &claimCounter{failOn: failOn, MemSource: corpus(t,
		asSet("AS-X", "AS-ANY, AS-Y"),
		asSet("AS-W", "AS1, AS-Y"),
		asSet("AS-V", "AS-Y, AS-U"),
		asSet("AS-U", "AS-ANY"),
		"as-set: AS-Y\nmembers: AS2, AS-Z\nmbrs-by-ref: ANY\nsource: TEST\n",
		"as-set: AS-Z\nmembers: AS3\nmbrs-by-ref: MNT-A\nsource: TEST\n",
		"aut-num: AS100\nas-name: HUNDRED\nmember-of: AS-Y\nmnt-by: MNT-A\nsource: TEST\n",
		"aut-num: AS101\nas-name: HUNDRED-ONE\nmember-of: AS-Z\nmnt-by: MNT-A\nsource: TEST\n",
		"mntner: MNT-A\nsource: TEST\n",
	)}
}

// Discovery fetches sets without their claims: an expansion that reaches
// AS-ANY, or one refused at a limit, never calls MembersByRef, so a failing
// MembersByRef cannot fail it.
func TestDiscoverSkipsClaims(t *testing.T) {
	ctx := context.Background()
	for _, top := range []string{"AS-X", "AS-V"} {
		src := claimsGraph(t, "")
		nf, err := (&Expander{Src: src}).NormalizeFilter(ctx, mustFilter(t, "<"+top+">"))
		if err != nil {
			t.Fatalf("<%s>: %v", top, err)
		}
		if s, ok := pathSetOf(t, nf, top); !ok || !s.Any() {
			t.Errorf("<%s>: Sets[%s] = %v (present %v), want Any", top, top, s, ok)
		}
		if n := src.count(); n != 0 {
			t.Errorf("<%s>: %d MembersByRef calls, want 0", top, n)
		}

		src = claimsGraph(t, "")
		var ae *AnySetError
		if _, err := (&Expander{Src: src}).ExpandAS(ctx, types.Ref(mustSet(t, top))); !errors.As(err, &ae) {
			t.Errorf("ExpandAS(%s): err %v, want *AnySetError", top, err)
		}
		if n := src.count(); n != 0 {
			t.Errorf("ExpandAS(%s): %d MembersByRef calls, want 0", top, n)
		}
	}

	// A MembersByRef that fails does not fail an answer that never needed it:
	// AS-Y, an mbrs-by-ref set, is fetched on the level that reaches AS-ANY
	// (through AS-U), in a regexp as in a peering.
	if nf, err := (&Expander{Src: claimsGraph(t, "AS-Y")}).NormalizeFilter(ctx, mustFilter(t, "<AS-V>")); err != nil {
		t.Errorf("<AS-V> with AS-Y's claims failing: %v", err)
	} else if s, ok := pathSetOf(t, nf, "AS-V"); !ok || !s.Any() {
		t.Errorf("<AS-V> with AS-Y's claims failing: Sets[AS-V] = %v (present %v), want Any", s, ok)
	}
	var ae *AnySetError
	if _, err := (&Expander{Src: claimsGraph(t, "AS-Y")}).ExpandAS(ctx, types.Ref(mustSet(t, "AS-V"))); !errors.As(err, &ae) || errors.Is(err, errClaims) {
		t.Errorf("ExpandAS(AS-V) with AS-Y's claims failing: err %v, want *AnySetError", err)
	}

	// Refused at a limit: AS-W → AS-Y → AS-Z, where AS-Z at depth 2 is past
	// MaxDepth 1 after AS-Y, an mbrs-by-ref set, was fetched.
	src := claimsGraph(t, "")
	_, err := (&Expander{Src: src, MaxDepth: 1}).ExpandAS(ctx, types.Ref(mustSet(t, "AS-W")))
	var tl *SetTooLargeError
	if !errors.As(err, &tl) || tl.Limit != LimitDepth {
		t.Errorf("ExpandAS(AS-W) at MaxDepth 1: err %v, want *SetTooLargeError on LimitDepth", err)
	}
	if n := src.count(); n != 0 {
		t.Errorf("ExpandAS(AS-W) at MaxDepth 1: %d MembersByRef calls, want 0", n)
	}
}

// Without AS-ANY the claims are fetched after discovery, and every expansion
// still gets them: a peering's ExpandAS and a regexp's pathSet alike.
func TestClaimsWithoutAnySet(t *testing.T) {
	ctx := context.Background()
	want := []uint32{1, 2, 3, 100, 101}
	got, err := (&Expander{Src: claimsGraph(t, "")}).ExpandAS(ctx, types.Ref(mustSet(t, "AS-W")))
	if err != nil {
		t.Fatalf("ExpandAS(AS-W): %v", err)
	}
	if !slices.Equal(asnList(got), want) {
		t.Errorf("ExpandAS(AS-W) = %v, want %v", asnList(got), want)
	}
	nf, err := (&Expander{Src: claimsGraph(t, "")}).NormalizeFilter(ctx, mustFilter(t, "<AS-W>"))
	if err != nil {
		t.Fatalf("<AS-W>: %v", err)
	}
	s, ok := pathSetOf(t, nf, "AS-W")
	if !ok || s.Any() || !slices.Equal(asnList(s), want) {
		t.Errorf("<AS-W>: Sets[AS-W] = %v (present %v, any %v), want %v", asnList(s), ok, s.Any(), want)
	}

	// A failing MembersByRef fails both, with its own error.
	if _, err := (&Expander{Src: claimsGraph(t, "AS-Z")}).ExpandAS(ctx, types.Ref(mustSet(t, "AS-W"))); !errors.Is(err, errClaims) {
		t.Errorf("ExpandAS(AS-W) with AS-Z's claims failing: err %v, want %v", err, errClaims)
	}
	if _, err := (&Expander{Src: claimsGraph(t, "AS-Z")}).NormalizeFilter(ctx, mustFilter(t, "<AS-W>")); !errors.Is(err, errClaims) {
		t.Errorf("<AS-W> with AS-Z's claims failing: err %v, want %v", err, errClaims)
	}
}

// A context cancelled while the claims are fetched is the answer, never an
// expansion without them. AS-W has one set with claims, so every run here
// fetches them serially whatever Concurrency says;
// TestClaimsPassHonoursCancelWideLevel covers lookups in flight together.
func TestClaimsPassHonoursCancel(t *testing.T) {
	for _, n := range []int{0, 8} {
		ctx, cancel := context.WithCancel(context.Background())
		src := claimsGraph(t, "")
		src.onClaims = cancel
		got, err := (&Expander{Src: src, Concurrency: n}).ExpandAS(ctx, types.Ref(mustSet(t, "AS-W")))
		if !errors.Is(err, context.Canceled) {
			t.Errorf("concurrency %d: ExpandAS(AS-W) = %v, %v; want context.Canceled", n, asnList(got), err)
		}
		cancel()
	}
}

// wideClaimsGraph is AS-TOP with three as-sets that each take claims from
// MNT-A, and one claimant for the first.
func wideClaimsGraph(t *testing.T) *claimCounter {
	t.Helper()
	return &claimCounter{MemSource: corpus(t,
		asSet("AS-TOP", "AS-Y1, AS-Y2, AS-Y3"),
		"as-set: AS-Y1\nmbrs-by-ref: MNT-A\nsource: TEST\n",
		"as-set: AS-Y2\nmbrs-by-ref: MNT-A\nsource: TEST\n",
		"as-set: AS-Y3\nmbrs-by-ref: MNT-A\nsource: TEST\n",
		"aut-num: AS100\nas-name: HUNDRED\nmember-of: AS-Y1\nmnt-by: MNT-A\nsource: TEST\n",
		"mntner: MNT-A\nsource: TEST\n",
	)}
}

// inFlight holds each of src's MembersByRef calls until n are in progress at
// once (or 5s pass, so a serial pass still ends, with a peak of 1), and
// returns the most that were in progress at once. The barrier, not timing,
// makes the calls overlap.
func inFlight(src *claimCounter, n int) (peak func() int) {
	var mu sync.Mutex
	cur, top := 0, 0
	all := make(chan struct{})
	src.onClaims = func() {
		mu.Lock()
		cur++
		top = max(top, cur)
		if cur == n {
			close(all)
		}
		mu.Unlock()
		select {
		case <-all:
		case <-time.After(5 * time.Second):
		}
		mu.Lock()
		cur--
		mu.Unlock()
	}
	return func() int { mu.Lock(); defer mu.Unlock(); return top }
}

// The three claim lookups of one level run together at Concurrency 8, and a
// context cancelled by one of them is the answer. The first half proves the
// second covers the parallel path.
func TestClaimsPassHonoursCancelWideLevel(t *testing.T) {
	ctx := context.Background()
	top := types.Ref(mustSet(t, "AS-TOP"))

	src := wideClaimsGraph(t)
	peak := inFlight(src, 3)
	got, err := (&Expander{Src: src, Concurrency: 8}).ExpandAS(ctx, top)
	if err != nil || !slices.Equal(asnList(got), []uint32{100}) {
		t.Fatalf("ExpandAS(AS-TOP) = %v, %v; want [100]", asnList(got), err)
	}
	if n := src.count(); n != 3 {
		t.Errorf("%d MembersByRef calls, want 3", n)
	}
	if p := peak(); p != 3 {
		t.Fatalf("at most %d MembersByRef calls in flight at Concurrency 8, want 3: the test does not cover the parallel path", p)
	}

	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	src = wideClaimsGraph(t)
	src.onClaims = cancel
	got, err = (&Expander{Src: src, Concurrency: 8}).ExpandAS(cctx, top)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("ExpandAS(AS-TOP) = %v, %v; want context.Canceled", asnList(got), err)
	}
}

// claimsRandomGraph draws six as-sets AS-C0..AS-C5 with AS members, nested
// sets (cycles allowed; AS-C6 is never defined, so some are missing), half of
// them with mbrs-by-ref: MNT-A, and up to two claimant aut-nums for each, each
// claimant with one route.
func claimsRandomGraph(t *testing.T, r *rand.Rand) *MemSource {
	t.Helper()
	var texts []string
	claimant := 1000
	for i := range 6 {
		var members []string
		for range r.IntN(3) {
			members = append(members, fmt.Sprintf("AS%d", 1+r.IntN(20)))
		}
		for range r.IntN(3) {
			members = append(members, fmt.Sprintf("AS-C%d", r.IntN(7)))
		}
		s := fmt.Sprintf("as-set: AS-C%d\n", i)
		if len(members) > 0 {
			s += "members: " + strings.Join(members, ", ") + "\n"
		}
		if r.IntN(2) == 0 {
			s += "mbrs-by-ref: MNT-A\n"
		}
		texts = append(texts, s+"source: TEST\n")
		for range r.IntN(3) {
			claimant++
			texts = append(texts,
				fmt.Sprintf("aut-num: AS%d\nas-name: C%d\nmember-of: AS-C%d\nmnt-by: MNT-A\nsource: TEST\n", claimant, claimant, i),
				fmt.Sprintf("route: 10.%d.%d.0/24\norigin: AS%d\nsource: TEST\n", claimant/256, claimant%256, claimant))
		}
	}
	for as := 1; as <= 20; as++ {
		texts = append(texts, fmt.Sprintf("route: 192.168.%d.0/24\norigin: AS%d\nsource: TEST\n", as, as))
	}
	return corpus(t, append(texts, "mntner: MNT-A\nsource: TEST\n")...)
}

// The claims pass runs a level's fetches together, as discovery does, and
// must not change a result either.
func TestConcurrencyWithClaims(t *testing.T) {
	ctx := context.Background()
	top := types.Ref(mustSet(t, "AS-C0"))
	f := mustFilter(t, "<AS-C0>")
	for seed := uint64(0); seed < 200; seed++ {
		src := claimsRandomGraph(t, rand.New(rand.NewPCG(seed, 0xc1a1)))
		run := func(n int) (string, error) {
			e := &Expander{Src: src, Concurrency: n}
			as, err := e.ExpandAS(ctx, top)
			if err != nil {
				return "", fmt.Errorf("ExpandAS: %w", err)
			}
			pfx, err := e.ExpandPrefixes(ctx, top)
			if err != nil {
				return "", fmt.Errorf("ExpandPrefixes: %w", err)
			}
			nf, err := e.NormalizeFilter(ctx, f)
			if err != nil {
				return "", fmt.Errorf("NormalizeFilter: %w", err)
			}
			return fmt.Sprintf("as=%s missing=%v\npfx=%s missing=%v\nnf=%s",
				as, as.Missing(), pfx, pfx.Missing(), pathSetsText(nf)), nil
		}
		serial, err := run(0)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		for _, n := range []int{2, 8, 64} {
			got, err := run(n)
			if err != nil {
				t.Fatalf("seed %d, concurrency %d: %v", seed, n, err)
			}
			if got != serial {
				t.Fatalf("seed %d: concurrency %d gave\n%s\nserial gave\n%s", seed, n, got, serial)
			}
		}
	}
}

// A Source that answers ErrNotFound from MembersByRef breaks its contract (no
// claimants is an empty result). The error names the set and no longer
// matches ErrNotFound, so a caller never reads the top set as missing.
func TestClaimsNotFoundIsNotAnAnswer(t *testing.T) {
	src := claimsGraph(t, "AS-Y")
	src.failWith = ErrNotFound
	_, err := (&Expander{Src: src}).ExpandAS(context.Background(), types.Ref(mustSet(t, "AS-W")))
	if err == nil {
		t.Fatal("ExpandAS(AS-W) with AS-Y's claims not found: no error")
	}
	if errors.Is(err, ErrNotFound) {
		t.Errorf("err %v matches ErrNotFound", err)
	}
	if !strings.Contains(err.Error(), "AS-Y") {
		t.Errorf("err %q does not name AS-Y", err)
	}
}
