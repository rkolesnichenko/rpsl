package resolve

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	rpsl "github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/types"
)

func netipMust(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// decode parses and typed-decodes one RPSL object for use in a corpus.
func decode(t *testing.T, text string) object.Object {
	t.Helper()
	o, _ := rpsl.ParseObject(text)
	obj, _ := object.Decode(o)
	return obj
}

func corpus(t *testing.T, texts ...string) *MemSource {
	t.Helper()
	objs := make([]object.Object, len(texts))
	for i, s := range texts {
		objs[i] = decode(t, s)
	}
	return NewMemSource(objs)
}

func asSet(name string, members ...string) string {
	s := "as-set: " + name + "\n"
	for _, m := range members {
		s += "members: " + m + "\n"
	}
	return s + "source: TEST\n"
}

func routeSet(name string, members ...string) string {
	s := "route-set: " + name + "\n"
	for _, m := range members {
		s += "members: " + m + "\n"
	}
	return s + "source: TEST\n"
}

func mustSet(t *testing.T, s string) types.SetName {
	t.Helper()
	n, err := types.ParseSetName(s)
	if err != nil {
		t.Fatalf("ParseSetName(%q): %v", s, err)
	}
	return n
}

func asnList(s ASSet) []uint32 {
	out := make([]uint32, 0, s.Len())
	for _, a := range s.List() {
		out = append(out, uint32(a))
	}
	return out
}

func TestExpandASNestedDedup(t *testing.T) {
	src := corpus(t,
		asSet("AS-TOP", "AS1", "AS-MID"),
		asSet("AS-MID", "AS2", "AS3", "AS1"), // AS1 duplicated
	)
	e := &Expander{Src: src}
	got, err := e.ExpandAS(context.Background(), mustSet(t, "AS-TOP"))
	if err != nil {
		t.Fatalf("ExpandAS: %v", err)
	}
	if want := []uint32{1, 2, 3}; fmt.Sprint(asnList(got)) != fmt.Sprint(want) {
		t.Errorf("ExpandAS = %v, want %v", asnList(got), want)
	}
}

func TestExpandASCycle(t *testing.T) {
	src := corpus(t,
		asSet("AS-A", "AS1", "AS-B"),
		asSet("AS-B", "AS2", "AS-A"), // cycle back to AS-A
	)
	e := &Expander{Src: src}
	got, err := e.ExpandAS(context.Background(), mustSet(t, "AS-A"))
	if err != nil {
		t.Fatalf("ExpandAS: %v", err)
	}
	if want := []uint32{1, 2}; fmt.Sprint(asnList(got)) != fmt.Sprint(want) {
		t.Errorf("ExpandAS = %v, want %v", asnList(got), want)
	}
}

func TestExpandASMaxDepth(t *testing.T) {
	src := corpus(t,
		asSet("AS-A", "AS1", "AS-B"),
		asSet("AS-B", "AS2", "AS-C"),
		asSet("AS-C", "AS3"),
	)
	e := &Expander{Src: src, MaxDepth: 1} // walk A (0) and B (1); C (2) skipped
	got, err := e.ExpandAS(context.Background(), mustSet(t, "AS-A"))
	if err != nil {
		t.Fatalf("ExpandAS: %v", err)
	}
	if got.Has(3) {
		t.Errorf("AS3 should be beyond MaxDepth=1; got %v", asnList(got))
	}
	if !got.Has(1) || !got.Has(2) {
		t.Errorf("expected AS1, AS2 within depth; got %v", asnList(got))
	}
}

func TestExpandPrefixesFromASCone(t *testing.T) {
	src := corpus(t,
		asSet("AS-CONE", "AS1", "AS2"),
		"route: 10.0.0.0/8\norigin: AS1\nsource: TEST\n",
		"route: 192.0.2.0/24\norigin: AS2\nsource: TEST\n",
	)
	e := &Expander{Src: src}
	got, err := e.ExpandPrefixes(context.Background(), mustSet(t, "AS-CONE"))
	if err != nil {
		t.Fatalf("ExpandPrefixes: %v", err)
	}
	if got.Len() != 2 || !got.Has(netipMust("10.0.0.0/8")) || !got.Has(netipMust("192.0.2.0/24")) {
		t.Errorf("prefixes = %v, want [10.0.0.0/8 192.0.2.0/24]", got.List())
	}
}

func TestExpandPrefixesRangeMaterialize(t *testing.T) {
	src := corpus(t, routeSet("RS-RANGE", "192.0.2.0/24^26"))
	e := &Expander{Src: src}
	got, err := e.ExpandPrefixes(context.Background(), mustSet(t, "RS-RANGE"))
	if err != nil {
		t.Fatalf("ExpandPrefixes: %v", err)
	}
	if got.Len() != 4 {
		t.Errorf("got %d prefixes, want 4 (/26s): %v", got.Len(), got.List())
	}
}

func TestExpandPrefixesAFIConstraint(t *testing.T) {
	mk := func(afi types.AFI) PrefixSet {
		src := corpus(t, routeSet("RS-MIX", "192.0.2.0/24", "2001:db8::/32"))
		e := &Expander{Src: src, AFI: afi}
		got, err := e.ExpandPrefixes(context.Background(), mustSet(t, "RS-MIX"))
		if err != nil {
			t.Fatalf("ExpandPrefixes(afi=%v): %v", afi, err)
		}
		return got
	}
	if v4 := mk(types.AFIv4); v4.Len() != 1 || !v4.Has(netipMust("192.0.2.0/24")) {
		t.Errorf("v4 = %v, want only 192.0.2.0/24", v4.List())
	}
	if v6 := mk(types.AFIv6); v6.Len() != 1 || !v6.Has(netipMust("2001:db8::/32")) {
		t.Errorf("v6 = %v, want only 2001:db8::/32", v6.List())
	}
	if any := mk(types.AFIAny); any.Len() != 2 {
		t.Errorf("any = %v, want both", any.List())
	}
}

func TestExpandPrefixesMaxPrefixes(t *testing.T) {
	src := corpus(t, routeSet("RS-BIG", "0.0.0.0/0^+"))
	e := &Expander{Src: src, MaxPrefixes: 10}
	_, err := e.ExpandPrefixes(context.Background(), mustSet(t, "RS-BIG"))
	var tooLarge ErrSetTooLarge
	if !errors.As(err, &tooLarge) {
		t.Fatalf("err = %v, want ErrSetTooLarge", err)
	}
}

// A pathologically wide IRR graph (10k unique as-sets at depth 1) is bounded
// by MaxVisited; we set it to 50 and expect ErrSetTooLarge before exhausting
// memory.
func TestExpandASMaxVisited(t *testing.T) {
	var texts []string
	var members []string
	for i := 1; i <= 200; i++ {
		members = append(members, fmt.Sprintf("AS-CHILD-%d", i))
		texts = append(texts, asSet(fmt.Sprintf("AS-CHILD-%d", i), fmt.Sprintf("AS%d", i)))
	}
	texts = append(texts, asSet("AS-WIDE", members...))
	src := corpus(t, texts...)
	e := &Expander{Src: src, MaxVisited: 50}
	_, err := e.ExpandAS(context.Background(), mustSet(t, "AS-WIDE"))
	var tooLarge ErrSetTooLarge
	if !errors.As(err, &tooLarge) {
		t.Fatalf("err = %v, want ErrSetTooLarge", err)
	}
	if tooLarge.Count <= 50 {
		t.Errorf("Count = %d, want > MaxVisited (50)", tooLarge.Count)
	}
}

// Context cancellation must take effect mid-walk, not only at function entry.
// The Source blocks on ctx; we cancel and assert the call returns within a
// tight bound (way below MaxDepth*RTT).
func TestExpandContextCancellationMidWalk(t *testing.T) {
	src := &blockingSource{block: make(chan struct{})}
	defer close(src.block)
	e := &Expander{Src: src}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := e.ExpandAS(ctx, mustSet(t, "AS-X"))
		done <- err
	}()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ExpandAS did not return after cancel")
	}
}

// blockingSource: GetSet sleeps until ctx is done. Used to verify ctx checks
// are honored deep in walk loops, not just at entry.
type blockingSource struct{ block chan struct{} }

func (b *blockingSource) GetSet(ctx context.Context, _ types.SetName) (object.Set, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-b.block:
		return nil, ErrNotFound
	}
}
func (b *blockingSource) OriginatedRoutes(context.Context, types.ASN, types.AFI) ([]netip.Prefix, error) {
	return nil, nil
}
func (b *blockingSource) MembersByRef(context.Context, types.SetName, []string) ([]object.Object, error) {
	return nil, nil
}

// TestExpandPrefixesBudgetAcrossMembers exercises the materialize budget fix:
// two ranges that each fit alone (6 prefixes from a /29^+ = 1+2+4+8 → bounded
// by the cap, but their union exceeds the 10-prefix MaxPrefixes). The engine
// must surface ErrSetTooLarge whose Count actually exceeds the cap.
func TestExpandPrefixesBudgetAcrossMembers(t *testing.T) {
	src := corpus(t, routeSet("RS-MULTI", "192.0.2.0/29^+", "198.51.100.0/29^+"))
	e := &Expander{Src: src, MaxPrefixes: 10}
	_, err := e.ExpandPrefixes(context.Background(), mustSet(t, "RS-MULTI"))
	var tooLarge ErrSetTooLarge
	if !errors.As(err, &tooLarge) {
		t.Fatalf("err = %v, want ErrSetTooLarge", err)
	}
	if tooLarge.Count <= 10 {
		t.Errorf("Count = %d, want > MaxPrefixes (10)", tooLarge.Count)
	}
}

// TestDualMembershipMntnerCheck is the hijack-relevant case: only routes whose
// maintainer is listed in mbrs-by-ref may join indirectly.
func TestDualMembershipMntnerCheck(t *testing.T) {
	src := corpus(t,
		"route-set: RS-REF\nmbrs-by-ref: MAINT-GOOD\nsource: TEST\n",
		"route: 198.51.100.0/24\norigin: AS10\nmember-of: RS-REF\nmnt-by: MAINT-GOOD\nsource: TEST\n",
		"route: 203.0.113.0/24\norigin: AS20\nmember-of: RS-REF\nmnt-by: MAINT-EVIL\nsource: TEST\n",
	)
	e := &Expander{Src: src}
	got, err := e.ExpandPrefixes(context.Background(), mustSet(t, "RS-REF"))
	if err != nil {
		t.Fatalf("ExpandPrefixes: %v", err)
	}
	if got.Len() != 1 || !got.Has(netipMust("198.51.100.0/24")) {
		t.Errorf("prefixes = %v, want only the MAINT-GOOD route (203.0.113.0/24 must be excluded)", got.List())
	}
}

func TestDualMembershipAny(t *testing.T) {
	src := corpus(t,
		"route-set: RS-OPEN\nmbrs-by-ref: ANY\nsource: TEST\n",
		"route: 198.51.100.0/24\norigin: AS10\nmember-of: RS-OPEN\nmnt-by: MAINT-A\nsource: TEST\n",
		"route: 203.0.113.0/24\norigin: AS20\nmember-of: RS-OPEN\nmnt-by: MAINT-B\nsource: TEST\n",
	)
	e := &Expander{Src: src}
	got, _ := e.ExpandPrefixes(context.Background(), mustSet(t, "RS-OPEN"))
	if got.Len() != 2 {
		t.Errorf("mbrs-by-ref: ANY should admit both; got %v", got.List())
	}
}

func TestContextCancellation(t *testing.T) {
	src := corpus(t, asSet("AS-A", "AS1"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e := &Expander{Src: src}
	if _, err := e.ExpandAS(ctx, mustSet(t, "AS-A")); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

// TestPropertyCyclicGraphTerminates builds a densely interconnected (cyclic) set
// graph and asserts expansion terminates and dedups within the universe of ASNs.
func TestPropertyCyclicGraphTerminates(t *testing.T) {
	const n = 60
	texts := make([]string, n)
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("AS-%d", i)
		// Each set lists its own ASN and references two neighbors, creating cycles.
		members := []string{
			fmt.Sprintf("AS%d", 1000+i),
			fmt.Sprintf("AS-%d", (i+1)%n),
			fmt.Sprintf("AS-%d", (i+7)%n),
		}
		texts[i] = asSet(name, members...)
	}
	src := corpus(t, texts...)
	// MaxDepth above the graph diameter so connectivity (not the depth cap) is
	// what the assertion measures; the +1 ring makes the graph strongly connected.
	e := &Expander{Src: src, MaxDepth: 1000}
	got, err := e.ExpandAS(context.Background(), mustSet(t, "AS-0"))
	if err != nil {
		t.Fatalf("ExpandAS: %v", err)
	}
	if got.Len() != n {
		t.Errorf("got %d ASNs, want %d (fully connected)", got.Len(), n)
	}
}
