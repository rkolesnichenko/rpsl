package resolve

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/types"
)

// ---- concurrent discovery ----

// Raising Concurrency must not change a single result. The graphs are the same
// random ones the serial engine is checked against, so this compares the two
// settings over cycles, self-loops and shared sub-sets alike.
func TestConcurrencyDoesNotChangeResults(t *testing.T) {
	for seed := uint64(0); seed < 200; seed++ {
		r := rand.New(rand.NewPCG(seed, 0x5eed))
		g := randomGraph(r, 6)
		src := g.corpus(t, r)
		top := mustSet(t, "AS-S0")
		// Every other seed leaves a random set out, so exclusion is covered too.
		var ex Exclusion
		if seed%2 == 1 {
			ex.Sets = []types.SetName{mustSet(t, fmt.Sprintf("AS-S%d", 1+r.IntN(5)))}
		}
		serial, err := (&Expander{Src: src, Exclude: ex}).ExpandAS(context.Background(), top)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		for _, n := range []int{2, 8, 64} {
			got, err := (&Expander{Src: src, Concurrency: n, Exclude: ex}).ExpandAS(context.Background(), top)
			if err != nil {
				t.Fatalf("seed %d, concurrency %d: %v", seed, n, err)
			}
			if got.String() != serial.String() {
				t.Fatalf("seed %d: concurrency %d gave %v, serial gave %v", seed, n, got, serial)
			}
			if len(got.Missing()) != len(serial.Missing()) {
				t.Fatalf("seed %d: concurrency %d Missing %v, serial %v", seed, n, got.Missing(), serial.Missing())
			}
		}
	}
}

// The same holds for prefix expansion, where the routes of each AS are fetched
// together as well.
func TestConcurrencyPrefixesAndRouters(t *testing.T) {
	src := corpus(t,
		asSet("AS-TOP", "AS1, AS-B, AS-C"), asSet("AS-B", "AS2, AS-C"), asSet("AS-C", "AS3, AS-TOP"),
		"route: 192.0.2.0/24\norigin: AS1\nsource: TEST\n",
		"route: 198.51.100.0/24\norigin: AS2\nsource: TEST\n",
		"route6: 2001:db8::/32\norigin: AS3\nsource: TEST\n",
		rtrSet("RTRS-TOP", "r1.example", "RTRS-B"),
		rtrSet("RTRS-B", "r2.example", "RTRS-TOP"),
	)
	ctx := context.Background()
	serial := &Expander{Src: src}
	parallel := &Expander{Src: src, Concurrency: 8}

	a, err := serial.ExpandPrefixes(ctx, mustSet(t, "AS-TOP"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := parallel.ExpandPrefixes(ctx, mustSet(t, "AS-TOP"))
	if err != nil {
		t.Fatal(err)
	}
	if a.String() != b.String() {
		t.Errorf("prefixes: serial %v, parallel %v", a, b)
	}
	c, err := serial.ExpandRouters(ctx, mustSet(t, "RTRS-TOP"))
	if err != nil {
		t.Fatal(err)
	}
	d, err := parallel.ExpandRouters(ctx, mustSet(t, "RTRS-TOP"))
	if err != nil {
		t.Fatal(err)
	}
	if c.String() != d.String() {
		t.Errorf("routers: serial %v, parallel %v", c, d)
	}
}

// Even in parallel, each AS's routes are fetched once per expansion.
func TestConcurrentRoutesFetchedOncePerAS(t *testing.T) {
	src := &countingSource{MemSource: corpus(t,
		asSet("AS-TOP", "AS1, AS-B, AS-C"), asSet("AS-B", "AS1"), asSet("AS-C", "AS1, AS2"),
		"route: 192.0.2.0/24\norigin: AS1\nsource: TEST\n",
		"route: 198.51.100.0/24\norigin: AS2\nsource: TEST\n",
	), calls: map[types.ASN]int{}}
	if _, err := (&Expander{Src: src, Concurrency: 8}).ExpandPrefixes(context.Background(), mustSet(t, "AS-TOP")); err != nil {
		t.Fatal(err)
	}
	for as, n := range src.calls {
		if n != 1 {
			t.Errorf("AS%d fetched %d times, want 1", as, n)
		}
	}
}

// A Source error still stops the expansion when fetches run in parallel.
func TestConcurrentFetchPropagatesError(t *testing.T) {
	boom := errors.New("backend down")
	src := &failingSource{MemSource: corpus(t,
		asSet("AS-TOP", "AS-B, AS-C"), asSet("AS-B", "AS1"), asSet("AS-C", "AS2")),
		fail: "AS-C", err: boom}
	_, err := (&Expander{Src: src, Concurrency: 8}).ExpandAS(context.Background(), mustSet(t, "AS-TOP"))
	if !errors.Is(err, boom) {
		t.Errorf("err = %v, want %v", err, boom)
	}
}

type failingSource struct {
	*MemSource
	fail string
	err  error
}

func (s *failingSource) GetSet(ctx context.Context, name types.SetName) (object.NamedSet, error) {
	if name.String() == s.fail {
		return nil, s.err
	}
	return s.MemSource.GetSet(ctx, name)
}

// ---- Cache ----

// A cache returns exactly what the underlying Source does, and asks it less.
func TestCache(t *testing.T) {
	inner := &callCounter{MemSource: corpus(t,
		asSet("AS-TOP", "AS1, AS-B"), asSet("AS-B", "AS2"),
		"route: 192.0.2.0/24\norigin: AS1\nsource: TEST\n",
		"route: 198.51.100.0/24\norigin: AS2\nsource: TEST\n",
	)}
	c := NewCache(inner, 0)
	e := &Expander{Src: c}
	ctx := context.Background()
	top := mustSet(t, "AS-TOP")

	first, err := e.ExpandPrefixes(ctx, top)
	if err != nil {
		t.Fatal(err)
	}
	afterFirst := inner.total()
	if afterFirst == 0 {
		t.Fatal("the first expansion asked the Source nothing")
	}
	for i := 0; i < 5; i++ {
		got, err := e.ExpandPrefixes(ctx, top)
		if err != nil {
			t.Fatal(err)
		}
		if got.String() != first.String() {
			t.Fatalf("expansion %d = %v, want %v", i, got, first)
		}
	}
	if n := inner.total(); n != afterFirst {
		t.Errorf("five more expansions cost %d extra Source calls, want 0", n-afterFirst)
	}
	st := c.Stats()
	if st.Hits == 0 || st.Misses == 0 || st.Entries == 0 {
		t.Errorf("Stats = %+v", st)
	}
	// Purging makes the next expansion pay again.
	c.Purge()
	if got := c.Stats().Entries; got != 0 {
		t.Errorf("Entries after Purge = %d", got)
	}
	if _, err := e.ExpandPrefixes(ctx, top); err != nil {
		t.Fatal(err)
	}
	if inner.total() == afterFirst {
		t.Error("Purge did not clear the cache")
	}
}

// A missing set is a real answer and is cached; a transport failure is not, so
// the next caller gets a fresh try.
func TestCacheNegativeAndErrors(t *testing.T) {
	inner := &callCounter{MemSource: corpus(t, asSet("AS-X", "AS1"))}
	c := NewCache(inner, 0)
	ctx := context.Background()
	gone := mustSet(t, "AS-GONE")
	for i := 0; i < 3; i++ {
		if _, err := c.GetSet(ctx, gone); !errors.Is(err, ErrNotFound) {
			t.Fatalf("GetSet err = %v, want ErrNotFound", err)
		}
	}
	if n := inner.sets; n != 1 {
		t.Errorf("a missing set was fetched %d times, want 1 (negative caching)", n)
	}

	boom := errors.New("transport")
	failing := &failingSource{MemSource: corpus(t, asSet("AS-X", "AS1")), fail: "AS-X", err: boom}
	c2 := NewCache(failing, 0)
	for i := 0; i < 2; i++ {
		if _, err := c2.GetSet(ctx, mustSet(t, "AS-X")); !errors.Is(err, boom) {
			t.Fatalf("GetSet err = %v, want %v", err, boom)
		}
	}
	if got := c2.Stats().Entries; got != 0 {
		t.Errorf("a failed lookup was cached: Entries = %d", got)
	}
}

// Entries expire, and the cache is bounded.
func TestCacheTTLAndEviction(t *testing.T) {
	inner := &callCounter{MemSource: corpus(t, asSet("AS-X", "AS1"))}
	c := NewCache(inner, time.Millisecond)
	ctx, name := context.Background(), mustSet(t, "AS-X")
	if _, err := c.GetSet(ctx, name); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * time.Millisecond)
	if _, err := c.GetSet(ctx, name); err != nil {
		t.Fatal(err)
	}
	if inner.sets != 2 {
		t.Errorf("an expired entry was reused: %d fetches", inner.sets)
	}

	big := &callCounter{MemSource: corpus(t, asSet("AS-X", "AS1"))}
	c2 := &Cache{Src: big, MaxEntries: 2, entries: map[cacheKey]*cacheEntry{}}
	for i := 0; i < 10; i++ {
		if _, err := c2.OriginatedRoutes(ctx, types.ASN(i), types.AFIAny); err != nil {
			t.Fatal(err)
		}
	}
	if got := c2.Stats().Entries; got > 2 {
		t.Errorf("Entries = %d, want at most 2", got)
	}
	// A negative cap means no eviction at all.
	c3 := &Cache{Src: big, MaxEntries: -1, entries: map[cacheKey]*cacheEntry{}}
	for i := 0; i < 10; i++ {
		if _, err := c3.OriginatedRoutes(ctx, types.ASN(i), types.AFIAny); err != nil {
			t.Fatal(err)
		}
	}
	if got := c3.Stats().Entries; got != 10 {
		t.Errorf("Entries with no cap = %d, want 10", got)
	}
}

// Concurrent lookups of one key collapse into a single call to the Source.
func TestCacheSingleFlight(t *testing.T) {
	slow := &slowSource{MemSource: corpus(t, asSet("AS-X", "AS1")), delay: 20 * time.Millisecond}
	c := NewCache(slow, 0)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.GetSet(context.Background(), mustSet(t, "AS-X")); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if n := slow.count(); n != 1 {
		t.Errorf("16 concurrent lookups made %d Source calls, want 1", n)
	}
}

// A Cache is safe for concurrent use by several expanders.
func TestCacheConcurrentExpansions(t *testing.T) {
	c := NewCache(corpus(t,
		asSet("AS-TOP", "AS1, AS-B"), asSet("AS-B", "AS2, AS-TOP"),
		"route: 192.0.2.0/24\norigin: AS1\nsource: TEST\n",
		"route: 198.51.100.0/24\norigin: AS2\nsource: TEST\n",
	), 0)
	e := &Expander{Src: c, Concurrency: 4}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := e.ExpandPrefixes(context.Background(), mustSet(t, "AS-TOP"))
			if err != nil {
				t.Error(err)
				return
			}
			if got.Len() != 2 {
				t.Errorf("Len = %d, want 2", got.Len())
			}
		}()
	}
	wg.Wait()
}

type callCounter struct {
	*MemSource
	mu     sync.Mutex
	sets   int
	routes int
	claims int
}

func (c *callCounter) GetSet(ctx context.Context, n types.SetName) (object.NamedSet, error) {
	c.mu.Lock()
	c.sets++
	c.mu.Unlock()
	return c.MemSource.GetSet(ctx, n)
}

func (c *callCounter) OriginatedRoutes(ctx context.Context, as types.ASN, afi types.AFI) ([]netip.Prefix, error) {
	c.mu.Lock()
	c.routes++
	c.mu.Unlock()
	return c.MemSource.OriginatedRoutes(ctx, as, afi)
}

func (c *callCounter) MembersByRef(ctx context.Context, s object.NamedSet) ([]object.Object, error) {
	c.mu.Lock()
	c.claims++
	c.mu.Unlock()
	return c.MemSource.MembersByRef(ctx, s)
}

func (c *callCounter) total() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sets + c.routes + c.claims
}

type slowSource struct {
	*MemSource
	delay time.Duration
	mu    sync.Mutex
	calls int
}

func (s *slowSource) GetSet(ctx context.Context, n types.SetName) (object.NamedSet, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	time.Sleep(s.delay)
	return s.MemSource.GetSet(ctx, n)
}

func (s *slowSource) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// ---- dump loading ----

const dumpText = `as-set:         AS-TOP
members:        AS1, AS-INNER
source:         TEST

as-set:         AS-INNER
members:        AS2
source:         TEST

route:          192.0.2.0/24
origin:         AS1
source:         TEST

route6:         2001:db8::/32
origin:         AS2
source:         TEST

person:         Not Needed
nic-hdl:        NN1-TEST
source:         TEST
`

// A dump loads into a Source that expands exactly as the same objects do when
// handed to NewMemSource directly.
func TestLoadDump(t *testing.T) {
	src, err := LoadDump(strings.NewReader(dumpText))
	if err != nil {
		t.Fatal(err)
	}
	got, err := (&Expander{Src: src}).ExpandPrefixes(context.Background(), mustSet(t, "AS-TOP"))
	if err != nil {
		t.Fatal(err)
	}
	if want := "[192.0.2.0/24 2001:db8::/32]"; got.String() != want {
		t.Errorf("ExpandPrefixes = %v, want %v", got, want)
	}
	as, err := (&Expander{Src: src}).ExpandAS(context.Background(), mustSet(t, "AS-TOP"))
	if err != nil {
		t.Fatal(err)
	}
	if want := "[AS1 AS2]"; as.String() != want {
		t.Errorf("ExpandAS = %v, want %v", as, want)
	}
}

// The loader reports what it saw, and keeps only what the engine can use.
func TestDumpLoaderStats(t *testing.T) {
	var l DumpLoader
	if err := l.Read(strings.NewReader(dumpText)); err != nil {
		t.Fatal(err)
	}
	if l.Stats.Objects != 5 {
		t.Errorf("Objects = %d, want 5", l.Stats.Objects)
	}
	if l.Stats.Kept != 4 {
		t.Errorf("Kept = %d, want 4 (the person is of no use to the engine)", l.Stats.Kept)
	}
	if l.Stats.Diagnosed != 0 {
		t.Errorf("Diagnosed = %d, want 0", l.Stats.Diagnosed)
	}
	// Reading a second dump adds to the same Source.
	if err := l.Read(strings.NewReader("as-set: AS-MORE\nmembers: AS9\nsource: TEST\n")); err != nil {
		t.Fatal(err)
	}
	if l.Stats.Objects != 6 || l.Stats.Kept != 5 {
		t.Errorf("Stats after a second read = %+v", l.Stats)
	}
	as, err := (&Expander{Src: l.Source()}).ExpandAS(context.Background(), mustSet(t, "AS-MORE"))
	if err != nil || as.String() != "[AS9]" {
		t.Errorf("ExpandAS(AS-MORE) = %v, %v", as, err)
	}
}

// A malformed object is counted and reported, and the good ones still load.
func TestDumpLoaderDiagnostics(t *testing.T) {
	const bad = `as-set:         AS-GOOD
members:        AS1
source:         TEST

route:          not-a-prefix
origin:         AS1
source:         TEST
`
	var reported int
	l := DumpLoader{OnDiagnostics: func(o *ast.Object, ds []ast.Diagnostic) {
		if o == nil || len(ds) == 0 {
			t.Error("OnDiagnostics called with nothing to report")
		}
		reported++
	}}
	if err := l.Read(strings.NewReader(bad)); err != nil {
		t.Fatal(err)
	}
	if reported == 0 {
		t.Error("OnDiagnostics was never called")
	}
	if l.Stats.Diagnosed == 0 {
		t.Error("Diagnosed = 0, want the malformed route counted")
	}
	// The good set still loads, and the malformed route is kept: decoding is
	// per-attribute, so its origin: is still usable.
	as, err := (&Expander{Src: l.Source()}).ExpandAS(context.Background(), mustSet(t, "AS-GOOD"))
	if err != nil || as.String() != "[AS1]" {
		t.Errorf("ExpandAS(AS-GOOD) = %v, %v", as, err)
	}
}

// LoadDumps reads several readers into one Source, with source precedence.
func TestLoadDumps(t *testing.T) {
	a := "as-set: AS-DUP\nmembers: AS1\nsource: RIPE\n"
	b := "as-set: AS-DUP\nmembers: AS2\nsource: RADB\n"
	src, err := LoadDumps([]io.Reader{strings.NewReader(b), strings.NewReader(a)}, "RIPE", "RADB")
	if err != nil {
		t.Fatal(err)
	}
	got, err := (&Expander{Src: src}).ExpandAS(context.Background(), mustSet(t, "AS-DUP"))
	if err != nil {
		t.Fatal(err)
	}
	if want := "[AS1]"; got.String() != want {
		t.Errorf("ExpandAS = %v, want %v — RIPE outranks RADB", got, want)
	}
}

// SourceOf views the loaded dumps as one registry's alone: its copy of a set
// wins even where another registry outranks it, a set only elsewhere is not
// found, and so are the other registries' routes and indirect members.
func TestDumpLoaderSourceOf(t *testing.T) {
	l := &DumpLoader{Sources: []string{"RADB", "RIPE"}}
	for _, text := range []string{
		"as-set: AS-DUP\nmembers: AS1\nmbrs-by-ref: ANY\nsource: RIPE\n",
		"as-set: AS-DUP\nmembers: AS2\nsource: RADB\n",
		"as-set: AS-ONLY-RADB\nmembers: AS3\nsource: RADB\n",
		"aut-num: AS7\nas-name: X\nmember-of: AS-DUP\nmnt-by: M\nsource: ripe\n",
		"route: 192.0.2.0/24\norigin: AS1\nsource: RADB\n",
	} {
		if err := l.Read(strings.NewReader(text)); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	all, ripe := l.Source(), l.SourceOf("ripe")
	if got, _ := (&Expander{Src: all}).ExpandAS(ctx, mustSet(t, "AS-DUP")); got.String() != "[AS2]" {
		t.Errorf("all dumps: %v, want RADB's AS-DUP", got)
	}
	if got, _ := (&Expander{Src: ripe}).ExpandAS(ctx, mustSet(t, "AS-DUP")); got.String() != "[AS1 AS7]" {
		t.Errorf("RIPE's alone: %v, want RIPE's AS-DUP and its indirect member", got)
	}
	if _, err := ripe.GetSet(ctx, mustSet(t, "AS-ONLY-RADB")); !errors.Is(err, ErrNotFound) {
		t.Errorf("a RADB set in RIPE's view: %v", err)
	}
	if ps, _ := ripe.OriginatedRoutes(ctx, 1, types.AFIAny); len(ps) != 0 {
		t.Errorf("RADB's route in RIPE's view: %v", ps)
	}
}

// A cache serves indirect members too, which is the third of the Source's
// three methods and the one an mbrs-by-ref set leans on hardest.
func TestCacheMembersByRef(t *testing.T) {
	inner := &callCounter{MemSource: corpus(t,
		"as-set: AS-REF\nmbrs-by-ref: MNT-OK\nsource: TEST\n",
		"aut-num: AS1\nas-name: X\nmember-of: AS-REF\nmnt-by: MNT-OK\nsource: TEST\n",
	)}
	c := NewCache(inner, 0)
	e := &Expander{Src: c}
	ctx, top := context.Background(), mustSet(t, "AS-REF")
	first, err := e.ExpandAS(ctx, top)
	if err != nil {
		t.Fatal(err)
	}
	if first.String() != "[AS1]" {
		t.Fatalf("ExpandAS = %v, want [AS1]", first)
	}
	claims := inner.claims
	for i := 0; i < 3; i++ {
		got, err := e.ExpandAS(ctx, top)
		if err != nil || got.String() != first.String() {
			t.Fatalf("expansion %d = %v, %v", i, got, err)
		}
	}
	if inner.claims != claims {
		t.Errorf("MembersByRef was called %d more times, want 0", inner.claims-claims)
	}
	// A nil set asks nothing.
	if got, err := c.MembersByRef(ctx, nil); err != nil || got != nil {
		t.Errorf("MembersByRef(nil) = %v, %v", got, err)
	}
}

// A truncated dump is an error, not a short read silently treated as the end.
func TestDumpReadError(t *testing.T) {
	boom := errors.New("disk gave up")
	r := io.MultiReader(strings.NewReader("as-set: AS-X\nmembers: AS1\nsource: TEST\n\n"), iotest.ErrReader(boom))
	var l DumpLoader
	err := l.Read(r)
	var de *DumpError
	if !errors.As(err, &de) {
		t.Fatalf("Read err = %v, want *DumpError", err)
	}
	if !strings.Contains(de.Error(), "reading dump") {
		t.Errorf("Error() = %q", de.Error())
	}
	if _, err := LoadDump(io.MultiReader(strings.NewReader("a: 1\n"), iotest.ErrReader(boom))); err == nil {
		t.Error("LoadDump reported no error on a truncated dump")
	}
	if _, err := LoadDumps([]io.Reader{iotest.ErrReader(boom)}); err == nil {
		t.Error("LoadDumps reported no error on a truncated dump")
	}
}

// A filter naming a set the registry does not have expands to nothing and says
// which set was missing, rather than failing the whole evaluation.
func TestEvalFilterMissingSets(t *testing.T) {
	e := &Expander{Src: corpus(t, routeSet("RS-A", "10.0.0.0/8"))}
	got, err := e.EvalFilter(context.Background(), mustFilter(t, "RS-A OR RS-GONE OR FLTR-GONE OR AS-GONE"))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"10.0.0.0/8"}; strings.Join(rangeList(got), " ") != strings.Join(want, " ") {
		t.Errorf("EvalFilter = %v, want %v", rangeList(got), want)
	}
	var names []string
	for _, n := range got.Missing() {
		names = append(names, n.String())
	}
	if want := "AS-GONE FLTR-GONE RS-GONE"; strings.Join(names, " ") != want {
		t.Errorf("Missing = %v, want %v (sorted, each once)", names, want)
	}
	// A name is recorded once however often it appears.
	got, err = e.EvalFilter(context.Background(), mustFilter(t, "RS-GONE OR RS-GONE"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Missing()) != 1 {
		t.Errorf("Missing = %v, want one entry", got.Missing())
	}
}

// The error types say what went wrong.
func TestErrorStrings(t *testing.T) {
	e := &Expander{Src: corpus(t, asSet("AS-X", "AS-ANY"))}
	_, err := e.ExpandAS(context.Background(), mustSet(t, "AS-X"))
	var anyErr *AnySetError
	if !errors.As(err, &anyErr) || !strings.Contains(anyErr.Error(), "AS-ANY") {
		t.Errorf("err = %v, want an AnySetError naming AS-ANY", err)
	}
	ne := &NotEnumerableError{Term: "NOT ANY", Why: "because"}
	if !strings.Contains(ne.Error(), "NOT ANY") || !strings.Contains(ne.Error(), "because") {
		t.Errorf("NotEnumerableError.Error() = %q", ne.Error())
	}
}

// cancelOnceSource blocks its first GetSet until that caller's context ends,
// and answers every later one at once.
type cancelOnceSource struct {
	*MemSource
	started chan struct{}
	once    sync.Once
}

func (s *cancelOnceSource) GetSet(ctx context.Context, n types.SetName) (object.NamedSet, error) {
	first := false
	s.once.Do(func() { first = true })
	if first {
		close(s.started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return s.MemSource.GetSet(ctx, n)
}

// A caller that joins another's lookup is not failed by that caller's
// cancellation: it fetches for itself.
func TestCacheWaiterSurvivesFillerCancel(t *testing.T) {
	src := &cancelOnceSource{MemSource: corpus(t, asSet("AS-X", "AS1")), started: make(chan struct{})}
	c := NewCache(src, 0)
	name := mustSet(t, "AS-X")

	ctxA, cancelA := context.WithCancel(context.Background())
	errA := make(chan error, 1)
	go func() { _, err := c.GetSet(ctxA, name); errA <- err }()
	<-src.started

	errB := make(chan error, 1)
	go func() { _, err := c.GetSet(context.Background(), name); errB <- err }()
	for c.Stats().Hits == 0 { // B has joined A's lookup
		runtime.Gosched()
	}
	cancelA()
	if err := <-errA; !errors.Is(err, context.Canceled) {
		t.Errorf("the cancelled caller got %v, want context.Canceled", err)
	}
	if err := <-errB; err != nil {
		t.Errorf("the caller that joined got %v, want the set", err)
	}
}

// The least recently used entry is the one evicted, however it was last used.
func TestCacheEvictsLeastRecentlyUsed(t *testing.T) {
	inner := &callCounter{MemSource: corpus(t)}
	c := &Cache{Src: inner, MaxEntries: 2, entries: map[cacheKey]*cacheEntry{}}
	ctx := context.Background()
	get := func(as types.ASN) {
		if _, err := c.OriginatedRoutes(ctx, as, types.AFIAny); err != nil {
			t.Fatal(err)
		}
	}
	get(1)
	get(2)
	get(1) // AS1 is now the most recent
	get(3) // evicts AS2
	before := inner.routes
	get(1)
	if inner.routes != before {
		t.Error("AS1, used more recently than AS2, was evicted")
	}
	get(2)
	if inner.routes != before+1 {
		t.Error("AS2 was not evicted")
	}
}

// Each lookup costs the same however many entries the cache holds.
func BenchmarkCacheLRU(b *testing.B) {
	c := NewCache(corpus(&testing.T{}), 0)
	ctx := context.Background()
	for i := 0; i < 50000; i++ {
		_, _ = c.OriginatedRoutes(ctx, types.ASN(i), types.AFIAny)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.OriginatedRoutes(ctx, types.ASN(i%50000), types.AFIAny)
	}
}
