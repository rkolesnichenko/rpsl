package resolve

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/types"
)

// setFetchCounter counts GetSet calls per set reference.
type setFetchCounter struct {
	Source
	mu sync.Mutex
	n  map[string]int
}

func (s *setFetchCounter) GetSet(ctx context.Context, ref types.SetRef) (object.NamedSet, error) {
	s.mu.Lock()
	s.n[ref.String()]++
	s.mu.Unlock()
	return s.Source.GetSet(ctx, ref)
}

func (s *setFetchCounter) count(name string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.n[name]
}

// overCorpus holds AS-A and four more as-sets of two ASNs each: each
// expansion weighs 3, and as many filters naming them weigh 2 or more.
func overCorpus(t *testing.T) *setFetchCounter {
	return &setFetchCounter{Source: corpus(t,
		asSet("AS-A", "AS1", "AS2"), asSet("AS-B", "AS3", "AS4"), asSet("AS-C", "AS5", "AS6"),
		asSet("AS-D", "AS7", "AS8"), asSet("AS-E", "AS9", "AS10"),
		"route: 10.1.0.0/16\norigin: AS1\nsource: TEST\n",
	), n: map[string]int{}}
}

// A layer keeps what it computed after the shared memo evicted it: another
// call's answers push AS-A's expansion out of shared, and the first call
// asks again without a fetch. This is the sweep's case: other workers' lints
// evicted a running lint's IXP filters between its sessions.
func TestFilterMemoOverKeepsEvicted(t *testing.T) {
	src := overCorpus(t)
	shared := NewFilterMemo(12)
	mine := &Expander{Src: src, Memo: NewFilterMemoOver(shared, 12)}
	other := &Expander{Src: src, Memo: NewFilterMemoOver(shared, 12)}
	ref := types.Ref(mustSet(t, "AS-A"))
	want, werr := (&Expander{Src: src}).ExpandAS(context.Background(), ref)
	if _, err := mine.ExpandAS(context.Background(), ref); err != nil { // weight 3
		t.Fatal(err)
	}
	for _, name := range []string{"AS-B", "AS-C", "AS-D", "AS-E"} { // 12 more: AS-A leaves shared
		if _, err := other.ExpandAS(context.Background(), types.Ref(mustSet(t, name))); err != nil {
			t.Fatal(err)
		}
	}
	before, sharedHits := src.count("AS-A"), shared.Stats().Hits
	got, gerr := mine.ExpandAS(context.Background(), ref)
	sameASNs(t, "AS-A again", got, gerr, want, werr)
	if n := src.count("AS-A"); n != before {
		t.Fatalf("AS-A fetched %d times, want %d: the layer did not keep it", n, before)
	}
	if st := shared.Stats(); st.Hits != sharedHits {
		t.Fatalf("shared stats %+v: a hit in the layer touched shared", st)
	}
	// shared really had evicted it: a fresh layer fetches AS-A again.
	if _, err := (&Expander{Src: src, Memo: NewFilterMemoOver(shared, 12)}).ExpandAS(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	if n := src.count("AS-A"); n != before+1 {
		t.Fatalf("AS-A fetched %d times by a fresh layer, want %d: shared still held it, so the test proves nothing", n, before+1)
	}
}

// The same for NormalizeFilter's answers (the filter pool).
func TestFilterMemoOverKeepsEvictedFilter(t *testing.T) {
	src := overCorpus(t)
	shared := NewFilterMemo(12)
	mine := &Expander{Src: src, Memo: NewFilterMemoOver(shared, 12)}
	other := &Expander{Src: src, Memo: NewFilterMemoOver(shared, 12)}
	f := mustFilter(t, "AS-A")
	want, werr := (&Expander{Src: src}).NormalizeFilter(context.Background(), f)
	if _, err := mine.NormalizeFilter(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"{10.1.0.0/16, 10.2.0.0/16}", "{10.3.0.0/16, 10.4.0.0/16}", "{10.5.0.0/16, 10.6.0.0/16}", "{10.7.0.0/16, 10.8.0.0/16}"} {
		if _, err := other.NormalizeFilter(context.Background(), mustFilter(t, s)); err != nil { // weight 3 each
			t.Fatal(err)
		}
	}
	before := src.count("AS-A")
	got, gerr := mine.NormalizeFilter(context.Background(), f)
	sameNormal(t, "AS-A again", got, gerr, want, werr)
	if n := src.count("AS-A"); n != before {
		t.Fatalf("AS-A fetched %d times, want %d: the layer did not keep the filter", n, before)
	}
	// shared really had evicted it: a fresh layer fetches AS-A again.
	if _, err := (&Expander{Src: src, Memo: NewFilterMemoOver(shared, 12)}).NormalizeFilter(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	if n := src.count("AS-A"); n != before+1 {
		t.Fatalf("AS-A fetched %d times by a fresh layer, want %d: shared still held the filter, so the test proves nothing", n, before+1)
	}
}

// Layers share through shared: B is answered with what A computed.
func TestFilterMemoOverShares(t *testing.T) {
	src := overCorpus(t)
	shared := NewFilterMemo(1 << 10)
	a := &Expander{Src: src, Memo: NewFilterMemoOver(shared, 1<<10)}
	bm := NewFilterMemoOver(shared, 1<<10)
	b := &Expander{Src: src, Memo: bm}
	ref := types.Ref(mustSet(t, "AS-A"))
	want, werr := a.ExpandAS(context.Background(), ref)
	got, gerr := b.ExpandAS(context.Background(), ref)
	sameASNs(t, "AS-A through B", got, gerr, want, werr)
	if n := src.count("AS-A"); n != 1 {
		t.Fatalf("AS-A fetched %d times, want once", n)
	}
	if st := bm.Stats(); st.Hits != 1 || st.Misses != 0 || st.Entries != 1 {
		t.Fatalf("B's stats %+v, want one hit, kept", st)
	}
	if st := shared.Stats(); st.Hits != 1 || st.Misses != 1 || st.Entries != 1 {
		t.Fatalf("shared stats %+v, want A's miss and B's hit", st)
	}
}

// A layer stores what shared would store, and nothing else, in both.
func TestFilterMemoOverStoresOnlyWhatSharedWould(t *testing.T) {
	type tc struct {
		name string
		run  func(t *testing.T, layer *FilterMemo) error
		kept int // entries expected in the layer and in shared
	}
	cases := []tc{
		{"cancelled context", func(t *testing.T, layer *FilterMemo) error {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_, err := (&Expander{Src: memoCorpus(t), Memo: layer}).NormalizeFilter(ctx, mustFilter(t, "AS-A"))
			if err == nil {
				return errors.New("a cancelled context normalized AS-A")
			}
			return nil
		}, 0},
		{"Source failure", func(t *testing.T, layer *FilterMemo) error {
			src := &downSource{Source: memoCorpus(t), down: true}
			if _, err := (&Expander{Src: src, Memo: layer}).NormalizeFilter(context.Background(), mustFilter(t, "AS-A")); err == nil {
				return errors.New("a failing Source normalized AS-A")
			}
			return nil
		}, 0},
		{"peer-dependent", func(t *testing.T, layer *FilterMemo) error {
			_, err := (&Expander{Src: memoCorpus(t), Peer: 65002, Memo: layer}).NormalizeFilter(context.Background(), mustFilter(t, "PeerAS"))
			return err
		}, 0},
		{"deterministic error", func(t *testing.T, layer *FilterMemo) error {
			_, err := (&Expander{Src: memoCorpus(t), Memo: layer, MaxConjuncts: 1}).NormalizeFilter(context.Background(), mustFilter(t, "<^AS65001> OR <^AS65002>"))
			var tl *SetTooLargeError
			if !errors.As(err, &tl) {
				return fmt.Errorf("got %v, want a *SetTooLargeError", err)
			}
			return nil
		}, 1},
		{"over a quarter of the bound", func(t *testing.T, layer *FilterMemo) error {
			_, err := (&Expander{Src: memoCorpus(t), Memo: layer}).NormalizeFilter(context.Background(), mustFilter(t, "{10.7.0.0/16, 10.8.0.0/16, 10.9.0.0/16}")) // weight 4
			return err
		}, 0},
		// The same for ExpandAS's answers (the expansion pool).
		{"ExpandAS cancelled context", func(t *testing.T, layer *FilterMemo) error {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if _, err := (&Expander{Src: memoCorpus(t), Memo: layer}).ExpandAS(ctx, types.Ref(mustSet(t, "AS-A"))); err == nil {
				return errors.New("a cancelled context expanded AS-A")
			}
			return nil
		}, 0},
		{"ExpandAS Source failure", func(t *testing.T, layer *FilterMemo) error {
			src := &downSource{Source: memoCorpus(t), down: true}
			if _, err := (&Expander{Src: src, Memo: layer}).ExpandAS(context.Background(), types.Ref(mustSet(t, "AS-A"))); err == nil {
				return errors.New("a failing Source expanded AS-A")
			}
			return nil
		}, 0},
		{"ExpandAS missing set", func(t *testing.T, layer *FilterMemo) error {
			_, err := (&Expander{Src: memoCorpus(t), Memo: layer}).ExpandAS(context.Background(), types.Ref(mustSet(t, "AS-NONE")))
			if !errors.Is(err, ErrNotFound) {
				return fmt.Errorf("got %v, want ErrNotFound", err)
			}
			return nil
		}, 0},
		{"ExpandAS deterministic error", func(t *testing.T, layer *FilterMemo) error {
			src := corpus(t, asSet("AS-TOP", "AS-A"), asSet("AS-A", "AS1"))
			_, err := (&Expander{Src: src, Memo: layer, MaxVisited: 1}).ExpandAS(context.Background(), types.Ref(mustSet(t, "AS-TOP")))
			var tl *SetTooLargeError
			if !errors.As(err, &tl) {
				return fmt.Errorf("got %v, want a *SetTooLargeError", err)
			}
			return nil
		}, 1},
		{"ExpandAS over a quarter of the bound", func(t *testing.T, layer *FilterMemo) error {
			src := corpus(t, asSet("AS-BIG", "AS1", "AS2", "AS3"))
			_, err := (&Expander{Src: src, Memo: layer}).ExpandAS(context.Background(), types.Ref(mustSet(t, "AS-BIG"))) // weight 4
			return err
		}, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			shared := NewFilterMemo(12)
			layer := NewFilterMemoOver(shared, 12)
			if err := c.run(t, layer); err != nil {
				t.Fatal(err)
			}
			if l, s := layer.Stats().Entries, shared.Stats().Entries; l != c.kept || s != c.kept {
				t.Fatalf("layer holds %d, shared %d; want %d in each", l, s, c.kept)
			}
		})
	}
}

// Review focus 1: an answer from shared too heavy for a smaller layer is
// served, not kept, and asking again goes to shared again.
func TestFilterMemoOverSmallerLayer(t *testing.T) {
	src := overCorpus(t)
	shared := NewFilterMemo(1 << 10)
	ref := types.Ref(mustSet(t, "AS-A"))
	want, werr := (&Expander{Src: src, Memo: shared}).ExpandAS(context.Background(), ref) // weight 3, in shared
	layer := NewFilterMemoOver(shared, 8)                                                 // a quarter of 8 is 2: too small for 3
	e := &Expander{Src: src, Memo: layer}
	for i := 0; i < 2; i++ {
		got, gerr := e.ExpandAS(context.Background(), ref)
		sameASNs(t, "AS-A from shared", got, gerr, want, werr)
	}
	if st := layer.Stats(); st.Hits != 2 || st.Entries != 0 {
		t.Fatalf("layer stats %+v, want two hits from shared and nothing kept", st)
	}
	if n := src.count("AS-A"); n != 1 {
		t.Fatalf("AS-A fetched %d times, want once", n)
	}
}

// Review focus 2: with Exclude set, neither the layer nor shared is read or
// written.
func TestFilterMemoOverIgnoredWithExclude(t *testing.T) {
	src := overCorpus(t)
	shared := NewFilterMemo(1 << 10)
	layer := NewFilterMemoOver(shared, 1<<10)
	e := &Expander{Src: src, Memo: layer, Exclude: Exclusion{ASNs: []types.ASN{2}}}
	if _, err := e.ExpandAS(context.Background(), types.Ref(mustSet(t, "AS-A"))); err != nil {
		t.Fatal(err)
	}
	if _, err := e.NormalizeFilter(context.Background(), mustFilter(t, "AS-A")); err != nil {
		t.Fatal(err)
	}
	if l, s := layer.Stats(), shared.Stats(); l != (FilterMemoStats{}) || s != (FilterMemoStats{}) {
		t.Fatalf("layer %+v, shared %+v; want both untouched", l, s)
	}
}

// Review focus 5: a nil shared is a plain FilterMemo.
func TestFilterMemoOverNilShared(t *testing.T) {
	src := overCorpus(t)
	m := NewFilterMemoOver(nil, 1<<10)
	e := &Expander{Src: src, Memo: m}
	ref := types.Ref(mustSet(t, "AS-A"))
	for i := 0; i < 2; i++ {
		if _, err := e.ExpandAS(context.Background(), ref); err != nil {
			t.Fatal(err)
		}
	}
	if st := m.Stats(); st.Hits != 1 || st.Misses != 1 || st.Entries != 1 {
		t.Fatalf("stats %+v, want one miss, one hit, one entry", st)
	}
}

// Many layers over one shared memo too small for them, and one layer used by
// several goroutines: every answer equals a plain Expander's.
func TestFilterMemoOverConcurrent(t *testing.T) {
	src := overCorpus(t)
	shared := NewFilterMemo(12)
	common := NewFilterMemoOver(shared, 12)
	var fs []policy.Filter
	for _, s := range []string{"AS-A", "AS-B OR AS-C", "AS-D", "AS-E AND {10.0.0.0/8^+}", "{10.7.0.0/16, 10.8.0.0/16}"} {
		fs = append(fs, mustFilter(t, s))
	}
	var refs []types.SetRef
	for _, s := range []string{"AS-A", "AS-B", "AS-C", "AS-D", "AS-E"} {
		refs = append(refs, types.Ref(mustSet(t, s)))
	}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			memo := common
			if g%2 == 0 {
				memo = NewFilterMemoOver(shared, 12)
			}
			plain, e := &Expander{Src: src}, &Expander{Src: src, Memo: memo}
			for i := 0; i < 50; i++ {
				f := fs[(g+i)%len(fs)]
				want, werr := plain.NormalizeFilter(context.Background(), f)
				got, gerr := e.NormalizeFilter(context.Background(), f)
				if fmt.Sprint(gerr) != fmt.Sprint(werr) || got.String() != want.String() {
					t.Errorf("%v: memo %q %v, plain %q %v", f, got, gerr, want, werr)
					return
				}
				r := refs[(g+i)%len(refs)]
				wa, waerr := plain.ExpandAS(context.Background(), r)
				ga, gaerr := e.ExpandAS(context.Background(), r)
				if fmt.Sprint(gaerr) != fmt.Sprint(waerr) || ga.String() != wa.String() {
					t.Errorf("%v: memo %v %v, plain %v %v", r, ga, gaerr, wa, waerr)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}
