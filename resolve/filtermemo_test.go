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

func memoCorpus(t *testing.T) *MemSource {
	return corpus(t,
		"as-set: AS-A\nmembers: AS65001\nsource: TEST\n",
		"route: 10.1.0.0/16\norigin: AS65001\nsource: TEST\n",
		"route: 10.2.0.0/16\norigin: AS65002\nsource: TEST\n",
		"route: 10.3.0.0/16\norigin: AS65003\nsource: TEST\n",
		"filter-set: FLTR-INNER\nfilter: PeerAS OR AS-A\nsource: TEST\n",
		"filter-set: FLTR-OUTER\nfilter: FLTR-INNER AND {10.0.0.0/8^+}\nsource: TEST\n",
	)
}

// sameNormal fails unless two answers are the same normal form, missing
// sets and error.
func sameNormal(t *testing.T, label string, got NormalFilter, gerr error, want NormalFilter, werr error) {
	t.Helper()
	if fmt.Sprint(gerr) != fmt.Sprint(werr) || got.String() != want.String() || fmt.Sprint(got.Missing()) != fmt.Sprint(want.Missing()) {
		t.Fatalf("%s: memo %q %v %v, plain %q %v %v", label, got, got.Missing(), gerr, want, want.Missing(), werr)
	}
}

func TestFilterMemoHit(t *testing.T) {
	src, memo := memoCorpus(t), NewFilterMemo(1<<10)
	e := &Expander{Src: src, Memo: memo}
	f := mustFilter(t, "AS-A")
	first, err1 := e.NormalizeFilter(context.Background(), f)
	again, err2 := e.NormalizeFilter(context.Background(), f)
	sameNormal(t, "AS-A", again, err2, first, err1)
	if st := memo.Stats(); st.Hits != 1 || st.Misses != 1 || st.Entries != 1 || st.Held != 2 {
		t.Fatalf("stats %+v, want 1 hit, 1 miss, 1 entry holding 2", st)
	}
}

// Review focus 1: a PeerAS two filter-sets deep is never shared between peers.
func TestFilterMemoNestedPeer(t *testing.T) {
	src, memo := memoCorpus(t), NewFilterMemo(1<<10)
	f := mustFilter(t, "FLTR-OUTER")
	for _, peer := range []types.ASN{65002, 65003, 65002, 0} {
		plain := &Expander{Src: src, Peer: peer}
		withMemo := &Expander{Src: src, Peer: peer, Memo: memo}
		want, werr := plain.NormalizeFilter(context.Background(), f)
		got, gerr := withMemo.NormalizeFilter(context.Background(), f)
		sameNormal(t, fmt.Sprintf("FLTR-OUTER peer %d", peer), got, gerr, want, werr)
	}
	if st := memo.Stats(); st.Hits != 0 || st.Entries != 0 || st.PeerDependent != 4 {
		t.Fatalf("stats %+v, want nothing stored and 4 peer-dependent answers", st)
	}
}

// Review focus 3: one text under two families is two answers.
func TestFilterMemoKeyedByAFI(t *testing.T) {
	src, memo := memoCorpus(t), NewFilterMemo(1<<10)
	f := mustFilter(t, "AS-A")
	for _, afi := range []types.AFI{types.AFIv4, types.AFIv6, types.AFIv4} {
		plain := &Expander{Src: src, AFI: afi}
		withMemo := &Expander{Src: src, AFI: afi, Memo: memo}
		want, werr := plain.NormalizeFilter(context.Background(), f)
		got, gerr := withMemo.NormalizeFilter(context.Background(), f)
		sameNormal(t, fmt.Sprintf("AS-A %v", afi), got, gerr, want, werr)
	}
	if st := memo.Stats(); st.Entries != 2 || st.Hits != 1 {
		t.Fatalf("stats %+v, want 2 entries and 1 hit", st)
	}
}

// Review focus 4: an Expander with Exclude neither reads nor fills the memo.
func TestFilterMemoIgnoredWithExclude(t *testing.T) {
	src, memo := memoCorpus(t), NewFilterMemo(1<<10)
	f := mustFilter(t, "AS-A")
	full := &Expander{Src: src, Memo: memo}
	if _, err := full.NormalizeFilter(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	ex := &Expander{Src: src, Memo: memo, Exclude: Exclusion{ASNs: []types.ASN{65001}}}
	want, werr := (&Expander{Src: src, Exclude: ex.Exclude}).NormalizeFilter(context.Background(), f)
	got, gerr := ex.NormalizeFilter(context.Background(), f)
	sameNormal(t, "AS-A excluding AS65001", got, gerr, want, werr)
	if st := memo.Stats(); st.Hits != 0 || st.Misses != 1 {
		t.Fatalf("stats %+v: the Exclude call touched the memo", st)
	}
}

// Review focus 2: a context error is never stored.
func TestFilterMemoContextNotStored(t *testing.T) {
	src, memo := memoCorpus(t), NewFilterMemo(1<<10)
	e := &Expander{Src: src, Memo: memo}
	f := mustFilter(t, "AS-A")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.NormalizeFilter(ctx, f); err == nil {
		t.Fatal("a cancelled context normalized AS-A")
	}
	got, err := e.NormalizeFilter(context.Background(), f)
	if err != nil || got.String() != "{10.1.0.0/16}" {
		t.Fatalf("after a cancelled call: %q %v", got, err)
	}
}

// downSource fails every GetSet while down.
type downSource struct {
	Source
	mu   sync.Mutex
	down bool
}

func (s *downSource) GetSet(ctx context.Context, ref types.SetRef) (object.NamedSet, error) {
	s.mu.Lock()
	down := s.down
	s.mu.Unlock()
	if down {
		return nil, errors.New("registry down")
	}
	return s.Source.GetSet(ctx, ref)
}

func TestFilterMemoSourceFailureNotStored(t *testing.T) {
	src := &downSource{Source: memoCorpus(t), down: true}
	memo := NewFilterMemo(1 << 10)
	e := &Expander{Src: src, Memo: memo}
	f := mustFilter(t, "AS-A")
	if _, err := e.NormalizeFilter(context.Background(), f); err == nil {
		t.Fatal("a failing Source normalized AS-A")
	}
	src.mu.Lock()
	src.down = false
	src.mu.Unlock()
	if got, err := e.NormalizeFilter(context.Background(), f); err != nil || got.String() != "{10.1.0.0/16}" {
		t.Fatalf("after the Source recovered: %q %v", got, err)
	}
}

// A deterministic error is stored: two regexps OR'd need two conjuncts,
// over MaxConjuncts 1 every time.
func TestFilterMemoStoresDeterministicError(t *testing.T) {
	src, memo := memoCorpus(t), NewFilterMemo(1<<10)
	e := &Expander{Src: src, Memo: memo, MaxConjuncts: 1}
	f := mustFilter(t, "<^AS65001> OR <^AS65002>")
	_, err1 := e.NormalizeFilter(context.Background(), f)
	_, err2 := e.NormalizeFilter(context.Background(), f)
	var tl *SetTooLargeError
	if !errors.As(err1, &tl) || fmt.Sprint(err1) != fmt.Sprint(err2) {
		t.Fatalf("%v, then %v; want the same *SetTooLargeError twice", err1, err2)
	}
	if st := memo.Stats(); st.Hits != 1 {
		t.Fatalf("stats %+v, want the second call answered from the memo", st)
	}
}

// Eviction keeps Held within the bound; an answer over a quarter of it is
// computed and not stored; answers stay equal throughout.
func TestFilterMemoBounded(t *testing.T) {
	src, memo := memoCorpus(t), NewFilterMemo(12)
	plain := &Expander{Src: src}
	withMemo := &Expander{Src: src, Memo: memo}
	texts := []string{"{10.0.0.0/8}", "{10.1.0.0/16}", "{10.2.0.0/16}", "{10.3.0.0/16}", "{10.4.0.0/16}",
		"{10.5.0.0/16}", "{10.6.0.0/16}", "{10.7.0.0/16, 10.8.0.0/16, 10.9.0.0/16}"}
	for round := 0; round < 2; round++ {
		for _, s := range texts {
			f := mustFilter(t, s)
			want, werr := plain.NormalizeFilter(context.Background(), f)
			got, gerr := withMemo.NormalizeFilter(context.Background(), f)
			sameNormal(t, s, got, gerr, want, werr)
			if st := memo.Stats(); st.Held > 12 {
				t.Fatalf("%s: held %d ranges, over 12", s, st.Held)
			}
		}
	}
	if st := memo.Stats(); st.Entries == 0 || st.Entries > 6 {
		t.Fatalf("stats %+v, want between 1 and 6 entries of weight 2", st)
	}
}

func TestFilterMemoConcurrent(t *testing.T) {
	src, memo := memoCorpus(t), NewFilterMemo(1<<10)
	var fs []policy.Filter
	for _, s := range []string{"AS-A", "FLTR-OUTER", "PeerAS", "{10.0.0.0/8^+}", "AS-A OR AS65002"} {
		fs = append(fs, mustFilter(t, s)) // here: t.Fatalf may not run in another goroutine
	}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				f := fs[(g+i)%len(fs)]
				peer := types.ASN(65002 + i%2)
				want, werr := (&Expander{Src: src, Peer: peer}).NormalizeFilter(context.Background(), f)
				got, gerr := (&Expander{Src: src, Peer: peer, Memo: memo}).NormalizeFilter(context.Background(), f)
				if fmt.Sprint(gerr) != fmt.Sprint(werr) || got.String() != want.String() {
					t.Errorf("%v peer %d: memo %q %v, plain %q %v", f, peer, got, gerr, want, werr)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}
