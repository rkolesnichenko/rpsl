package consist

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/types"
)

func keepPolicySource(t *testing.T, n int) resolve.PolicySource {
	t.Helper()
	l := &resolve.DumpLoader{Sources: []string{"RIPE"}, KeepPolicy: true}
	if err := l.Read(strings.NewReader(lintDump(n))); err != nil {
		t.Fatal(err)
	}
	return l.Source()
}

// A bounded LRU still reads AS1 once when its checks run consecutively, as
// rpslcheck orders them; it never holds more than its bound, and an aut-num
// it evicted is read from the Source again.
func TestMemoAutNumsBounded(t *testing.T) {
	src := countingSource{keepPolicySource(t, 5), map[types.ASN]int{}}
	c := &Checker{Eval: peval.Evaluator{Src: src}, Memo: NewMemoWith(MemoOptions{AutNums: 2})}
	for peer := types.ASN(2); peer <= 6; peer++ {
		if _, err := c.Check(context.Background(), Pair{A: 1, B: peer, AF: v4}); err != nil {
			t.Fatal(err)
		}
	}
	if src.n[1] != 1 {
		t.Fatalf("AS1 read %d times over five checks, want 1", src.n[1])
	}
	// Each check reads each side's aut-num twice (peval's Export, then
	// Import): 20 lookups, AS1 and each peer missed once.
	if st := c.Memo.Stats(); st.AutNumHits != 14 || st.AutNumMisses != 6 {
		t.Fatalf("stats %+v, want 14 hits and 6 misses", st)
	}
	if n, m := c.Memo.lru.Len(), len(c.Memo.objects); n > 2 || m > 2 {
		t.Fatalf("the memo holds %d (list) and %d (map) aut-nums, over its bound of 2", n, m)
	}
	// AS3 and AS4 push AS1 out, so checking AS1 again reads it again.
	for _, p := range []Pair{{A: 3, B: 4, AF: v4}, {A: 1, B: 2, AF: v4}} {
		if _, err := c.Check(context.Background(), p); err != nil {
			t.Fatal(err)
		}
	}
	if src.n[1] != 2 {
		t.Fatalf("AS1 read %d times, want 2: once, and again after it was evicted", src.n[1])
	}
}

// flakySource fails AutNum while down.
type flakySource struct {
	resolve.PolicySource
	mu   sync.Mutex
	down bool
}

func (s *flakySource) AutNum(ctx context.Context, as types.ASN, source string) (*object.AutNum, error) {
	s.mu.Lock()
	down := s.down
	s.mu.Unlock()
	if down {
		return nil, errors.New("registry down")
	}
	return s.PolicySource.AutNum(ctx, as, source)
}

// A Source failure is not stored: the next call reads again.
func TestMemoSourceFailureNotStored(t *testing.T) {
	src := &flakySource{PolicySource: keepPolicySource(t, 2), down: true}
	c := &Checker{Eval: peval.Evaluator{Src: src}, Memo: NewMemo()}
	if _, err := c.Check(context.Background(), Pair{A: 1, B: 2, AF: v4}); err == nil {
		t.Fatal("a failing Source gave a report")
	}
	src.mu.Lock()
	src.down = false
	src.mu.Unlock()
	want, _ := (&Checker{Eval: peval.Evaluator{Src: src}}).Check(context.Background(), Pair{A: 1, B: 2, AF: v4})
	got, err := c.Check(context.Background(), Pair{A: 1, B: 2, AF: v4})
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("after recovery: %+v %v, want %+v", got, err, want)
	}
}

// Review focus 2: a cancelled check does not change the next check's answer.
// It cannot tell put's ctx.Err() guard apart: MemSource.AutNum ignores the
// context, so what the cancelled check reads is a true answer either way.
// The guard is defensive.
func TestMemoCheckAfterTimeout(t *testing.T) {
	src := keepPolicySource(t, 3)
	c := &Checker{Eval: peval.Evaluator{Src: src}, Memo: NewMemo()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Its answer does not matter (MemSource.AutNum ignores the context, so
	// it may even succeed); what it leaves in the memo does.
	c.Check(ctx, Pair{A: 1, B: 2, AF: v4})
	want, werr := (&Checker{Eval: peval.Evaluator{Src: src}}).Check(context.Background(), Pair{A: 1, B: 2, AF: v4})
	got, gerr := c.Check(context.Background(), Pair{A: 1, B: 2, AF: v4})
	if werr != nil || gerr != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("after a cancelled check: %+v %v, want %+v %v", got, gerr, want, werr)
	}
}

// Many goroutines through one Memo, against the same checks without it.
func TestMemoConcurrent(t *testing.T) {
	src := keepPolicySource(t, 30)
	plain := &Checker{Eval: peval.Evaluator{Src: src}}
	c := &Checker{Eval: peval.Evaluator{Src: src}, Memo: NewMemo()}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for peer := types.ASN(2); peer < 32; peer++ {
				p := Pair{A: 1, B: peer, AF: v4}
				want, werr := plain.Check(context.Background(), p)
				got, gerr := c.Check(context.Background(), p)
				if werr != nil || gerr != nil || !reflect.DeepEqual(got, want) {
					t.Errorf("%v: %+v %v, want %+v %v", p, got, gerr, want, werr)
					return
				}
			}
			if _, err := c.Lint(context.Background(), types.ASN(2+g)); err != nil {
				t.Error(err)
			}
		}(g)
	}
	wg.Wait()
}
