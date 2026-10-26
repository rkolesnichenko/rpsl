package resolve

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/types"
)

// batchSrc counts the calls of one Source method (GetSet and MembersByRef
// only for sets named AS-S…, OriginatedRoutes for every AS) and runs onCall
// with each counted call's number, from 1. The call numbered failAt fails
// with failWith. MemSource ignores the context, so every call that starts is
// counted.
type batchSrc struct {
	*MemSource
	method   string
	onCall   func(k int)
	failAt   int
	failWith error
	mu       sync.Mutex
	calls    int
}

func (b *batchSrc) counted(method, name string) error {
	if method != b.method || (method != "OriginatedRoutes" && !strings.HasPrefix(name, "AS-S")) {
		return nil
	}
	b.mu.Lock()
	b.calls++
	k := b.calls
	b.mu.Unlock()
	if b.onCall != nil {
		b.onCall(k)
	}
	if k == b.failAt {
		return b.failWith
	}
	return nil
}

func (b *batchSrc) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls
}

func (b *batchSrc) GetSet(ctx context.Context, ref types.SetRef) (object.NamedSet, error) {
	if err := b.counted("GetSet", ref.Name().String()); err != nil {
		return nil, err
	}
	return b.MemSource.GetSet(ctx, ref)
}

func (b *batchSrc) MembersByRef(ctx context.Context, set object.NamedSet) ([]object.Object, error) {
	if err := b.counted("MembersByRef", set.SetName().String()); err != nil {
		return nil, err
	}
	return b.MemSource.MembersByRef(ctx, set)
}

func (b *batchSrc) OriginatedRoutes(ctx context.Context, as types.ASN, afi types.AFI) ([]netip.Prefix, error) {
	if err := b.counted("OriginatedRoutes", as.String()); err != nil {
		return nil, err
	}
	return b.MemSource.OriginatedRoutes(ctx, as, afi)
}

// cancelAt makes src's n-th counted call cancel and then release the calls
// before it, which wait for that (or 5s, so a broken each fails its count
// instead of hanging). Calls after the n-th pass straight through. With n
// calls in flight when it cancels, nothing is spawned but not yet started.
func cancelAt(src *batchSrc, n int, cancel func()) {
	release := make(chan struct{})
	src.onCall = func(k int) {
		switch {
		case k == n:
			cancel()
			close(release)
		case k < n:
			select {
			case <-release:
			case <-time.After(5 * time.Second):
			}
		}
	}
}

// batchGraph is a batch of 40 for one Source method: "sets" is AS-TOP over
// AS-S0..AS-S39, "claims" the same with a mbrs-by-ref: on each AS-Si, and
// "routes" AS-FLAT over AS100..AS139. It returns the source and the set to
// expand.
func batchGraph(t *testing.T, kind string) (*batchSrc, types.SetRef) {
	t.Helper()
	var texts, sets, ases []string
	for i := range 40 {
		sets = append(sets, fmt.Sprintf("AS-S%d", i))
		ases = append(ases, fmt.Sprintf("AS%d", 100+i))
		s := fmt.Sprintf("as-set: AS-S%d\nmembers: AS%d\n", i, 100+i)
		if kind == "claims" {
			s += "mbrs-by-ref: MNT-A\n"
		}
		texts = append(texts, s+"source: TEST\n")
	}
	texts = append(texts,
		asSet("AS-TOP", strings.Join(sets, ", ")),
		asSet("AS-FLAT", strings.Join(ases, ", ")),
		"mntner: MNT-A\nsource: TEST\n")
	method, top := map[string]string{"sets": "GetSet", "claims": "MembersByRef", "routes": "OriginatedRoutes"}[kind], "AS-TOP"
	if kind == "routes" {
		top = "AS-FLAT"
	}
	return &batchSrc{MemSource: corpus(t, texts...), method: method}, types.Ref(mustSet(t, top))
}

// Once the context is cancelled, a batch of a level's sets, claims or routes
// starts no further call: at Concurrency 1 the cancelling call is the last,
// and at Concurrency 4, cancelled while 4 are in flight, those 4 are all.
func TestEachStopsAtCancel(t *testing.T) {
	for _, kind := range []string{"sets", "claims", "routes"} {
		for _, c := range []struct{ conc, n int }{{1, 1}, {4, 4}} {
			ctx, cancel := context.WithCancel(context.Background())
			src, top := batchGraph(t, kind)
			cancelAt(src, c.n, cancel)
			e := &Expander{Src: src, Concurrency: c.conc}
			var err error
			if kind == "routes" {
				_, err = e.ExpandPrefixes(ctx, top)
			} else {
				_, err = e.ExpandAS(ctx, top)
			}
			cancel()
			if !errors.Is(err, context.Canceled) {
				t.Errorf("%s at Concurrency %d: err %v, want context.Canceled", kind, c.conc, err)
			}
			if got := src.count(); got != c.n {
				t.Errorf("%s at Concurrency %d: %d of 40 calls, want %d", kind, c.conc, got, c.n)
			}
		}
	}
}

// fetchRoutes answers a cancelled batch with the context's error, never with
// the routes it fetched before (a skipped AS has none) nor with a started
// call's own error. Through ExpandPrefixes the evaluator's walk would notice
// the cancellation anyway, so this calls fetchRoutes itself.
func TestFetchRoutesReturnsCancel(t *testing.T) {
	errRoutes := errors.New("routes failed")
	for _, tc := range []struct {
		name     string
		failWith error
		pre      bool // cancelled before the batch
		maxCalls int
		reps     int // how many times fetchRoutes runs
	}{
		{"cancelled by the first call", nil, false, 4, 1},
		{"first call also fails", errRoutes, false, 4, 1},
		{"cancelled before", nil, true, 0, 20},
	} {
		src, top := batchGraph(t, "routes")
		e := &Expander{Src: src, Concurrency: 4}
		g, err := e.discover(context.Background(), top, false)
		if err != nil {
			t.Fatalf("discover(%s): %v", top, err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		if tc.pre {
			cancel()
		} else {
			cancelAt(src, 1, cancel)
			src.failAt, src.failWith = 1, tc.failWith
		}
		// Cancelled before, each's select finds both a free slot and Done
		// ready and picks at random, so repeat it: only checking the context
		// again after taking a slot makes every run start nothing.
		for range tc.reps {
			if err := e.fetchRoutes(ctx, g); !errors.Is(err, context.Canceled) {
				t.Errorf("%s: fetchRoutes = %v, want context.Canceled", tc.name, err)
			}
		}
		cancel()
		if got := src.count(); got > tc.maxCalls {
			t.Errorf("%s: %d calls, want at most %d", tc.name, got, tc.maxCalls)
		}
	}
}
