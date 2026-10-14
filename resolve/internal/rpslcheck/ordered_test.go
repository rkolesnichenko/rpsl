package rpslcheck

import (
	"context"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// waitFor polls cond for up to 5 s.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for range 1000 {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met within 5s")
}

// Every result is emitted once, in index order, whatever conc and window
// are and however long each work takes; no work starts window or more past
// the results already emitted.
func TestOrderedEmitsInOrder(t *testing.T) {
	const n = 300
	for _, conc := range []int{1, 4, 16} {
		for _, window := range []int{1, 3, 64} {
			r := rand.New(rand.NewPCG(uint64(conc), uint64(window)))
			delay := make([]time.Duration, n)
			for i := range delay {
				delay[i] = time.Duration(r.IntN(300)) * time.Microsecond
			}
			var got []int
			var emitted atomic.Int64
			ok := ordered(context.Background(), n, conc, window, func(_ context.Context, i int) int {
				if e := emitted.Load(); int64(i) >= e+int64(window) {
					t.Errorf("conc %d window %d: work %d started with %d emitted", conc, window, i, e)
				}
				time.Sleep(delay[i])
				return i * 10
			}, func(i, v int) bool {
				if v != i*10 {
					t.Errorf("conc %d window %d: emit(%d, %d)", conc, window, i, v)
				}
				got = append(got, i)
				emitted.Add(1)
				return true
			})
			if !ok {
				t.Errorf("conc %d window %d: ordered returned false", conc, window)
			}
			if len(got) != n {
				t.Fatalf("conc %d window %d: %d emitted, want %d", conc, window, len(got), n)
			}
			for i, v := range got {
				if v != i {
					t.Fatalf("conc %d window %d: emitted out of order: %v", conc, window, got)
				}
			}
		}
	}
}

// Review Focus 3: while the head result is still running, no more than
// window works start, however many workers are free.
func TestOrderedWindowHoldsBack(t *testing.T) {
	const n, conc, window = 50, 16, 4
	release := make(chan struct{})
	var started atomic.Int64
	result := make(chan []int, 1)
	go func() {
		var got []int
		ordered(context.Background(), n, conc, window, func(_ context.Context, i int) int {
			started.Add(1)
			if i == 0 {
				<-release
			}
			return i
		}, func(i, _ int) bool {
			got = append(got, i)
			return true
		})
		result <- got
	}()
	waitFor(t, func() bool { return started.Load() == window })
	time.Sleep(50 * time.Millisecond) // time for a wrongly dispatched work to start
	if s := started.Load(); s != window {
		t.Fatalf("%d works started while work 0 runs, want %d", s, window)
	}
	close(release)
	select {
	case got := <-result:
		if len(got) != n {
			t.Fatalf("%d emitted, want %d", len(got), n)
		}
		for i, v := range got {
			if v != i {
				t.Fatalf("emitted out of order: %v", got)
			}
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ordered did not finish after work 0 was released")
	}
}

// Review Focus 4: emit returning false stops the run there. Nothing after
// it is emitted, running work sees its context cancelled, and ordered
// returns false only after every work has returned.
func TestOrderedStopsWhereEmitSays(t *testing.T) {
	const n, k = 100, 10
	var active, cancelled atomic.Int64
	afterK := make(chan struct{})
	var once sync.Once
	var got []int
	finished := make(chan bool, 1)
	go func() {
		finished <- ordered(context.Background(), n, 4, 8, func(ctx context.Context, i int) int {
			active.Add(1)
			defer active.Add(-1)
			switch {
			case i == k:
				<-afterK // emit k only once some later work is running
			case i > k:
				once.Do(func() { close(afterK) })
				<-ctx.Done() // only the stop can end this work
				cancelled.Add(1)
			}
			return i
		}, func(i, _ int) bool {
			got = append(got, i)
			return i != k
		})
	}()
	select {
	case ok := <-finished:
		if ok {
			t.Error("ordered returned true after emit stopped it")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ordered did not return: the stop did not cancel the running work")
	}
	if len(got) != k+1 || got[k] != k {
		t.Errorf("emitted %v, want 0..%d", got, k)
	}
	if a := active.Load(); a != 0 {
		t.Errorf("%d works still running after ordered returned", a)
	}
	if cancelled.Load() == 0 {
		t.Error("no running work saw its context cancelled")
	}
}

// The caller's context ending stops dispatch: ordered returns false, and
// what it emitted is still a prefix in order.
func TestOrderedRunContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	const n = 1000
	var got []int
	ok := ordered(ctx, n, 4, 8, func(_ context.Context, i int) int { return i }, func(i, _ int) bool {
		got = append(got, i)
		if i == 20 {
			cancel()
		}
		return true
	})
	if ok {
		t.Error("ordered returned true though its context ended")
	}
	if len(got) >= n {
		t.Errorf("all %d emitted after the context ended", n)
	}
	for i, v := range got {
		if v != i {
			t.Fatalf("emitted out of order: %v", got)
		}
	}
}

func TestOrderedEdges(t *testing.T) {
	for _, c := range []struct{ n, conc, window int }{
		{0, 4, 8},   // nothing to do
		{3, 16, 64}, // n below conc and window
		{50, 1, 1},  // one at a time
		{50, 8, 1},  // a window of one serializes even with free workers
	} {
		var got []int
		ok := ordered(context.Background(), c.n, c.conc, c.window, func(_ context.Context, i int) int { return i }, func(i, _ int) bool {
			got = append(got, i)
			return true
		})
		if !ok || len(got) != c.n {
			t.Errorf("%+v: ok %v, %d emitted", c, ok, len(got))
			continue
		}
		for i, v := range got {
			if v != i {
				t.Errorf("%+v: emitted out of order: %v", c, got)
				break
			}
		}
	}
}
