package consist

import (
	"container/list"
	"context"
	"errors"
	"sync"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

// The defaults NewMemo uses, from RIPE measurements: 1<<21 ranges is the
// largest bound that kept the memo's cost within 1 GB on a 2,000-aut-num
// sample sweep, and 256 aut-nums answered 92.8% of that sample's lookups
// from the memo.
const (
	defaultMemoAutNums = 256
	defaultMemoRanges  = 1 << 21
)

// Memo shares work between a Checker's calls: decoded aut-nums and
// inet-rtrs (a bounded LRU) and normalized filters (a resolve.FilterMemo).
// It changes no answer. It holds data read from Checker.Eval.Src, so it
// serves one Checker, or Checkers with the same Eval; it never notices a
// change in the Source, so build a new one for a new snapshot. Safe for
// concurrent use.
type Memo struct {
	mu      sync.Mutex
	max     int
	objects map[memoKey]*list.Element // of *memoEntry
	lru     list.List                 // front: most recently used
	hits    int
	misses  int
	filters *resolve.FilterMemo
}

// MemoOptions bounds a Memo. A zero field takes its default.
type MemoOptions struct {
	AutNums int // decoded aut-nums and inet-rtrs held (default 256)
	Ranges  int // the filter memo's bound, in prefix ranges and path-set ASNs (default 1<<21, 2,097,152; see resolve.FilterMemo)
}

// MemoStats is a Memo's counters, for measurement and tests.
type MemoStats struct {
	AutNumHits, AutNumMisses int // aut-num and inet-rtr lookups answered from the memo / read
	Filters                  resolve.FilterMemoStats
}

type memoKey struct {
	kind         byte // 'a' aut-num, 'r' inet-rtr
	name, source string
}

type memoEntry struct {
	key memoKey
	obj object.Object // a *object.AutNum or *object.InetRtr, possibly a typed nil
	err error
}

// NewMemo returns a Memo with the default bounds.
func NewMemo() *Memo { return NewMemoWith(MemoOptions{}) }

// NewMemoWith returns a Memo with o's bounds.
func NewMemoWith(o MemoOptions) *Memo {
	if o.AutNums <= 0 {
		o.AutNums = defaultMemoAutNums
	}
	if o.Ranges <= 0 {
		o.Ranges = defaultMemoRanges
	}
	return &Memo{max: o.AutNums, objects: map[memoKey]*list.Element{}, filters: resolve.NewFilterMemo(o.Ranges)}
}

// Stats returns the counters so far.
func (m *Memo) Stats() MemoStats {
	m.mu.Lock()
	s := MemoStats{AutNumHits: m.hits, AutNumMisses: m.misses}
	m.mu.Unlock()
	s.Filters = m.filters.Stats()
	return s
}

func (m *Memo) get(k memoKey) (*memoEntry, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	el, ok := m.objects[k]
	if !ok {
		m.misses++
		return nil, false
	}
	m.hits++
	m.lru.MoveToFront(el)
	return el.Value.(*memoEntry), true
}

// put stores an answer: an object, or not found. Any other error (a Source
// failure, a context error) is not stored.
func (m *Memo) put(ctx context.Context, k memoKey, obj object.Object, err error) {
	if err != nil && (!errors.Is(err, resolve.ErrNotFound) || ctx.Err() != nil) {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.objects[k]; ok {
		return
	}
	m.objects[k] = m.lru.PushFront(&memoEntry{key: k, obj: obj, err: err})
	for len(m.objects) > m.max {
		back := m.lru.Back()
		m.lru.Remove(back)
		delete(m.objects, back.Value.(*memoEntry).key)
	}
}

// memoSource is a PolicySource answering aut-nums and inet-rtrs through a
// Memo shared by a Checker's calls.
type memoSource struct {
	resolve.PolicySource
	m *Memo
}

func (s memoSource) AutNum(ctx context.Context, as types.ASN, source string) (*object.AutNum, error) {
	k := memoKey{'a', as.String(), source}
	if e, ok := s.m.get(k); ok {
		an, _ := e.obj.(*object.AutNum)
		return an, e.err
	}
	an, err := s.PolicySource.AutNum(ctx, as, source)
	s.m.put(ctx, k, an, err)
	return an, err
}

func (s memoSource) InetRtr(ctx context.Context, name, source string) (*object.InetRtr, error) {
	k := memoKey{'r', name, source}
	if e, ok := s.m.get(k); ok {
		ir, _ := e.obj.(*object.InetRtr)
		return ir, e.err
	}
	ir, err := s.PolicySource.InetRtr(ctx, name, source)
	s.m.put(ctx, k, ir, err)
	return ir, err
}
