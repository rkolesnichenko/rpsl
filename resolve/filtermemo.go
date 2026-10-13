package resolve

import (
	"container/list"
	"errors"
	"sync"

	"github.com/rkolesnichenko/rpsl/types"
)

// FilterMemo shares NormalizeFilter's answers between Expanders that differ
// only in AFI and Peer: the same Src, limits and Concurrency, and no
// Exclude (an Expander with Exclude set ignores it). An answer is keyed by
// the filter's text and AFI; one whose normalization read Peer — PeerAS, a
// set template, a regexp naming the peer, at any depth, inside filter-sets
// too, bound or not — is never stored, so a hit is always the answer
// NormalizeFilter would compute. Successes are stored, and the errors that
// follow from the filter and the registry alone (*SetTooLargeError,
// *NotEnumerableError, *AnySetError); a context error or a Source failure
// never is. It holds at most maxRanges prefix ranges in all (each answer
// weighs one plus its conjuncts' Prefixes and NotPrefixes), evicting the
// least recently used; an answer heavier than a quarter of that is not
// stored. A NormalFilter it returns is shared: the caller must not modify
// it. It never notices a change in the Source: build a new one for a new
// snapshot. Safe for concurrent use.
type FilterMemo struct {
	mu      sync.Mutex
	max     int
	held    int
	entries map[filterKey]*list.Element // of *filterAnswer
	lru     list.List                   // front: most recently used
	stats   FilterMemoStats
}

// FilterMemoStats is a FilterMemo's counters, for measurement and tests.
type FilterMemoStats struct {
	Hits, Misses  int // lookups answered from the memo / computed
	PeerDependent int // computed answers not stored because they read Peer
	Entries, Held int // answers stored; their weight in prefix ranges
}

type filterKey struct {
	text string
	afi  types.AFI
}

type filterAnswer struct {
	key    filterKey
	nf     NormalFilter
	err    error
	weight int
}

// NewFilterMemo returns a FilterMemo holding at most maxRanges prefix
// ranges.
func NewFilterMemo(maxRanges int) *FilterMemo {
	return &FilterMemo{max: maxRanges, entries: map[filterKey]*list.Element{}}
}

// Stats returns the counters so far.
func (m *FilterMemo) Stats() FilterMemoStats {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.stats
	s.Entries, s.Held = len(m.entries), m.held
	return s
}

// get returns the stored answer for k, if any, and counts the lookup.
func (m *FilterMemo) get(k filterKey) (*filterAnswer, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	el, ok := m.entries[k]
	if !ok {
		m.stats.Misses++
		return nil, false
	}
	m.stats.Hits++
	m.lru.MoveToFront(el)
	return el.Value.(*filterAnswer), true
}

// put stores an answer computed for k, unless it read the peer, is an error
// that does not follow from the inputs alone, or is too heavy.
func (m *FilterMemo) put(k filterKey, nf NormalFilter, err error, usedPeer bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if usedPeer {
		m.stats.PeerDependent++
		return
	}
	if err != nil && !memoizable(err) {
		return
	}
	if _, ok := m.entries[k]; ok {
		return // another goroutine computed it too
	}
	w := 1
	for _, c := range nf.Conjuncts {
		w += c.Prefixes.Len() + c.NotPrefixes.Len()
	}
	if w > m.max/4 {
		return
	}
	m.entries[k] = m.lru.PushFront(&filterAnswer{key: k, nf: nf, err: err, weight: w})
	m.held += w
	for m.held > m.max {
		back := m.lru.Back()
		old := back.Value.(*filterAnswer)
		m.lru.Remove(back)
		delete(m.entries, old.key)
		m.held -= old.weight
	}
}

// memoizable reports whether err follows from the filter and the registry
// alone, so recomputing would give it again.
func memoizable(err error) bool {
	var tl *SetTooLargeError
	var ne *NotEnumerableError
	var as *AnySetError
	return errors.As(err, &tl) || errors.As(err, &ne) || errors.As(err, &as)
}
