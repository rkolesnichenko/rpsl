package resolve

import (
	"container/list"
	"errors"
	"strconv"
	"strings"
	"sync"

	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/types"
)

// FilterMemo shares NormalizeFilter's and ExpandAS's answers between
// Expanders that differ only in AFI, limits and Peer: the same Src (and so
// the same snapshot), and no Exclude (an Expander with Exclude set ignores
// it). Concurrency never changes an answer, so it may differ too. A
// NormalizeFilter answer is keyed by the filter's whole structure — a
// rendering that keeps every grouping, operator and spelling the normal form
// can depend on or carry (memoText) — with the AFI and the effective
// MaxDepth, MaxPrefixes, MaxVisited and MaxConjuncts (zero and the default
// are one key). A filter holding a node that rendering does not know is never
// looked up or stored. An answer whose normalization read Peer — PeerAS, a
// set template, a regexp naming the peer, at any depth, inside filter-sets
// too, bound or not — is never stored. An ExpandAS answer, which reads
// neither the AFI nor Peer, is keyed by the set reference and the effective
// MaxDepth and MaxVisited, apart from every filter's. So a hit is the answer
// NormalizeFilter or ExpandAS computes. Successes are stored, and the errors
// that follow from the filter or set and the registry alone
// (*SetTooLargeError, *NotEnumerableError, *AnySetError); a context error, a
// Source failure or a missing top set never is. A filter answer weighs one
// plus its conjuncts' Prefixes and NotPrefixes ranges and the ASNs in its
// AS-path tests' Sets, an expansion one plus its ASNs and missing sets. The
// memo holds at most maxRanges of filter weight and, apart, at most maxRanges
// of expansion weight, so neither kind evicts the other; each is evicted least
// recently used first, and it does not store an answer heavier than a quarter
// of maxRanges. A NormalFilter or ASNSet it returns is shared: the caller must
// not modify it. It never notices a change in the Source: build a new one for
// a new snapshot. Safe for concurrent use.
//
// NewFilterMemoOver layers one over another, for one call: a layer keeps
// what its call uses for as long as the call runs, whatever the memo under
// it evicts meanwhile.
type FilterMemo struct {
	mu      sync.Mutex
	max     int
	shared  *FilterMemo                 // the memo this one is layered over (NewFilterMemoOver), or nil
	entries map[filterKey]*list.Element // of *filterAnswer, in either pool
	filters memoPool                    // NormalizeFilter's answers
	asns    memoPool                    // ExpandAS's answers
	stats   FilterMemoStats
}

// memoPool is one kind of answer, bounded apart from the other: sharing one
// bound, the IXP sets a lint's peerings expand evicted its filters, and big
// filters the expansions.
type memoPool struct {
	held int
	lru  list.List // front: most recently used
}

// pool returns the pool an answer for k lives in.
func (m *FilterMemo) pool(k filterKey) *memoPool {
	if k.asns {
		return &m.asns
	}
	return &m.filters
}

// FilterMemoStats is a FilterMemo's counters, for measurement and tests.
type FilterMemoStats struct {
	Hits, Misses  int // lookups answered from the memo / computed
	PeerDependent int // computed answers not stored because they read Peer
	Entries, Held int // answers stored; their total weight (see FilterMemo)
}

// filterKey is what an answer depends on, besides Src: the filter's
// memoText, the AFI and the effective limits; for an ExpandAS answer (asns),
// the set reference's text, MaxDepth and MaxVisited.
//
// The ExpandAS pool is read only by ExpandAS. NormalizeFilter's evaluator
// expands sets through filterEval.asSet and filterEval.pathSet, which call
// expandAS directly and must never read that pool: a set reaching AS-ANY is
// every AS in an AS-path regexp and an *AnySetError in ExpandAS, so the two
// answers for one set reference differ.
type filterKey struct {
	asns                                bool
	text                                string
	afi                                 types.AFI
	depth, prefixes, visited, conjuncts int
}

type filterAnswer struct {
	key    filterKey
	nf     NormalFilter
	asns   ASNSet
	err    error
	weight int
}

// NewFilterMemo returns a FilterMemo holding NormalizeFilter answers of at
// most maxRanges weight in all, and ExpandAS answers of at most maxRanges
// apart (see FilterMemo). It stores no answer heavier than maxRanges/4, so
// below 4 it stores nothing.
func NewFilterMemo(maxRanges int) *FilterMemo {
	return &FilterMemo{max: maxRanges, entries: map[filterKey]*list.Element{}}
}

// NewFilterMemoOver returns a FilterMemo bounded as NewFilterMemo(maxRanges)
// is, layered over shared: a lookup it cannot answer itself is answered from
// shared when shared holds the key, and the answer is then kept in the layer
// too; an answer computed through it is stored in the layer and in shared,
// each by its own rules. A hit in the layer does not touch shared. Use one
// for one call's evaluations, so that what shared evicts while the call runs
// is not computed again; shared must serve the same snapshot (see
// FilterMemo). A nil shared makes it NewFilterMemo(maxRanges). Its Stats
// count its own lookups: a lookup answered from shared is a hit in both, and
// an answer that read the peer counts as PeerDependent in every memo of the
// chain.
func NewFilterMemoOver(shared *FilterMemo, maxRanges int) *FilterMemo {
	m := NewFilterMemo(maxRanges)
	m.shared = shared
	return m
}

// Stats returns the counters so far.
func (m *FilterMemo) Stats() FilterMemoStats {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.stats
	s.Entries, s.Held = len(m.entries), m.filters.held+m.asns.held
	return s
}

// get returns the stored answer for k, if any — the layer's own, or else
// shared's, which the layer then keeps — and counts the lookup. It never
// holds the layer's lock and shared's together.
func (m *FilterMemo) get(k filterKey) (*filterAnswer, bool) {
	m.mu.Lock()
	if el, ok := m.entries[k]; ok {
		m.stats.Hits++
		m.pool(k).lru.MoveToFront(el)
		a := el.Value.(*filterAnswer)
		m.mu.Unlock()
		return a, true
	}
	m.mu.Unlock()
	if m.shared != nil {
		if a, ok := m.shared.get(k); ok {
			m.mu.Lock()
			m.stats.Hits++
			m.keep(a)
			m.mu.Unlock()
			return a, true
		}
	}
	m.mu.Lock()
	m.stats.Misses++
	m.mu.Unlock()
	return nil, false
}

// put stores a NormalizeFilter answer computed for k, unless it read the
// peer, is an error that does not follow from the inputs alone, or is too
// heavy.
func (m *FilterMemo) put(k filterKey, nf NormalFilter, err error, usedPeer bool) {
	if usedPeer {
		for x := m; x != nil; x = x.shared {
			x.mu.Lock()
			x.stats.PeerDependent++
			x.mu.Unlock()
		}
		return
	}
	w := 1
	for _, c := range nf.Conjuncts {
		w += c.Prefixes.Len() + c.NotPrefixes.Len()
		for _, p := range c.Paths {
			for _, s := range p.Sets {
				w += s.Len()
			}
		}
	}
	m.store(&filterAnswer{key: k, nf: nf, err: err, weight: w})
}

// putASNs stores an ExpandAS answer computed for k, as put does.
func (m *FilterMemo) putASNs(k filterKey, s ASNSet, err error) {
	m.store(&filterAnswer{key: k, asns: s, err: err, weight: 1 + s.Len() + len(s.Missing())})
}

// store adds a, unless its error does not follow from the inputs alone, to
// m (see keep) and then to shared.
func (m *FilterMemo) store(a *filterAnswer) {
	if a.err != nil && !memoizable(a.err) {
		return
	}
	m.mu.Lock()
	m.keep(a)
	m.mu.Unlock()
	if m.shared != nil {
		m.shared.store(a)
	}
}

// keep adds a to m's own pool, unless m holds its key already or it weighs
// over a quarter of the bound, evicting the least recently used answers of
// the pool to keep it within the bound. m.mu is held.
func (m *FilterMemo) keep(a *filterAnswer) {
	if _, ok := m.entries[a.key]; ok {
		return // another goroutine computed it too
	}
	if a.weight > m.max/4 {
		return
	}
	p := m.pool(a.key)
	m.entries[a.key] = p.lru.PushFront(a)
	p.held += a.weight
	for p.held > m.max {
		back := p.lru.Back()
		old := back.Value.(*filterAnswer)
		p.lru.Remove(back)
		delete(m.entries, old.key)
		p.held -= old.weight
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

// memoText renders f for a filterKey: a text from which f's whole tree can be
// read back, so two filters with one text are one filter and normalize alike.
// Unlike String, it parenthesizes every AND, OR, NOT and binary AS
// expression (the normalizer charges depth and visits per group), keeps a
// community test's operator, Raw and Values verbatim and an AS-path regexp's
// Raw and tree (both reach the answer), writes a range operator's fields when
// its String would drop them, and tells a nil list from an empty one. Every
// part is self-delimiting: a tag and brackets around each node, quoted free
// text, and leaves (set names, ASNs, prefix ranges) that hold none of the
// brackets or separators. ok is false when f holds a node it does not know
// (a nil, or a pointer to a node), never a lossy text.
func memoText(f policy.Filter) (string, bool) {
	var b strings.Builder
	if !writeFilter(&b, f) {
		return "", false
	}
	return b.String(), true
}

func writeFilter(b *strings.Builder, f policy.Filter) bool {
	switch x := f.(type) {
	case policy.FilterAny:
		b.WriteString("ANY")
	case policy.FilterPeerAS:
		b.WriteString("PeerAS")
		writeRangeOp(b, x.Op)
	case policy.FilterPrefixList:
		// Each range is closed by ';', so the zero range ("") still shows.
		b.WriteString("{")
		if x.Ranges == nil {
			b.WriteString("nil")
		}
		for _, r := range x.Ranges {
			b.WriteString(r.String())
			b.WriteString(";")
		}
		b.WriteString("}")
	case policy.FilterASExpr:
		b.WriteString("as(")
		if !writeASExpr(b, x.AS) {
			return false
		}
		b.WriteString(")")
		writeRangeOp(b, x.Op)
	case policy.FilterSetRef:
		b.WriteString("set(" + x.Name.String() + ")")
		writeRangeOp(b, x.Op)
	case policy.FilterSetTemplate:
		b.WriteString("tpl(" + x.Template.String() + ")")
		writeRangeOp(b, x.Op)
	case policy.FilterPathRE:
		b.WriteString("re(" + strconv.Quote(x.Raw) + ",")
		if x.Regexp == nil {
			b.WriteString("nil")
		} else if !writeRE(b, x.Regexp.Body) {
			return false
		}
		b.WriteString(")")
	case policy.FilterCommunity:
		b.WriteString("comm(" + strconv.Itoa(int(x.Op)) + "," + strconv.Quote(x.Raw) + ",")
		if x.Values == nil {
			b.WriteString("nil")
		} else {
			b.WriteString("[")
			for _, v := range x.Values {
				b.WriteString(strconv.Quote(v) + ",")
			}
			b.WriteString("]")
		}
		b.WriteString(")")
	case policy.FilterAnd:
		return writeFilters(b, "and", x.Terms)
	case policy.FilterOr:
		return writeFilters(b, "or", x.Terms)
	case policy.FilterNot:
		b.WriteString("not(")
		if !writeFilter(b, x.Inner) {
			return false
		}
		b.WriteString(")")
	default:
		return false
	}
	return true
}

func writeFilters(b *strings.Builder, tag string, fs []policy.Filter) bool {
	b.WriteString(tag)
	if fs == nil {
		b.WriteString("nil")
		return true
	}
	b.WriteString("(")
	for _, f := range fs {
		if !writeFilter(b, f) {
			return false
		}
		b.WriteString(",")
	}
	b.WriteString(")")
	return true
}

func writeASExpr(b *strings.Builder, e policy.ASExpr) bool {
	switch x := e.(type) {
	case policy.ASNum:
		b.WriteString(x.AS.String())
	case policy.ASSetRef:
		b.WriteString("set(" + x.Name.String() + ")")
	case policy.ASSetTemplate:
		b.WriteString("tpl(" + x.Template.String() + ")")
	case policy.ASExprBinary:
		b.WriteString("(")
		if !writeASExpr(b, x.L) {
			return false
		}
		b.WriteString(" " + strconv.Itoa(int(x.Op)) + " ")
		if !writeASExpr(b, x.R) {
			return false
		}
		b.WriteString(")")
	default:
		return false
	}
	return true
}

func writeRE(b *strings.Builder, e policy.ASPathExpr) bool {
	switch x := e.(type) {
	case policy.ASPathAlt:
		return writeREs(b, "alt", x.Alts)
	case policy.ASPathSeq:
		return writeREs(b, "seq", x.Terms)
	case policy.ASPathRepeat:
		b.WriteString("rep(")
		if !writeRE(b, x.Inner) {
			return false
		}
		b.WriteString("," + strconv.Itoa(int(x.Op)) + "," + strconv.Itoa(x.Min) + "," + strconv.Itoa(x.Max) + "," + strconv.FormatBool(x.Same) + ")")
	case policy.ASPathAny:
		b.WriteString(".")
	case policy.ASPathASN:
		b.WriteString(x.AS.String())
	case policy.ASPathSet:
		b.WriteString("set(" + x.Name.String() + ")")
	case policy.ASPathSetTemplate:
		b.WriteString("tpl(" + x.Template.String() + ")")
	case policy.ASPathPeerAS:
		b.WriteString("PeerAS")
	case policy.ASPathStart:
		b.WriteString("^")
	case policy.ASPathEnd:
		b.WriteString("$")
	case policy.ASPathClass:
		b.WriteString("class(" + strconv.FormatBool(x.Negated) + ",")
		if !writeREs(b, "", x.Items) {
			return false
		}
		b.WriteString(")")
	case policy.ASPathASNRange:
		b.WriteString("range(" + x.Lo.String() + "," + x.Hi.String() + ")")
	default:
		return false
	}
	return true
}

func writeREs(b *strings.Builder, tag string, es []policy.ASPathExpr) bool {
	b.WriteString(tag)
	if es == nil {
		b.WriteString("nil")
		return true
	}
	b.WriteString("(")
	for _, e := range es {
		if !writeRE(b, e) {
			return false
		}
		b.WriteString(",")
	}
	b.WriteString(")")
	return true
}

// writeRangeOp writes o as String does when that is the only operator with
// that String (no operator, ^+ and ^- with zero N and M, ^n with N == M, and
// every ^n-m), and its fields otherwise.
func writeRangeOp(b *strings.Builder, o types.RangeOperator) {
	canonical := false
	switch o.Op {
	case types.RangeExact, types.RangePlus, types.RangeMinus:
		canonical = o.N == 0 && o.M == 0
	case types.RangeLength:
		canonical = o.N == o.M
	case types.RangeRange:
		canonical = true
	}
	if canonical {
		b.WriteString(o.String())
		return
	}
	b.WriteString("^?" + strconv.Itoa(int(o.Op)) + "/" + strconv.Itoa(int(o.N)) + "/" + strconv.Itoa(int(o.M)))
}
