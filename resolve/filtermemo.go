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

// FilterMemo shares NormalizeFilter's answers between Expanders that differ
// only in AFI, limits and Peer: the same Src (and so the same snapshot), and
// no Exclude (an Expander with Exclude set ignores it). Concurrency never
// changes an answer, so it may differ too. An answer is keyed by the filter's
// whole structure — a rendering that keeps every grouping, operator and
// spelling the normal form can depend on or carry (memoText) — with the AFI
// and the effective MaxDepth, MaxPrefixes, MaxVisited and MaxConjuncts (zero
// and the default are one key). A filter holding a node that rendering does
// not know is never looked up or stored. An answer whose normalization read
// Peer — PeerAS, a set template, a regexp naming the peer, at any depth,
// inside filter-sets too, bound or not — is never stored. So a hit is the
// answer NormalizeFilter computes for that filter. Successes are stored, and
// the errors that follow from the filter and the registry alone
// (*SetTooLargeError, *NotEnumerableError, *AnySetError); a context error or
// a Source failure never is. Each answer weighs one plus its conjuncts'
// Prefixes and NotPrefixes ranges and the ASNs in its AS-path tests' Sets;
// the memo holds at most maxRanges of weight in all, evicting the least
// recently used, and does not store an answer heavier than a quarter of
// that. A NormalFilter it returns is shared: the caller must not modify it.
// It never notices a change in the Source: build a new one for a new
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
	Entries, Held int // answers stored; their total weight (see FilterMemo)
}

// filterKey is what an answer depends on, besides Src: the filter's
// memoText, the AFI and the effective limits.
type filterKey struct {
	text                                string
	afi                                 types.AFI
	depth, prefixes, visited, conjuncts int
}

type filterAnswer struct {
	key    filterKey
	nf     NormalFilter
	err    error
	weight int
}

// NewFilterMemo returns a FilterMemo holding answers of at most maxRanges
// weight in all (see FilterMemo). It stores no answer heavier than
// maxRanges/4, so below 4 it stores nothing.
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
		for _, p := range c.Paths {
			for _, s := range p.Sets {
				w += s.Len()
			}
		}
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
