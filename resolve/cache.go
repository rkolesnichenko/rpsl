package resolve

import (
	"container/list"
	"context"
	"errors"
	"iter"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/types"
)

// A caching Source. Expanding a large customer cone asks the same backend for
// the same sets over and over — once per expansion, and again for every
// expansion that overlaps it — so a cache in front of a live IRRd or WHOIS
// server is usually the difference between seconds and minutes.
//
// Caching belongs here, in a Source, rather than in the Expander: freshness is
// a policy question that depends on the registry and on what the answer is for,
// and the engine stays pure (design §8.3).

// DefaultCacheEntries is the entry cap a Cache uses when MaxEntries is zero.
const DefaultCacheEntries = 1 << 16

// Cache wraps a Source with an in-memory cache of set, route and claim
// lookups. It is safe for concurrent use, and it caches "not found" too — a
// missing set is a common answer and costs a round trip like any other.
//
// Identical lookups in flight at the same time are collapsed into one call to
// the underlying Source, so a burst of goroutines expanding overlapping sets
// does not multiply the load on the registry.
//
// The zero value is not usable: build one with NewCache.
type Cache struct {
	// Src is the Source being cached.
	Src Source
	// TTL is how long an entry stays fresh. Zero means entries never expire,
	// which is what a snapshot wants; a live registry wants minutes.
	TTL time.Duration
	// MaxEntries caps the number of cached entries, evicting the least recently
	// used. Zero means DefaultCacheEntries; negative means no cap.
	MaxEntries int

	mu      sync.Mutex
	entries map[cacheKey]*cacheEntry
	order   list.List // of cacheKey, least recently used first
	hits    int
	misses  int
}

// CacheStats reports what a Cache has done.
type CacheStats struct {
	Hits    int
	Misses  int
	Entries int
}

type cacheKind uint8

const (
	kindSet cacheKind = iota
	kindRoutes
	kindClaims
	kindAutNum
	kindInetRtr
)

type cacheKey struct {
	kind cacheKind
	name string    // the set reference, or (set source, set name) for claims; the inet-rtr name for kindInetRtr; "" for a route or aut-num lookup
	as   types.ASN // the AS, for a route or aut-num lookup
	afi  types.AFI
	src  string // upper-case source scope, for kindAutNum and kindInetRtr ("" is the precedence); a separate field, not concatenated into name, so ("A", "B::C") and ("A::B", "C") cannot collide
}

type cacheEntry struct {
	ready chan struct{} // closed once the value is filled in
	at    time.Time
	elem  *list.Element // the entry's place in Cache.order

	set    object.NamedSet
	routes []netip.Prefix
	claims []object.Object
	obj    object.Object // AutNum or InetRtr
	err    error
}

// NewCache returns a Cache over src with the given freshness. A zero ttl means
// entries never expire.
func NewCache(src Source, ttl time.Duration) *Cache {
	return &Cache{Src: src, TTL: ttl, entries: map[cacheKey]*cacheEntry{}}
}

var _ Source = (*Cache)(nil)

// GetSet returns the set ref names, from the cache when it is there and fresh.
// A scoped and an unscoped reference to one name are cached apart.
func (c *Cache) GetSet(ctx context.Context, ref types.SetRef) (object.NamedSet, error) {
	e, err := c.lookup(ctx, cacheKey{kind: kindSet, name: ref.String()}, func(ctx context.Context, e *cacheEntry) {
		e.set, e.err = c.Src.GetSet(ctx, ref)
	})
	if err != nil {
		return nil, err
	}
	return e.set, e.err
}

// OriginatedRoutes returns the routes the AS originates, from the cache when it
// is there and fresh. Each address family is cached separately, as each is a
// separate query.
func (c *Cache) OriginatedRoutes(ctx context.Context, as types.ASN, afi types.AFI) ([]netip.Prefix, error) {
	e, err := c.lookup(ctx, cacheKey{kind: kindRoutes, as: as, afi: afi}, func(ctx context.Context, e *cacheEntry) {
		e.routes, e.err = c.Src.OriginatedRoutes(ctx, as, afi)
	})
	if err != nil {
		return nil, err
	}
	if e.err != nil {
		return nil, e.err
	}
	return append([]netip.Prefix(nil), e.routes...), nil
}

// MembersByRef returns the objects claiming membership in set, from the cache
// when it is there and fresh.
func (c *Cache) MembersByRef(ctx context.Context, set object.NamedSet) ([]object.Object, error) {
	if set == nil {
		return nil, nil
	}
	// two same-named sets of two registries have different claimants; the
	// source is folded as ClaimAllowed compares it (ASCII only)
	key := cacheKey{kind: kindClaims, name: lowerASCII(strings.TrimSpace(set.SetSource())) + "::" + set.SetName().String()}
	e, err := c.lookup(ctx, key, func(ctx context.Context, e *cacheEntry) {
		e.claims, e.err = c.Src.MembersByRef(ctx, set)
	})
	if err != nil {
		return nil, err
	}
	if e.err != nil {
		return nil, e.err
	}
	return append([]object.Object(nil), e.claims...), nil
}

// AutNum returns the aut-num of as, from the cache when it is there and fresh.
func (c *Cache) AutNum(ctx context.Context, as types.ASN, source string) (*object.AutNum, error) {
	ps, ok := c.Src.(PolicySource)
	if !ok {
		return nil, ErrNoPolicy
	}
	e, err := c.lookup(ctx, cacheKey{kind: kindAutNum, as: as, src: policySourceKey(source)}, func(ctx context.Context, e *cacheEntry) {
		an, err := ps.AutNum(ctx, as, source)
		e.obj, e.err = an, err
	})
	if err != nil {
		return nil, err
	}
	if e.err != nil {
		return nil, e.err
	}
	return e.obj.(*object.AutNum), nil
}

// InetRtr returns the inet-rtr named name, from the cache when it is there and fresh.
func (c *Cache) InetRtr(ctx context.Context, name, source string) (*object.InetRtr, error) {
	ps, ok := c.Src.(PolicySource)
	if !ok {
		return nil, ErrNoPolicy
	}
	key := cacheKey{kind: kindInetRtr, name: rtrKey(name), src: policySourceKey(source)}
	e, err := c.lookup(ctx, key, func(ctx context.Context, e *cacheEntry) {
		ir, err := ps.InetRtr(ctx, name, source)
		e.obj, e.err = ir, err
	})
	if err != nil {
		return nil, err
	}
	if e.err != nil {
		return nil, e.err
	}
	return e.obj.(*object.InetRtr), nil
}

var _ PolicySource = (*Cache)(nil)

var _ PolicyIndex = (*Cache)(nil)

// AutNums passes through to Src when it is a PolicyIndex, and is ErrNoIndex
// otherwise. A listing is not cached.
func (c *Cache) AutNums() (iter.Seq[types.ASN], error) {
	if pi, ok := c.Src.(PolicyIndex); ok {
		return pi.AutNums()
	}
	return nil, ErrNoIndex
}

// NamedBy passes through to Src when it is a PolicyIndex, and is ErrNoIndex
// otherwise. The index is in memory already; it is not cached again.
func (c *Cache) NamedBy(as types.ASN) ([]types.ASN, error) {
	if pi, ok := c.Src.(PolicyIndex); ok {
		return pi.NamedBy(as)
	}
	return nil, ErrNoIndex
}

// policySourceKey is the cache key of a policy lookup's source: its canonical
// form, as the lookups compare it (types.ParseSourceName), so every spelling
// of one registry shares an entry; a name that is not a source name keeps its
// raw text, which no canonical name equals (strings.ToUpper would fold
// "ripeſ" into the valid "RIPES").
func policySourceKey(source string) string {
	if canon, err := types.ParseSourceName(source); err == nil {
		return canon
	}
	return source
}

// lookup returns the entry for key, filling it with fill on a miss. Concurrent
// lookups of one key wait for the first rather than each calling the Source.
func (c *Cache) lookup(ctx context.Context, key cacheKey, fill func(context.Context, *cacheEntry)) (*cacheEntry, error) {
	for {
		c.mu.Lock()
		if e, ok := c.entries[key]; ok && c.fresh(e) {
			c.hits++
			c.touch(e)
			c.mu.Unlock()
			select {
			case <-e.ready:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			// The caller that filled the entry was cancelled; that says
			// nothing about this caller, which fetches for itself.
			if isContextErr(e.err) && ctx.Err() == nil {
				continue
			}
			return e, nil
		}
		c.misses++
		e := &cacheEntry{ready: make(chan struct{})}
		c.entries[key] = e
		e.elem = c.order.PushBack(key)
		c.evict()
		c.mu.Unlock()

		fill(ctx, e)
		e.at = time.Now()
		// A cancelled or failed lookup should not be remembered as an answer:
		// the next caller deserves a fresh try. ErrNotFound is a real answer
		// and stays. The entry goes before its waiters wake, so one that
		// retries starts a new lookup rather than finding this one again.
		if e.err != nil && !errors.Is(e.err, ErrNotFound) {
			c.mu.Lock()
			if c.entries[key] == e {
				c.remove(key, e)
			}
			c.mu.Unlock()
		}
		close(e.ready)
		return e, nil
	}
}

// isContextErr reports whether err is a context's cancellation or deadline.
func isContextErr(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// fresh reports whether an entry is still within the TTL.
func (c *Cache) fresh(e *cacheEntry) bool {
	if c.TTL <= 0 {
		return true
	}
	select {
	case <-e.ready:
		return time.Since(e.at) < c.TTL
	default:
		return true // still being filled; joining it is what we want
	}
}

// touch moves e to the most-recently-used end. Called with mu held.
func (c *Cache) touch(e *cacheEntry) {
	if e.elem != nil {
		c.order.MoveToBack(e.elem)
	}
}

// remove drops the entry for key. Called with mu held.
func (c *Cache) remove(key cacheKey, e *cacheEntry) {
	delete(c.entries, key)
	if e.elem != nil {
		c.order.Remove(e.elem)
		e.elem = nil
	}
}

// evict drops least-recently-used entries down to the cap. Called with mu held.
func (c *Cache) evict() {
	max := c.MaxEntries
	switch {
	case max < 0:
		return
	case max == 0:
		max = DefaultCacheEntries
	}
	for c.order.Len() > max {
		oldest := c.order.Front()
		key := oldest.Value.(cacheKey)
		c.remove(key, c.entries[key])
	}
}

// Purge empties the cache.
func (c *Cache) Purge() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = map[cacheKey]*cacheEntry{}
	c.order.Init()
}

// Stats reports the hits, misses and current size.
func (c *Cache) Stats() CacheStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return CacheStats{Hits: c.hits, Misses: c.misses, Entries: len(c.entries)}
}
