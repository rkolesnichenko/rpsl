package resolve

import (
	"container/list"
	"context"
	"errors"
	"net/netip"
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
)

type cacheKey struct {
	kind cacheKind
	name string    // the canonical set name, or "" for a route lookup
	as   types.ASN // the AS, for a route lookup
	afi  types.AFI
}

type cacheEntry struct {
	ready chan struct{} // closed once the value is filled in
	at    time.Time
	elem  *list.Element // the entry's place in Cache.order

	set    object.NamedSet
	routes []netip.Prefix
	claims []object.Object
	err    error
}

// NewCache returns a Cache over src with the given freshness. A zero ttl means
// entries never expire.
func NewCache(src Source, ttl time.Duration) *Cache {
	return &Cache{Src: src, TTL: ttl, entries: map[cacheKey]*cacheEntry{}}
}

var _ Source = (*Cache)(nil)

// GetSet returns the named set, from the cache when it is there and fresh.
func (c *Cache) GetSet(ctx context.Context, name types.SetName) (object.NamedSet, error) {
	e, err := c.lookup(ctx, cacheKey{kind: kindSet, name: name.String()}, func(ctx context.Context, e *cacheEntry) {
		e.set, e.err = c.Src.GetSet(ctx, name)
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
	key := cacheKey{kind: kindClaims, name: set.SetName().String()}
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
