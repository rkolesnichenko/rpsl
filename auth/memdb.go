package auth

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/types"
)

// Database is what authorising an update looks up in the registry being
// updated: its maintainers, and the objects an update's permission comes from.
// It holds one IRR source — maintainer names are unique only within one — and
// its objects are values as object.Decode returns them.
//
// It is the authorisation model's I/O, injected as resolve.Source injects the
// expansion engine's: a registry implements it over its store, and MemDatabase
// over decoded objects.
type Database interface {
	Registry // Mntner(ctx, name)

	// Current returns the stored object of o's class with o's primary key, or
	// an error wrapping ErrNotFound.
	Current(ctx context.Context, o object.Object) (object.Object, error)

	// Object returns the object of class with primary key key, compared as
	// RPSL compares keys, or an error wrapping ErrNotFound.
	Object(ctx context.Context, class, key string) (object.Object, error)

	// Covering returns the objects of class — inetnum, inet6num, route or
	// route6 — whose address space holds all of lo..hi, most specific first,
	// an exact match included.
	Covering(ctx context.Context, class string, lo, hi netip.Addr) ([]object.Object, error)

	// ASBlocks returns the as-blocks that hold as, most specific first.
	ASBlocks(ctx context.Context, as types.ASN) ([]object.AsBlock, error)
}

// ErrNotFound reports an object the registry does not have.
var ErrNotFound = errors.New("auth: not in the registry")

// MemDatabase is a Database over decoded objects of one source: for tests, and
// for checking updates against a dump. Of two objects with one primary key,
// the later wins, as loading a dump in order would leave it. Its lookups scan
// the objects they may match, so it suits a test corpus or a sample better
// than a whole registry.
type MemDatabase struct {
	objects map[string]object.Object // class + "\x00" + primary key
	spaces  map[string][]spaceEntry  // class -> address-space objects
	blocks  []object.AsBlock
}

type spaceEntry struct {
	lo, hi netip.Addr
	o      object.Object
}

var _ Database = (*MemDatabase)(nil)

// NewMemDatabase indexes objs.
func NewMemDatabase(objs []object.Object) *MemDatabase {
	db := &MemDatabase{objects: map[string]object.Object{}, spaces: map[string][]spaceEntry{}}
	for _, o := range objs {
		if o == nil {
			continue
		}
		class, key, ok := primaryKey(o)
		if !ok {
			continue
		}
		db.objects[class+"\x00"+key] = o
		if lo, hi, ok := addressRange(o); ok {
			db.spaces[class] = append(db.spaces[class], spaceEntry{lo, hi, o})
		}
		if b, ok := o.(object.AsBlock); ok {
			db.blocks = append(db.blocks, b)
		}
	}
	return db
}

// Mntner returns the named maintainer, or an error wrapping ErrNoMntner.
func (db *MemDatabase) Mntner(_ context.Context, name string) (object.Mntner, error) {
	o, ok := db.objects["mntner\x00"+normalKey("mntner", name)]
	if m, isMntner := o.(object.Mntner); ok && isMntner {
		return m, nil
	}
	return object.Mntner{}, fmt.Errorf("%w: %s", ErrNoMntner, name)
}

// Current returns the stored object with o's class and primary key.
func (db *MemDatabase) Current(_ context.Context, o object.Object) (object.Object, error) {
	class, key, ok := primaryKey(o)
	if !ok {
		return nil, fmt.Errorf("%w: an object with no primary key", ErrNotFound)
	}
	if got, ok := db.objects[class+"\x00"+key]; ok {
		return got, nil
	}
	return nil, fmt.Errorf("%w: %s %s", ErrNotFound, class, key)
}

// Object returns the object of class with primary key key.
func (db *MemDatabase) Object(_ context.Context, class, key string) (object.Object, error) {
	class = strings.ToLower(strings.TrimSpace(class))
	if got, ok := db.objects[class+"\x00"+normalKey(class, key)]; ok {
		return got, nil
	}
	return nil, fmt.Errorf("%w: %s %s", ErrNotFound, class, key)
}

// Covering returns the objects of class holding lo..hi, most specific first.
func (db *MemDatabase) Covering(_ context.Context, class string, lo, hi netip.Addr) ([]object.Object, error) {
	var hits []spaceEntry
	for _, e := range db.spaces[strings.ToLower(class)] {
		if e.lo.BitLen() == lo.BitLen() && e.lo.Compare(lo) <= 0 && hi.Compare(e.hi) <= 0 {
			hits = append(hits, e)
		}
	}
	// Every hit holds lo..hi, so of two the one starting later, or ending
	// sooner, lies inside the other.
	sort.SliceStable(hits, func(i, j int) bool {
		if c := hits[i].lo.Compare(hits[j].lo); c != 0 {
			return c > 0
		}
		return hits[i].hi.Compare(hits[j].hi) < 0
	})
	out := make([]object.Object, len(hits))
	for i, e := range hits {
		out[i] = e.o
	}
	return out, nil
}

// ASBlocks returns the as-blocks holding as, most specific first.
func (db *MemDatabase) ASBlocks(_ context.Context, as types.ASN) ([]object.AsBlock, error) {
	var out []object.AsBlock
	for _, b := range db.blocks {
		if b.Lo <= as && as <= b.Hi {
			out = append(out, b)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Hi-out[i].Lo < out[j].Hi-out[j].Lo })
	return out, nil
}

// primaryKey returns o's class and its primary key in canonical form, so that
// every spelling of one key is one map key. A route's key is its prefix and
// origin together, as in the RIPE Database and IRRd.
func primaryKey(o object.Object) (class, key string, ok bool) {
	switch t := o.(type) {
	case object.Route:
		if !t.Prefix.IsValid() {
			return "", "", false
		}
		return "route", t.Prefix.Masked().String() + t.Origin.String(), true
	case object.Route6:
		if !t.Prefix.IsValid() {
			return "", "", false
		}
		return "route6", t.Prefix.Masked().String() + t.Origin.String(), true
	case object.Inetnum:
		if !t.Lo.IsValid() || !t.Hi.IsValid() {
			return "", "", false
		}
		return "inetnum", t.Lo.String() + " - " + t.Hi.String(), true
	case object.Inet6num:
		if !t.Prefix.IsValid() {
			return "", "", false
		}
		return "inet6num", t.Prefix.Masked().String(), true
	case object.AsBlock:
		return "as-block", t.Lo.String() + " - " + t.Hi.String(), true
	case object.Person: // a person or role is known by its nic-hdl, not its name
		if h := t.NicHdl.String(); h != "" {
			return "person", strings.ToUpper(h), true
		}
		return "", "", false
	case object.Role:
		if h := t.NicHdl.String(); h != "" {
			return "role", strings.ToUpper(h), true
		}
		return "", "", false
	}
	raw := o.Raw()
	if raw == nil || raw.Class() == "" {
		return "", "", false
	}
	class = raw.Class()
	key = normalKey(class, raw.Key())
	return class, key, key != ""
}

// normalKey puts a key of class in canonical form: AS numbers as asplain,
// set names as types.SetName writes them, anything else upper-cased.
func normalKey(class, key string) string {
	key = strings.TrimSpace(key)
	switch class {
	case "aut-num":
		if as, err := types.ParseASN(key); err == nil {
			return as.String()
		}
	case "as-set", "route-set", "rtr-set", "peering-set", "filter-set":
		if n, err := types.ParseSetName(key); err == nil {
			return n.String()
		}
	case "domain":
		return strings.ToUpper(strings.TrimSuffix(key, "."))
	}
	return strings.ToUpper(key)
}

// addressRange returns the addresses an address-space object holds.
func addressRange(o object.Object) (lo, hi netip.Addr, ok bool) {
	switch t := o.(type) {
	case object.Inetnum:
		return t.Lo, t.Hi, t.Lo.IsValid() && t.Hi.IsValid()
	case object.Inet6num:
		return prefixRange(t.Prefix)
	case object.Route:
		return prefixRange(t.Prefix)
	case object.Route6:
		return prefixRange(t.Prefix)
	}
	return netip.Addr{}, netip.Addr{}, false
}

// prefixRange returns the first and last address of p.
func prefixRange(p netip.Prefix) (lo, hi netip.Addr, ok bool) {
	if !p.IsValid() {
		return netip.Addr{}, netip.Addr{}, false
	}
	p = p.Masked()
	return p.Addr(), lastAddr(p), true
}
