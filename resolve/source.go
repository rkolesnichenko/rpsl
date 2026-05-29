// Package resolve expands RPSL set references (as-set, route-set) into concrete
// ASNs and prefixes. The engine is pure: it holds no global state, opens no
// sockets, is context-cancellable, and takes all limits explicitly. Every I/O
// boundary goes through the injected Source, so the same engine runs against an
// in-memory corpus in tests and a live IRR/RDAP backend in production.
package resolve

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/types"
)

// ErrNotFound is returned by a Source when a requested set does not exist. The
// engine treats it as an empty expansion for that reference, not a fatal error.
var ErrNotFound = errors.New("resolve: set not found")

// ErrSetTooLarge reports that an expansion exceeded the configured MaxPrefixes
// budget. It is returned during enumeration, before the full set is allocated.
type ErrSetTooLarge struct {
	Name  types.SetName
	Count int
}

func (e ErrSetTooLarge) Error() string {
	return fmt.Sprintf("resolve: expansion of %s exceeds prefix cap (%d)", e.Name.Canonical(), e.Count)
}

// Source is the injected data backend. Implementations decide trust, ordering
// across IRRs, and freshness; the engine only traverses what they return.
type Source interface {
	// GetSet fetches a set object by name. It returns ErrNotFound (wrapped is
	// fine) when the set does not exist.
	GetSet(ctx context.Context, name types.SetName) (object.Set, error)

	// OriginatedRoutes returns the prefixes a given AS originates, filtered to
	// the requested address family (types.AFIUnspecified or AFIAny = all).
	OriginatedRoutes(ctx context.Context, as types.ASN, afi types.AFI) ([]netip.Prefix, error)

	// MembersByRef returns objects that claim member-of the given set and are
	// maintained by one of the listed mntners (the mbrs-by-ref mechanism). The
	// implementation performs the mntner match; "ANY" in mntners means any
	// maintainer qualifies.
	MembersByRef(ctx context.Context, set types.SetName, mntners []string) ([]object.Object, error)
}
