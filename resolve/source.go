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

// ErrNotFound is returned by a Source when a requested set does not exist. For a
// nested reference the engine expands it to nothing and lists it in the result's
// Missing(); for the top-level set it returns an error wrapping ErrNotFound.
var ErrNotFound = errors.New("resolve: set not found")

// ErrSetClass is returned when the named set's class does not fit the
// expansion: ExpandAS takes an as-set; ExpandPrefixes and ExpandPrefixRanges
// take an as-set or a route-set.
var ErrSetClass = errors.New("resolve: set class does not fit this expansion")

// Limit identifies which Expander cap an expansion exceeded.
type Limit uint8

const (
	LimitPrefixes Limit = iota // MaxPrefixes: output prefixes (or ranges)
	LimitVisited               // MaxVisited: distinct sets fetched, or evaluation visits
	LimitDepth                 // MaxDepth: shortest nesting distance from the top set
)

// String returns the name of the Expander field the limit is, e.g. "MaxVisited".
func (l Limit) String() string {
	switch l {
	case LimitVisited:
		return "MaxVisited"
	case LimitDepth:
		return "MaxDepth"
	default:
		return "MaxPrefixes"
	}
}

// SetTooLargeError reports that an expansion exceeded one of the Expander's caps.
// It is returned, as a *SetTooLargeError, as soon as the cap trips, before the
// full result is built: Max is the cap and Count the value reached (at least
// Max+1).
type SetTooLargeError struct {
	Name  types.SetName
	Limit Limit
	Max   int
	Count int
}

// Error implements error.
func (e *SetTooLargeError) Error() string {
	if e.Name.IsZero() { // a filter evaluated outside any filter-set
		return fmt.Sprintf("resolve: expansion exceeds %s (%d): reached %d", e.Limit, e.Max, e.Count)
	}
	return fmt.Sprintf("resolve: expansion of %s exceeds %s (%d): reached %d", e.Name, e.Limit, e.Max, e.Count)
}

// AnySetError reports a reference to AS-ANY or RS-ANY, which denote every AS or
// every route in the IRR (RFC 2622 §5) and cannot be expanded. It is returned
// as an *AnySetError.
type AnySetError struct{ Name types.SetName }

// Error implements error.
func (e *AnySetError) Error() string {
	return fmt.Sprintf("resolve: %s denotes the whole IRR and cannot be expanded", e.Name)
}

// Source is the injected data backend. Implementations decide trust, ordering
// across IRRs, and freshness; the engine only traverses what they return.
//
// MembersByRef is a contract that varies by backend, intentionally. Pure-WHOIS
// backends must resolve the mbrs-by-ref / member-of indirect-membership
// mechanism themselves (typically via an inverse query, then a mntner check),
// because the protocol does not pre-expand it. IRRd-style backends that already
// expand indirect membership server-side during !i may safely return an empty
// slice — duplicating the join client-side would only over-collect. Custom
// Source authors must decide which world they are in; see resolve/whois and
// resolve/irrd for the two reference implementations.
//
// ErrNotFound means a missing set and nothing else: OriginatedRoutes and
// MembersByRef report "nothing there" as an empty result, not an error, and any
// other error aborts the expansion.
type Source interface {
	// GetSet fetches a set object by name. It returns ErrNotFound (wrapped is
	// fine) when the set does not exist; a nil set with a nil error is treated
	// the same way.
	GetSet(ctx context.Context, name types.SetName) (object.NamedSet, error)

	// OriginatedRoutes returns the prefixes a given AS originates, filtered to
	// the requested address family (types.AFIUnspecified or AFIAny = all).
	OriginatedRoutes(ctx context.Context, as types.ASN, afi types.AFI) ([]netip.Prefix, error)

	// MembersByRef returns the objects whose claim of membership in set is
	// honored (the mbrs-by-ref mechanism): they name the set in member-of, are
	// maintained by one of set.RefMntners() ("ANY" admits any maintainer), and
	// come from set.SetSource(). Implementations should filter with
	// ClaimAllowed. The Expander re-applies ClaimAllowed to every returned
	// object, so an over-inclusive result cannot widen a set.
	MembersByRef(ctx context.Context, set object.NamedSet) ([]object.Object, error)
}
