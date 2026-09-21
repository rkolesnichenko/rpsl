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

// Limit identifies which Expander cap an expansion exceeded.
type Limit uint8

const (
	LimitPrefixes Limit = iota // MaxPrefixes: output prefixes (or ranges)
	LimitVisited               // MaxVisited: distinct sets fetched, or evaluation visits
	LimitDepth                 // MaxDepth: shortest nesting distance from the top set
)

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

// ErrSetTooLarge reports that an expansion exceeded one of the Expander's caps.
// It is returned as soon as the cap trips, before the full result is built.
// Count is the value reached when it tripped (at least the cap plus one).
type ErrSetTooLarge struct {
	Name  types.SetName
	Limit Limit
	Count int
}

func (e ErrSetTooLarge) Error() string {
	return fmt.Sprintf("resolve: expansion of %s exceeds %s (%d)", e.Name.Canonical(), e.Limit, e.Count)
}

// ErrCyclicOperator reports a range operator applied along a cycle: a set is
// re-entered from inside its own expansion under a different stack of operators
// (e.g. RS-A lists RS-B^+ and RS-B lists RS-A). Composing that exactly needs a
// fixpoint computation, so the engine refuses rather than return a result that
// is too small.
type ErrCyclicOperator struct {
	Set    types.SetName // the set containing the member that closes the cycle
	Member string        // that member's text
}

func (e ErrCyclicOperator) Error() string {
	return fmt.Sprintf("resolve: %s member %q closes a cycle under a range operator", e.Set, e.Member)
}

// ErrAnySet reports a reference to AS-ANY or RS-ANY, which denote every AS or
// every route in the IRR (RFC 2622 §5) and cannot be expanded.
type ErrAnySet struct{ Name types.SetName }

func (e ErrAnySet) Error() string {
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
type Source interface {
	// GetSet fetches a set object by name. It returns ErrNotFound (wrapped is
	// fine) when the set does not exist.
	GetSet(ctx context.Context, name types.SetName) (object.Set, error)

	// OriginatedRoutes returns the prefixes a given AS originates, filtered to
	// the requested address family (types.AFIUnspecified or AFIAny = all).
	OriginatedRoutes(ctx context.Context, as types.ASN, afi types.AFI) ([]netip.Prefix, error)

	// MembersByRef returns objects that claim member-of the given set and are
	// maintained by one of the listed mntners (the mbrs-by-ref mechanism);
	// "ANY" in mntners means any maintainer qualifies. Implementations should
	// filter with ClaimAllowed. The Expander re-applies ClaimAllowed to every
	// returned object, so an over-inclusive result cannot widen a set.
	MembersByRef(ctx context.Context, set types.SetName, mntners []string) ([]object.Object, error)
}
