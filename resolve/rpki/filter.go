package rpki

import (
	"context"
	"net/netip"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

// Filter is a resolve.Source that suppresses what IRRd 4's RPKI-aware mode
// suppresses: every route and route6 object Validate finds Invalid. So
// OriginatedRoutes drops each prefix that is Invalid for the AS asked about,
// and MembersByRef drops each route or route6 claimant that is Invalid for its
// own origin. GetSet and the members a set lists pass through unchanged — IRRd
// suppresses route objects, not the prefixes a route-set names.
//
// A route's state depends only on its prefix and origin, so filtering the
// prefixes a Source returns is what IRRd's per-object suppression does when no
// source is rpki_excluded, IRRd's default. Filter never adds a route: IRRd's
// pseudo objects come from WriteRPSL, or from a server that serves them.
//
// Filter sees only what Src reports as routes. irrd.Source gets a route-set's
// indirect route members folded by the server into the set's members, as
// prefixes Filter cannot tell from the ones the set lists, so over an IRRd
// that is not RPKI-aware those members stay. An RPKI-aware IRRd (RADB)
// suppresses them itself, and MemSource and whois.Source report them as the
// route objects they are.
type Filter struct {
	Src  resolve.Source
	VRPs *VRPs // nil suppresses nothing

	// OnSuppress, when set, is called for each route dropped, with its prefix
	// and origin. It may be called concurrently when the Expander is.
	OnSuppress func(p netip.Prefix, origin types.ASN)
}

// GetSet returns Src's answer unchanged.
func (f *Filter) GetSet(ctx context.Context, name types.SetName) (object.NamedSet, error) {
	return f.Src.GetSet(ctx, name)
}

// OriginatedRoutes returns Src's routes for as without those Invalid for as.
func (f *Filter) OriginatedRoutes(ctx context.Context, as types.ASN, afi types.AFI) ([]netip.Prefix, error) {
	ps, err := f.Src.OriginatedRoutes(ctx, as, afi)
	if err != nil {
		return nil, err
	}
	return keep(ps, func(p netip.Prefix) bool { return !f.suppressed(p, as) }), nil
}

// MembersByRef returns Src's claimants without the route and route6 objects
// Invalid for their origin.
func (f *Filter) MembersByRef(ctx context.Context, set object.NamedSet) ([]object.Object, error) {
	objs, err := f.Src.MembersByRef(ctx, set)
	if err != nil {
		return nil, err
	}
	return keep(objs, func(o object.Object) bool {
		p, origin, ok := route(o)
		return !ok || !f.suppressed(p, origin)
	}), nil
}

// keep returns the elements of xs that ok accepts: xs itself when it accepts
// them all, as it usually does, and a copy only once one is left out.
func keep[T any](xs []T, ok func(T) bool) []T {
	var out []T // nil until an element is left out
	for i, x := range xs {
		switch {
		case !ok(x):
			if out == nil {
				out = append(make([]T, 0, len(xs)), xs[:i]...)
			}
		case out != nil:
			out = append(out, x)
		}
	}
	if out == nil {
		return xs
	}
	return out
}

func (f *Filter) suppressed(p netip.Prefix, origin types.ASN) bool {
	if f.VRPs.Validate(p, origin) != Invalid {
		return false
	}
	if f.OnSuppress != nil {
		f.OnSuppress(p, origin)
	}
	return true
}

// route returns the prefix and origin of a route or route6 object, as a value
// or a pointer.
func route(o object.Object) (netip.Prefix, types.ASN, bool) {
	switch t := o.(type) {
	case object.Route:
		return t.Prefix, t.Origin, true
	case *object.Route:
		if t != nil {
			return t.Prefix, t.Origin, true
		}
	case object.Route6:
		return t.Prefix, t.Origin, true
	case *object.Route6:
		if t != nil {
			return t.Prefix, t.Origin, true
		}
	}
	return netip.Prefix{}, 0, false
}

var _ resolve.Source = (*Filter)(nil)
