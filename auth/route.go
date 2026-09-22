package auth

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/policy"
)

// Creating a route object is the authorisation that matters most, because
// getting it wrong is how prefixes get hijacked in an IRR. RFC 2725 §4 requires
// three separate permissions, and a registry that drops any one of them lets a
// stranger register someone else's address space:
//
//  1. from the new object's own maintainers (mnt-by:), so the creator owns it;
//  2. from the origin AS — its aut-num decides who may originate from it;
//  3. from the address space — the covering inetnum, inet6num or less specific
//     route object decides who may route it.
//
// For (2) and (3) the authoritative attribute is mnt-routes: when there is one,
// otherwise mnt-lower:, otherwise mnt-by:. An mnt-routes: may be scoped to
// particular prefixes, and a scope that does not cover the prefix grants
// nothing — so an object that delegates 192.0.2.0/24 does not thereby delegate
// the rest of its space.

// RouteRequest describes a route object someone is asking to create.
type RouteRequest struct {
	// Prefix is the route being created.
	Prefix netip.Prefix
	// MntBy is the new object's own mnt-by:.
	MntBy []string
	// Origin is the aut-num for the route's origin:. A nil Origin means the
	// registry has none, which refuses the creation rather than waving it
	// through — an unknown AS authorises nothing.
	Origin object.Object
	// Space is the most specific inetnum, inet6num or less specific route
	// object covering Prefix. A nil Space refuses the creation for the same
	// reason.
	Space object.Object
}

// RouteRequestFor builds a RouteRequest for an already-decoded route object.
// Origin and Space are still the caller's to supply: finding them is a registry
// lookup, which this package does not do.
func RouteRequestFor(r object.Route, origin, space object.Object) RouteRequest {
	return RouteRequest{Prefix: r.Prefix, MntBy: r.MntBy, Origin: origin, Space: space}
}

// RouteRequestFor6 is RouteRequestFor for a route6 object.
func RouteRequestFor6(r object.Route6, origin, space object.Object) RouteRequest {
	return RouteRequest{Prefix: r.Prefix, MntBy: r.MntBy, Origin: origin, Space: space}
}

// RouteCreation decides whether cred may create the requested route, applying
// all three checks of RFC 2725 §4. Every check must pass; the Decision's
// reasons say which one failed and why.
func RouteCreation(ctx context.Context, reg Registry, req RouteRequest, cred Credential, v Verifier) (Decision, error) {
	var d Decision
	steps := []struct {
		what  string
		names []string
	}{
		{"the route object's own maintainers", req.MntBy},
		{"the origin AS", RouteAuthority(req.Origin, req.Prefix)},
		{"the address space", RouteAuthority(req.Space, req.Prefix)},
	}
	for i, step := range steps {
		if (i == 1 && req.Origin == nil) || (i == 2 && req.Space == nil) {
			d.Reasons = append(d.Reasons, step.what+": not in the registry, so it authorises nothing")
			return d, nil
		}
		if len(step.names) == 0 {
			d.Reasons = append(d.Reasons, step.what+": delegates no maintainer for this prefix")
			return d, nil
		}
		got, err := CheckMntners(ctx, reg, step.names, cred, v)
		if err != nil {
			return Decision{}, err
		}
		d.Reasons = append(d.Reasons, fmt.Sprintf("%s (%v): %s", step.what, step.names, got))
		if !got.OK {
			return d, nil
		}
	}
	d.OK = true
	return d, nil
}

// RouteAuthority returns the maintainers an object delegates to authorise a
// route for prefix: its mnt-routes: when it has one, otherwise its mnt-lower:,
// otherwise its mnt-by: (RFC 2725 §4).
//
// When the object has mnt-routes: entries but none whose scope covers prefix,
// the result is empty: the object has delegated its routing authority
// elsewhere, and not to this prefix. Falling back to mnt-by: there would hand
// the whole space to a maintainer the holder deliberately narrowed.
func RouteAuthority(o object.Object, prefix netip.Prefix) []string {
	mntRoutes, mntLower, mntBy, ok := authorities(o)
	if !ok {
		return nil
	}
	if len(mntRoutes) > 0 {
		return scopedMntners(mntRoutes, prefix)
	}
	if len(mntLower) > 0 {
		return mntLower
	}
	return mntBy
}

// scopedMntners returns the maintainers of the mnt-routes: entries whose scope
// covers prefix. An entry with no scope, or ANY, covers everything.
func scopedMntners(entries []policy.MntRoutes, prefix netip.Prefix) []string {
	var out []string
	for _, m := range entries {
		if m.Mntner == "" {
			continue
		}
		if m.Any && len(m.Ranges) == 0 {
			out = append(out, m.Mntner)
			continue
		}
		for _, r := range m.Ranges {
			if r.Contains(prefix) {
				out = append(out, m.Mntner)
				break
			}
		}
	}
	return out
}

// authorities reads the three maintainer attributes that decide routing
// authority. ok is false for a class that has none of them.
func authorities(o object.Object) (mntRoutes []policy.MntRoutes, mntLower, mntBy []string, ok bool) {
	switch t := o.(type) {
	case object.AutNum:
		return t.MntRoutes, t.MntLower, t.MntBy, true
	case object.Route:
		return t.MntRoutes, t.MntLower, t.MntBy, true
	case object.Route6:
		return t.MntRoutes, t.MntLower, t.MntBy, true
	case object.Inetnum:
		return t.MntRoutes, t.MntLower, t.MntBy, true
	case object.Inet6num:
		return t.MntRoutes, t.MntLower, t.MntBy, true
	}
	return nil, nil, nil, false
}
