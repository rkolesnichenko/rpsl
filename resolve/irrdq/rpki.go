package irrdq

import (
	"net/netip"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve/rpki"
	"github.com/rkolesnichenko/rpsl/types"
)

// notFoundState is IRRd's rpki-ov-state: value for a route no VRP covers.
const notFoundState = "not_found # No ROAs found, or RPKI validation not enabled for source"

// visible reports whether a route is served: in RPKI-aware mode, a route of
// any registry but the pseudo one is hidden when RFC 6811 finds it invalid.
func (snap *Snapshot) visible(r *Registry, rt route) bool {
	return snap.routeVisible(r, rt.prefix, rt.origin)
}

// routeVisible is visible for a route of r given by prefix and origin.
func (snap *Snapshot) routeVisible(r *Registry, p netip.Prefix, origin types.ASN) bool {
	v := snap.opts.VRPs
	return v == nil || r.name == rpki.PseudoSource || v.Validate(p.Masked(), origin) != rpki.Invalid
}

// claimVisible reports whether a member-of claimant of r is served: a route
// or route6 only when routeVisible, any other object always. IRRd mode
// (claimants) and RFC mode (multiSource) both filter with it.
func (snap *Snapshot) claimVisible(r *Registry, o object.Object) bool {
	switch t := o.(type) {
	case object.Route:
		return snap.routeVisible(r, t.Prefix, t.Origin)
	case object.Route6:
		return snap.routeVisible(r, t.Prefix, t.Origin)
	}
	return true
}

// ovState is the line a route's text is served with: in RPKI-aware mode,
// IRRd's rpki-ov-state: line (not on a pseudo route), otherwise "". An
// invalid route is never served, so its state is valid or not_found.
func (snap *Snapshot) ovState(r *Registry, rt route) string {
	v := snap.opts.VRPs
	if v == nil || r.name == rpki.PseudoSource || rt.text == "" {
		return ""
	}
	if v.Validate(rt.prefix, rt.origin) != rpki.Valid {
		return ovNotFound
	}
	return ovValid
}

// The rpki-ov-state: lines a served route carries in RPKI-aware mode.
const (
	ovValid    = "rpki-ov-state:  valid\n"
	ovNotFound = "rpki-ov-state:  " + notFoundState + "\n"
)
