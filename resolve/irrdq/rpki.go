package irrdq

import (
	"net/netip"

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

// routeText is a route's text as served: in RPKI-aware mode, with IRRd's
// rpki-ov-state: line after it (not on a pseudo route). An invalid route is
// never served, so its state is valid or not_found.
func (snap *Snapshot) routeText(r *Registry, rt route) string {
	v := snap.opts.VRPs
	if v == nil || r.name == rpki.PseudoSource || rt.text == "" {
		return rt.text
	}
	state := "valid"
	if v.Validate(rt.prefix, rt.origin) != rpki.Valid {
		state = notFoundState
	}
	return rt.text + "rpki-ov-state:  " + state + "\n"
}
