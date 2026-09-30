package rtconfig

import (
	"net/netip"
	"strings"

	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/types"
)

// setOps is what a clause's actions do to a route, vendor-neutrally. The
// community operations are kept order-independent: a route ends with
// (its communities − commDel) ∪ commAdd, or commSet when commSetGiven.
type setOps struct {
	localPref    int // −1: unset
	med          int // −1: unset
	medIGP       bool
	commSet      []community
	commSetGiven bool
	commAdd      []community
	commDel      []community
	prepend      []types.ASN // prepended in this order: the path becomes prepend… old
	nextHop      netip.Addr
	nextHopSelf  bool
}

// compileActions reads a clause's actions (RFC 2622 §9) in order, for a
// session of family afi. term names the clause in errors.
func (g *Generator) compileActions(acts []policy.Action, afi types.AFI, term string) (setOps, error) {
	ops := setOps{localPref: -1, med: -1}
	for _, a := range acts {
		switch {
		case a.Attr == "pref" && a.Op == policy.ActionAssign:
			n, ok := a.Int()
			if !ok || n < 0 {
				return ops, unsupported(g.Vendor, CauseActionValue, a.String())
			}
			if n > g.maxPref() {
				return ops, unsupported(g.Vendor, CausePref, a.String())
			}
			ops.localPref = g.maxPref() - n
		case a.Attr == "med" && a.Op == policy.ActionAssign:
			if strings.EqualFold(strings.TrimSpace(a.Value), "igp_cost") {
				if !g.supports(FeatureMEDIGP) {
					return ops, unsupported(g.Vendor, CauseActionValue, a.String())
				}
				ops.med, ops.medIGP = -1, true
				continue
			}
			n, ok := a.Int()
			if !ok || n < 0 {
				return ops, unsupported(g.Vendor, CauseActionValue, a.String())
			}
			ops.med, ops.medIGP = n, false
		case a.Attr == "community":
			if err := g.communityAction(&ops, a); err != nil {
				return ops, err
			}
		case a.Attr == "aspath" && a.Op == policy.ActionMethod && a.Method == "prepend":
			as, ok := a.Prepends()
			if !ok {
				return ops, unsupported(g.Vendor, CauseActionValue, a.String())
			}
			ops.prepend = append(append([]types.ASN(nil), as...), ops.prepend...)
		case a.Attr == "next-hop" && a.Op == policy.ActionAssign:
			v := strings.TrimSpace(a.Value)
			if strings.EqualFold(v, "self") {
				if !g.supports(FeatureNextHopSelf) {
					return ops, unsupported(g.Vendor, CauseActionValue, a.String())
				}
				ops.nextHop, ops.nextHopSelf = netip.Addr{}, true
				continue
			}
			addr, err := netip.ParseAddr(v)
			if err != nil || addr.Zone() != "" || addr.Is4() != (afi == types.AFIv4) {
				// A next-hop of the other family is no next-hop for this
				// session: IOS rejects "set ipv6 next-hop 192.0.2.1" on load
				// but keeps the entry, which then leaves routes' next-hop as
				// it was. A zone is no part of an RPSL address.
				return ops, unsupported(g.Vendor, CauseActionValue, a.String())
			}
			ops.nextHop, ops.nextHopSelf = addr, false
		default:
			return ops, unsupported(g.Vendor, CauseAction, a.String())
		}
	}
	if g.Vendor == Junos && ops.commSetGiven && len(ops.commSet) == 0 {
		// "community = {}": Junos sets a named community's members, and a
		// community has at least one.
		return ops, unsupported(g.Vendor, CauseActionValue, term)
	}
	return ops, nil
}

// communityAction applies one community action to ops: "=" replaces, ".=" and
// append add, delete removes.
func (g *Generator) communityAction(ops *setOps, a policy.Action) error {
	var vals []string
	switch {
	case a.Op == policy.ActionAssign, a.Op == policy.ActionAppend,
		a.Op == policy.ActionMethod && a.Method == "append":
		vals, _ = a.Communities()
	case a.Op == policy.ActionMethod && a.Method == "delete":
		vals = a.Args
	default:
		return unsupported(g.Vendor, CauseAction, a.String())
	}
	cs, err := g.parseCommunities(vals, a.String())
	if err != nil {
		return err
	}
	switch {
	case a.Op == policy.ActionAssign:
		ops.commSet, ops.commSetGiven, ops.commAdd, ops.commDel = cs, true, nil, nil
	case a.Method == "delete":
		if ops.commSetGiven {
			ops.commSet = without(ops.commSet, cs)
			return nil
		}
		ops.commAdd = without(ops.commAdd, cs)
		ops.commDel = union(ops.commDel, cs)
	default:
		if ops.commSetGiven {
			ops.commSet = union(ops.commSet, cs)
			return nil
		}
		ops.commDel = without(ops.commDel, cs)
		ops.commAdd = union(ops.commAdd, cs)
	}
	return nil
}

func union(a, b []community) []community {
	seen := map[community]bool{}
	var out []community
	for _, c := range append(append([]community(nil), a...), b...) {
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

func without(a, b []community) []community {
	drop := map[community]bool{}
	for _, c := range b {
		drop[c] = true
	}
	var out []community
	for _, c := range a {
		if !drop[c] {
			out = append(out, c)
		}
	}
	return out
}
