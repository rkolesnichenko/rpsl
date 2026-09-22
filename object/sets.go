package object

import (
	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/types"
)

// The set classes seen through the interfaces the resolution engine traverses.
// Every set class shares NamedSet — a name, the mbrs-by-ref maintainers that
// enable indirect membership, and the registry it belongs to — and then differs
// in what its members are: ASNs and prefix ranges (as-set, route-set), routers
// (rtr-set), peerings (peering-set), or a filter expression (filter-set).
//
// The methods are named to avoid clashing with the concrete types' exported
// fields.

// NamedSet is what every set class has in common, and all the engine needs to
// fetch a set and decide whose indirect membership claims it honours.
type NamedSet interface {
	Object
	SetName() types.SetName // the set's own name
	RefMntners() []string   // mbrs-by-ref: maintainers enabling indirect membership
	SetSource() string      // source: the registry the set belongs to ("" if absent)
}

// Set is a set whose members are ASNs, prefix ranges and nested sets: an as-set
// or a route-set (RFC 2622 §5.1, §5.2).
type Set interface {
	NamedSet
	SetMembers() []SetMember // direct members: members: plus mp-members:
}

// RouterSet is a rtr-set: its members are routers and nested rtr-sets
// (RFC 2622 §5.5).
type RouterSet interface {
	NamedSet
	SetRouters() []RtrSetMember // direct members: members: plus mp-members:
}

// PeeringGroup is a peering-set: its members are peering specifications and
// nested peering-set references (RFC 2622 §5.6).
type PeeringGroup interface {
	NamedSet
	SetPeerings() []policy.Peering // peering: plus mp-peering:
}

// FilterGroup is a filter-set: it holds a filter expression rather than a
// member list (RFC 2622 §5.4). The two accessors are separate because RFC 4012
// §2.4 makes mp-filter: the multiprotocol form of the same thing, and which one
// applies depends on the address family being expanded.
type FilterGroup interface {
	NamedSet
	SetFilter() policy.Filter   // filter:, or nil when absent
	SetMpFilter() policy.Filter // mp-filter:, or nil when absent
}

func (s AsSet) SetName() types.SetName { return s.Name }

// SetMembers returns the as-set's direct members: members: then mp-members:, in
// that order.
func (s AsSet) SetMembers() []SetMember {
	out := make([]SetMember, 0, len(s.Members)+len(s.MpMembers))
	out = append(out, s.Members...)
	out = append(out, s.MpMembers...)
	return out
}

// RefMntners returns the mbrs-by-ref maintainers.
func (s AsSet) RefMntners() []string { return s.MbrsByRef }

// SetSource returns the set's source: attribute.
func (s AsSet) SetSource() string { return s.Source }

func (s RouteSet) SetName() types.SetName { return s.Name }

// SetMembers returns the route-set's direct members: members: then mp-members:.
func (s RouteSet) SetMembers() []SetMember {
	out := make([]SetMember, 0, len(s.Members)+len(s.MpMembers))
	out = append(out, s.Members...)
	out = append(out, s.MpMembers...)
	return out
}

// RefMntners returns the mbrs-by-ref maintainers.
func (s RouteSet) RefMntners() []string { return s.MbrsByRef }

// SetSource returns the set's source: attribute.
func (s RouteSet) SetSource() string { return s.Source }

func (s RtrSet) SetName() types.SetName { return s.Name }

// SetRouters returns the rtr-set's direct members: members: then mp-members:.
func (s RtrSet) SetRouters() []RtrSetMember {
	out := make([]RtrSetMember, 0, len(s.Members)+len(s.MpMembers))
	out = append(out, s.Members...)
	out = append(out, s.MpMembers...)
	return out
}

// RefMntners returns the mbrs-by-ref maintainers.
func (s RtrSet) RefMntners() []string { return s.MbrsByRef }

// SetSource returns the set's source: attribute.
func (s RtrSet) SetSource() string { return s.Source }

func (s PeeringSet) SetName() types.SetName { return s.Name }

// SetPeerings returns the peering-set's peerings: peering: then mp-peering:.
func (s PeeringSet) SetPeerings() []policy.Peering {
	out := make([]policy.Peering, 0, len(s.Peerings)+len(s.MpPeerings))
	out = append(out, s.Peerings...)
	out = append(out, s.MpPeerings...)
	return out
}

// RefMntners returns no maintainers: a peering-set has no mbrs-by-ref:, so it
// has no indirect membership.
func (s PeeringSet) RefMntners() []string { return nil }

// SetSource returns the set's source: attribute.
func (s PeeringSet) SetSource() string { return s.Source }

func (s FilterSet) SetName() types.SetName { return s.Name }

// SetFilter returns the filter: expression, or nil when there is none.
func (s FilterSet) SetFilter() policy.Filter { return s.Filter }

// SetMpFilter returns the mp-filter: expression, or nil when there is none.
func (s FilterSet) SetMpFilter() policy.Filter { return s.MpFilter }

// RefMntners returns no maintainers: a filter-set has no mbrs-by-ref:, so it
// has no indirect membership.
func (s FilterSet) RefMntners() []string { return nil }

// SetSource returns the set's source: attribute.
func (s FilterSet) SetSource() string { return s.Source }

// Compile-time checks that each set class satisfies the interface for its kind.
var (
	_ Set          = AsSet{}
	_ Set          = RouteSet{}
	_ RouterSet    = RtrSet{}
	_ PeeringGroup = PeeringSet{}
	_ FilterGroup  = FilterSet{}
	_ NamedSet     = AsSet{}
	_ NamedSet     = RouteSet{}
	_ NamedSet     = RtrSet{}
	_ NamedSet     = PeeringSet{}
	_ NamedSet     = FilterSet{}
)
