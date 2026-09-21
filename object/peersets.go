package object

import (
	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/types"
)

// PeeringSet is a peering-set (prng-…): a named collection of peering
// specifications carried in peering:/mp-peering: attributes (RFC 2622 §5.6,
// RFC 4012).
type PeeringSet struct {
	Common
	Name     types.SetName
	Peerings []policy.Peering // parsed peering:/mp-peering: specs, in document order
	raw      *ast.Object
}

func (s PeeringSet) Class() string    { return "peering-set" }
func (s PeeringSet) Raw() *ast.Object { return s.raw }

func decodePeeringSet(d *decoder) PeeringSet {
	ps := PeeringSet{
		Common: d.common("peering-set"),
		Name:   d.setKey("peering-set", "object/peering-set-name", types.PeeringSet),
		raw:    d.o,
	}
	for _, a := range d.o.Attributes() {
		if a.Name != "peering" && a.Name != "mp-peering" {
			continue
		}
		pe, ds := policy.ParsePeering(a.Value)
		ps.Peerings = append(ps.Peerings, pe)
		d.rebase(a, ds)
	}
	return ps
}

// FilterSet is a filter-set (fltr-…): a named policy filter (RFC 2622 §5.4).
// Filter is the parsed filter: value and MpFilter the RFC 4012 mp-filter: value;
// either is nil when absent.
type FilterSet struct {
	Common
	Name     types.SetName
	Filter   policy.Filter
	MpFilter policy.Filter
	raw      *ast.Object
}

func (s FilterSet) Class() string    { return "filter-set" }
func (s FilterSet) Raw() *ast.Object { return s.raw }

func decodeFilterSet(d *decoder) FilterSet {
	fs := FilterSet{
		Common: d.common("filter-set"),
		Name:   d.setKey("filter-set", "object/filter-set-name", types.FilterSet),
		raw:    d.o,
	}
	parse := func(name string) policy.Filter {
		a, ok := d.o.GetFirst(name)
		if !ok {
			return nil
		}
		f, ds := policy.ParseFilter(a.Value)
		d.rebase(a, ds)
		return f
	}
	fs.Filter, fs.MpFilter = parse("filter"), parse("mp-filter")
	return fs
}

// RtrSet is a rtr-set (rtrs-…): a named collection of routers. Members and
// MpMembers carry inet-rtr names, nested rtr-set names, and router addresses,
// kept as their raw text. MbrsByRef enables indirect membership.
type RtrSet struct {
	Common
	Name      types.SetName
	Members   []string
	MpMembers []string
	MbrsByRef []string
	raw       *ast.Object
}

func (s RtrSet) Class() string    { return "rtr-set" }
func (s RtrSet) Raw() *ast.Object { return s.raw }

func decodeRtrSet(d *decoder) RtrSet {
	return RtrSet{
		Common:    d.common("rtr-set"),
		Name:      d.setKey("rtr-set", "object/rtr-set-name", types.RtrSet),
		Members:   d.list("members"),
		MpMembers: d.list("mp-members"),
		MbrsByRef: d.list("mbrs-by-ref"),
		raw:       d.o,
	}
}
