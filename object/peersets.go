package object

import (
	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/types"
)

// PeeringSet is a peering-set (prng-…): a named collection of peering
// specifications carried in peering:/mp-peering: attributes (RFC 2622 §5.4).
type PeeringSet struct {
	Name     types.SetName
	Peerings []policy.Peering // parsed peering:/mp-peering: specs, in document order
	MntBy    []string
	Source   string
	raw      *ast.Object
}

func (s PeeringSet) Class() string    { return "peering-set" }
func (s PeeringSet) Raw() *ast.Object { return s.raw }

func decodePeeringSet(d *decoder) PeeringSet {
	ps := PeeringSet{
		Name:   d.setKey("peering-set", "object/peering-set-name"),
		MntBy:  d.all("mnt-by"),
		Source: d.str("source"),
		raw:    d.o,
	}
	for _, name := range []string{"peering", "mp-peering"} {
		for _, a := range d.o.GetAll(name) {
			pe, ds := policy.ParsePeering(a.Value)
			ps.Peerings = append(ps.Peerings, pe)
			d.rebase(a, ds)
		}
	}
	return ps
}

// FilterSet is a filter-set (fltr-…): a named policy filter carried in a
// filter:/mp-filter: attribute (RFC 2622 §5.4, RFC 4012). Filter is the parsed
// expression of the first such attribute (nil when absent or unparsable).
type FilterSet struct {
	Name   types.SetName
	Filter policy.Filter
	MntBy  []string
	Source string
	raw    *ast.Object
}

func (s FilterSet) Class() string    { return "filter-set" }
func (s FilterSet) Raw() *ast.Object { return s.raw }

func decodeFilterSet(d *decoder) FilterSet {
	fs := FilterSet{
		Name:   d.setKey("filter-set", "object/filter-set-name"),
		MntBy:  d.all("mnt-by"),
		Source: d.str("source"),
		raw:    d.o,
	}
	// filter: is a single-valued attribute; mp-filter: is its RFC 4012 form.
	for _, name := range []string{"filter", "mp-filter"} {
		if a, ok := d.o.GetFirst(name); ok {
			f, ds := policy.ParseFilter(a.Value)
			fs.Filter = f
			d.rebase(a, ds)
			break
		}
	}
	return fs
}

// RtrSet is a rtr-set (rtrs-…): a named collection of routers. Members and
// MpMembers carry inet-rtr names, nested rtr-set names, and router addresses,
// kept as their raw text (router specs are not further structured, per the M3
// scope note). MbrsByRef enables indirect membership.
type RtrSet struct {
	Name      types.SetName
	Members   []string
	MpMembers []string
	MbrsByRef []string
	MntBy     []string
	Source    string
	raw       *ast.Object
}

func (s RtrSet) Class() string    { return "rtr-set" }
func (s RtrSet) Raw() *ast.Object { return s.raw }

func decodeRtrSet(d *decoder) RtrSet {
	return RtrSet{
		Name:      d.setKey("rtr-set", "object/rtr-set-name"),
		Members:   d.all("members"),
		MpMembers: d.all("mp-members"),
		MbrsByRef: d.all("mbrs-by-ref"),
		MntBy:     d.all("mnt-by"),
		Source:    d.str("source"),
		raw:       d.o,
	}
}
