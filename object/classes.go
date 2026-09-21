package object

import (
	"net/netip"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/types"
)

// AutNum is an aut-num object. Its import:/export:/default: values are parsed
// into the policy AST; each policy diagnostic is re-based onto its attribute.
type AutNum struct {
	Common
	AS       types.ASN
	AsName   string
	MemberOf []types.SetName
	Imports  []policy.Import
	Exports  []policy.Export
	Defaults []policy.Default
	raw      *ast.Object
}

func (a AutNum) Class() string    { return "aut-num" }
func (a AutNum) Raw() *ast.Object { return a.raw }

func decodeAutNum(d *decoder) AutNum {
	an := AutNum{
		Common:   d.common("aut-num"),
		AS:       d.asn("aut-num", "object/aut-num-as"),
		AsName:   d.str("as-name"),
		MemberOf: d.setNames("member-of", "object/aut-num-member-of"),
		raw:      d.o,
	}
	// import: and mp-import: are unioned into Imports (design §6) in document
	// order, because the order of policies is their precedence (design §4); the
	// MP field marks the RFC 4012 entries. Likewise for export and default.
	for _, a := range d.o.Attributes() {
		var ds []ast.Diagnostic
		switch a.Name {
		case "import", "mp-import":
			parse := policy.ParseImport
			if a.Name == "mp-import" {
				parse = policy.ParseMPImport
			}
			var imp policy.Import
			imp, ds = parse(a.Value)
			an.Imports = append(an.Imports, imp)
		case "export", "mp-export":
			parse := policy.ParseExport
			if a.Name == "mp-export" {
				parse = policy.ParseMPExport
			}
			var exp policy.Export
			exp, ds = parse(a.Value)
			an.Exports = append(an.Exports, exp)
		case "default", "mp-default":
			parse := policy.ParseDefault
			if a.Name == "mp-default" {
				parse = policy.ParseMPDefault
			}
			var def policy.Default
			def, ds = parse(a.Value)
			an.Defaults = append(an.Defaults, def)
		default:
			continue
		}
		d.rebase(a, ds)
	}
	return an
}

// Mntner is a maintainer object. Auth lines are kept raw and uninterpreted.
type Mntner struct {
	Common
	Handle string
	Auth   []string
	UpdTo  []string
	MntNfy []string
	raw    *ast.Object
}

func (m Mntner) Class() string    { return "mntner" }
func (m Mntner) Raw() *ast.Object { return m.raw }

func decodeMntner(d *decoder) Mntner {
	return Mntner{
		Common: d.common("mntner"),
		Handle: d.key("mntner"),
		Auth:   d.all("auth"),
		UpdTo:  d.all("upd-to"),
		MntNfy: d.all("mnt-nfy"),
		raw:    d.o,
	}
}

// Person is a contact person object.
type Person struct {
	Common
	Name    string
	NicHdl  types.NICHandle
	Address []string
	Phone   []string
	FaxNo   []string
	Email   []string
	raw     *ast.Object
}

func (p Person) Class() string    { return "person" }
func (p Person) Raw() *ast.Object { return p.raw }

func decodePerson(d *decoder) Person {
	var nh types.NICHandle
	if hs := d.nicHandles("nic-hdl", "object/person-nic-hdl"); len(hs) > 0 {
		nh = hs[0]
	}
	return Person{
		Common:  d.common("person"),
		Name:    d.key("person"),
		NicHdl:  nh,
		Address: d.all("address"),
		Phone:   d.all("phone"),
		FaxNo:   d.all("fax-no"),
		Email:   d.all("e-mail"),
		raw:     d.o,
	}
}

// Role is a contact role object (a team behind a single handle).
type Role struct {
	Common
	Name    string
	NicHdl  types.NICHandle
	Trouble []string
	Address []string
	Phone   []string
	FaxNo   []string
	Email   []string
	raw     *ast.Object
}

func (r Role) Class() string    { return "role" }
func (r Role) Raw() *ast.Object { return r.raw }

func decodeRole(d *decoder) Role {
	var nh types.NICHandle
	if hs := d.nicHandles("nic-hdl", "object/role-nic-hdl"); len(hs) > 0 {
		nh = hs[0]
	}
	return Role{
		Common:  d.common("role"),
		Name:    d.key("role"),
		NicHdl:  nh,
		Trouble: d.all("trouble"),
		Address: d.all("address"),
		Phone:   d.all("phone"),
		FaxNo:   d.all("fax-no"),
		Email:   d.all("e-mail"),
		raw:     d.o,
	}
}

// Route is an IPv4 route object binding a prefix to an originating ASN. A
// non-IPv4 prefix, host bits in the prefix, or a hole outside it is a Warning.
// Inject, Components, AggrBndry, AggrMtd and ExportComps (RFC 2622 §8.1
// aggregation) are kept as raw text.
type Route struct {
	Common
	Prefix      netip.Prefix
	Origin      types.ASN
	MemberOf    []types.SetName
	Holes       []netip.Prefix
	Pingable    []string
	Inject      []string
	Components  string
	AggrBndry   string
	AggrMtd     string
	ExportComps string
	raw         *ast.Object
}

func (r Route) Class() string    { return "route" }
func (r Route) Raw() *ast.Object { return r.raw }

func decodeRoute(d *decoder) Route {
	pfx := d.routePrefix("route", false)
	return Route{
		Common:      d.common("route"),
		Prefix:      pfx,
		Origin:      d.asn("origin", "object/route-origin"),
		MemberOf:    d.setNames("member-of", "object/route-member-of"),
		Holes:       d.holes("route", pfx),
		Pingable:    d.all("pingable"),
		Inject:      d.all("inject"),
		Components:  d.str("components"),
		AggrBndry:   d.str("aggr-bndry"),
		AggrMtd:     d.str("aggr-mtd"),
		ExportComps: d.str("export-comps"),
		raw:         d.o,
	}
}

// Route6 is the IPv6 counterpart of Route (RFC 4012), with the same attributes
// and warnings.
type Route6 struct {
	Common
	Prefix      netip.Prefix
	Origin      types.ASN
	MemberOf    []types.SetName
	Holes       []netip.Prefix
	Pingable    []string
	Inject      []string
	Components  string
	AggrBndry   string
	AggrMtd     string
	ExportComps string
	raw         *ast.Object
}

func (r Route6) Class() string    { return "route6" }
func (r Route6) Raw() *ast.Object { return r.raw }

func decodeRoute6(d *decoder) Route6 {
	pfx := d.routePrefix("route6", true)
	return Route6{
		Common:      d.common("route6"),
		Prefix:      pfx,
		Origin:      d.asn("origin", "object/route6-origin"),
		MemberOf:    d.setNames("member-of", "object/route6-member-of"),
		Holes:       d.holes("route6", pfx),
		Pingable:    d.all("pingable"),
		Inject:      d.all("inject"),
		Components:  d.str("components"),
		AggrBndry:   d.str("aggr-bndry"),
		AggrMtd:     d.str("aggr-mtd"),
		ExportComps: d.str("export-comps"),
		raw:         d.o,
	}
}

// AsSet is an as-set: a named, possibly nested collection of ASNs. MpMembers
// carries the RFC 4012 mp-members: list, which RIPE/IRRd reality admits on
// as-set objects even where strict RFC 4012 does not (see object/profiles.go).
type AsSet struct {
	Common
	Name      types.SetName
	Members   []SetMember
	MpMembers []SetMember
	MbrsByRef []string
	raw       *ast.Object
}

func (s AsSet) Class() string    { return "as-set" }
func (s AsSet) Raw() *ast.Object { return s.raw }

func decodeAsSet(d *decoder) AsSet {
	return AsSet{
		Common:    d.common("as-set"),
		Name:      d.setKey("as-set", "object/as-set-name", types.AsSet),
		Members:   d.members("members", "object/as-set-members", types.AsSet),
		MpMembers: d.members("mp-members", "object/as-set-mp-members", types.AsSet),
		MbrsByRef: d.list("mbrs-by-ref"),
		raw:       d.o,
	}
}

// RouteSet is a route-set: a named collection of prefixes, prefix-ranges, set
// names, and ASNs. MpMembers carries the RFC 4012 mp-members: list.
type RouteSet struct {
	Common
	Name      types.SetName
	Members   []SetMember
	MpMembers []SetMember
	MbrsByRef []string
	raw       *ast.Object
}

func (s RouteSet) Class() string    { return "route-set" }
func (s RouteSet) Raw() *ast.Object { return s.raw }

func decodeRouteSet(d *decoder) RouteSet {
	return RouteSet{
		Common:    d.common("route-set"),
		Name:      d.setKey("route-set", "object/route-set-name", types.RouteSet),
		Members:   d.members("members", "object/route-set-members", types.RouteSet),
		MpMembers: d.members("mp-members", "object/route-set-mp-members", types.RouteSet),
		MbrsByRef: d.list("mbrs-by-ref"),
		raw:       d.o,
	}
}
