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
	AS       types.ASN
	AsName   string
	Imports  []policy.Import
	Exports  []policy.Export
	Defaults []policy.Default
	AdminC   []types.NICHandle
	TechC    []types.NICHandle
	MntBy    []string
	Source   string
	raw      *ast.Object
}

func (a AutNum) Class() string    { return "aut-num" }
func (a AutNum) Raw() *ast.Object { return a.raw }

func decodeAutNum(d *decoder) AutNum {
	an := AutNum{
		AS:     d.asn("aut-num", "object/aut-num-as"),
		AsName: d.str("as-name"),
		AdminC: d.nicHandles("admin-c", "object/aut-num-admin-c"),
		TechC:  d.nicHandles("tech-c", "object/aut-num-tech-c"),
		MntBy:  d.all("mnt-by"),
		Source: d.str("source"),
		raw:    d.o,
	}
	// import: and mp-import: are unioned into Imports (design §6); the AFIs field
	// distinguishes legacy from RFC 4012 mp entries. Likewise for export.
	for _, name := range []string{"import", "mp-import"} {
		for _, a := range d.o.GetAll(name) {
			imp, ds := policy.ParseImport(a.Value)
			an.Imports = append(an.Imports, imp)
			d.rebase(a, ds)
		}
	}
	for _, name := range []string{"export", "mp-export"} {
		for _, a := range d.o.GetAll(name) {
			exp, ds := policy.ParseExport(a.Value)
			an.Exports = append(an.Exports, exp)
			d.rebase(a, ds)
		}
	}
	for _, name := range []string{"default", "mp-default"} {
		for _, a := range d.o.GetAll(name) {
			def, ds := policy.ParseDefault(a.Value)
			an.Defaults = append(an.Defaults, def)
			d.rebase(a, ds)
		}
	}
	return an
}

// Mntner is a maintainer object. Auth lines are kept raw and uninterpreted.
type Mntner struct {
	Handle string
	Descr  []string
	AdminC []types.NICHandle
	Auth   []string
	MntBy  []string
	Source string
	raw    *ast.Object
}

func (m Mntner) Class() string    { return "mntner" }
func (m Mntner) Raw() *ast.Object { return m.raw }

func decodeMntner(d *decoder) Mntner {
	return Mntner{
		Handle: d.str("mntner"),
		Descr:  d.all("descr"),
		AdminC: d.nicHandles("admin-c", "object/mntner-admin-c"),
		Auth:   d.all("auth"),
		MntBy:  d.all("mnt-by"),
		Source: d.str("source"),
		raw:    d.o,
	}
}

// Person is a contact person object.
type Person struct {
	Name    string
	NicHdl  types.NICHandle
	Address []string
	Phone   []string
	Email   []string
	MntBy   []string
	Source  string
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
		Name:    d.str("person"),
		NicHdl:  nh,
		Address: d.all("address"),
		Phone:   d.all("phone"),
		Email:   d.all("e-mail"),
		MntBy:   d.all("mnt-by"),
		Source:  d.str("source"),
		raw:     d.o,
	}
}

// Role is a contact role object (a team behind a single handle).
type Role struct {
	Name    string
	NicHdl  types.NICHandle
	Address []string
	Email   []string
	AdminC  []types.NICHandle
	TechC   []types.NICHandle
	MntBy   []string
	Source  string
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
		Name:    d.str("role"),
		NicHdl:  nh,
		Address: d.all("address"),
		Email:   d.all("e-mail"),
		AdminC:  d.nicHandles("admin-c", "object/role-admin-c"),
		TechC:   d.nicHandles("tech-c", "object/role-tech-c"),
		MntBy:   d.all("mnt-by"),
		Source:  d.str("source"),
		raw:     d.o,
	}
}

// Route is an IPv4 route object binding a prefix to an originating ASN.
type Route struct {
	Prefix   netip.Prefix
	Origin   types.ASN
	MemberOf []types.SetName
	Holes    []netip.Prefix
	MntBy    []string
	Source   string
	raw      *ast.Object
}

func (r Route) Class() string    { return "route" }
func (r Route) Raw() *ast.Object { return r.raw }

func decodeRoute(d *decoder) Route {
	return Route{
		Prefix:   d.prefix("route", "object/route-prefix"),
		Origin:   d.asn("origin", "object/route-origin"),
		MemberOf: d.setNames("member-of", "object/route-member-of"),
		Holes:    d.prefixes("holes", "object/route-holes"),
		MntBy:    d.all("mnt-by"),
		Source:   d.str("source"),
		raw:      d.o,
	}
}

// Route6 is the IPv6 counterpart of Route. A non-IPv6 prefix is a Warning, not
// an Error: the object still decodes.
type Route6 struct {
	Prefix   netip.Prefix
	Origin   types.ASN
	MemberOf []types.SetName
	Holes    []netip.Prefix
	MntBy    []string
	Source   string
	raw      *ast.Object
}

func (r Route6) Class() string    { return "route6" }
func (r Route6) Raw() *ast.Object { return r.raw }

func decodeRoute6(d *decoder) Route6 {
	pfx := d.prefix("route6", "object/route6-prefix")
	if pfx.IsValid() && !pfx.Addr().Is6() {
		if a, ok := d.o.GetFirst("route6"); ok {
			d.warnf(a, "object/route6-afi", "route6 prefix is not IPv6")
		}
	}
	return Route6{
		Prefix:   pfx,
		Origin:   d.asn("origin", "object/route6-origin"),
		MemberOf: d.setNames("member-of", "object/route6-member-of"),
		Holes:    d.prefixes("holes", "object/route6-holes"),
		MntBy:    d.all("mnt-by"),
		Source:   d.str("source"),
		raw:      d.o,
	}
}

// AsSet is an as-set: a named, possibly nested collection of ASNs. MpMembers
// carries the RFC 4012 mp-members: list, which RIPE/IRRd reality admits on
// as-set objects even where strict RFC 4012 does not (see object/profiles.go).
type AsSet struct {
	Name      types.SetName
	Members   []SetMember
	MpMembers []SetMember
	MbrsByRef []string
	MntBy     []string
	Source    string
	raw       *ast.Object
}

func (s AsSet) Class() string    { return "as-set" }
func (s AsSet) Raw() *ast.Object { return s.raw }

func decodeAsSet(d *decoder) AsSet {
	var name types.SetName
	if a, ok := d.o.GetFirst("as-set"); ok {
		if n, err := types.ParseSetName(a.Value); err == nil {
			name = n
		} else {
			d.errf(a, "object/as-set-name", err.Error())
		}
	}
	return AsSet{
		Name:      name,
		Members:   d.members("members", "object/as-set-members", false, types.AsSet),
		MpMembers: d.members("mp-members", "object/as-set-mp-members", false, types.AsSet),
		MbrsByRef: d.all("mbrs-by-ref"),
		MntBy:     d.all("mnt-by"),
		Source:    d.str("source"),
		raw:       d.o,
	}
}

// RouteSet is a route-set: a named collection of prefixes, prefix-ranges, set
// names, and ASNs. MpMembers carries the RFC 4012 mp-members: list.
type RouteSet struct {
	Name      types.SetName
	Members   []SetMember
	MpMembers []SetMember
	MbrsByRef []string
	MntBy     []string
	Source    string
	raw       *ast.Object
}

func (s RouteSet) Class() string    { return "route-set" }
func (s RouteSet) Raw() *ast.Object { return s.raw }

func decodeRouteSet(d *decoder) RouteSet {
	var name types.SetName
	if a, ok := d.o.GetFirst("route-set"); ok {
		if n, err := types.ParseSetName(a.Value); err == nil {
			name = n
		} else {
			d.errf(a, "object/route-set-name", err.Error())
		}
	}
	return RouteSet{
		Name:      name,
		Members:   d.members("members", "object/route-set-members", true, types.RouteSet),
		MpMembers: d.members("mp-members", "object/route-set-mp-members", true, types.RouteSet),
		MbrsByRef: d.all("mbrs-by-ref"),
		MntBy:     d.all("mnt-by"),
		Source:    d.str("source"),
		raw:       d.o,
	}
}
