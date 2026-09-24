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
	Registry
	AS       types.ASN
	AsName   string
	MemberOf []types.SetName
	Imports  []policy.Import
	Exports  []policy.Export
	Defaults []policy.Default
	// ImportVia and ExportVia are the import-via: and export-via: policies
	// (draft-ietf-grow-rpsl-via; RIPE), in document order. They are kept apart
	// from Imports and Exports: every clause names a peering the routes pass
	// through (PeerAction.Via), and a consumer that ignored it would read a
	// route-server policy as one for a direct peering. The draft resolves
	// overlaps across via and plain policies by specification order; the
	// attributes' order is in Raw.
	ImportVia []policy.Import
	ExportVia []policy.Export
	Status    string
	raw       *ast.Object
}

// Class returns "aut-num".
func (a AutNum) Class() string { return "aut-num" }

// Raw returns the object's lossless source, or nil for one built without it.
func (a AutNum) Raw() *ast.Object { return a.raw }

func decodeAutNum(d *decoder) AutNum {
	an := AutNum{
		Common:   d.common("aut-num"),
		Registry: d.registry("aut-num"),
		AS:       d.asn("aut-num", "object/aut-num-as"),
		AsName:   d.str("as-name"),
		MemberOf: d.memberOf("aut-num", types.ClassAsSet),
		Status:   d.str("status"),
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
		case "import-via":
			var imp policy.Import
			imp, ds = policy.ParseImportVia(a.Value)
			an.ImportVia = append(an.ImportVia, imp)
		case "export-via":
			var exp policy.Export
			exp, ds = policy.ParseExportVia(a.Value)
			an.ExportVia = append(an.ExportVia, exp)
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

// Mntner is a maintainer object. Auth holds the authentication schemes and
// their credentials; nothing here verifies one, which needs cryptography this
// module does not depend on. ReferralBy (RFC 2725) names the maintainer that
// created this one.
type Mntner struct {
	Common
	Registry
	Handle     string
	Auth       []Auth
	UpdTo      []string
	MntNfy     []string
	ReferralBy []string
	raw        *ast.Object
}

// Class returns "mntner".
func (m Mntner) Class() string { return "mntner" }

// Raw returns the object's lossless source, or nil for one built without it.
func (m Mntner) Raw() *ast.Object { return m.raw }

func decodeMntner(d *decoder) Mntner {
	return Mntner{
		Common:     d.common("mntner"),
		Registry:   d.registry("mntner"),
		Handle:     d.key("mntner"),
		Auth:       d.auth("mntner"),
		UpdTo:      d.all("upd-to"),
		MntNfy:     d.all("mnt-nfy"),
		ReferralBy: d.list("referral-by"),
		raw:        d.o,
	}
}

// Person is a contact person object.
type Person struct {
	Common
	Registry
	Name    string
	NicHdl  types.NICHandle
	Address []string
	Phone   []string
	FaxNo   []string
	Email   []string
	Contact []string
	raw     *ast.Object
}

// Class returns "person".
func (p Person) Class() string { return "person" }

// Raw returns the object's lossless source, or nil for one built without it.
func (p Person) Raw() *ast.Object { return p.raw }

func decodePerson(d *decoder) Person {
	var nh types.NICHandle
	if hs := d.nicHandles("nic-hdl", "object/person-nic-hdl"); len(hs) > 0 {
		nh = hs[0]
	}
	return Person{
		Common:   d.common("person"),
		Registry: d.registry("person"),
		Name:     d.key("person"),
		NicHdl:   nh,
		Address:  d.all("address"),
		Phone:    d.all("phone"),
		FaxNo:    d.all("fax-no"),
		Email:    d.all("e-mail"),
		Contact:  d.all("contact"),
		raw:      d.o,
	}
}

// Role is a contact role object (a team behind a single handle).
type Role struct {
	Common
	Registry
	Name         string
	NicHdl       types.NICHandle
	Trouble      []string
	Address      []string
	Phone        []string
	FaxNo        []string
	Email        []string
	Contact      []string
	AbuseMailbox string
	raw          *ast.Object
}

// Class returns "role".
func (r Role) Class() string { return "role" }

// Raw returns the object's lossless source, or nil for one built without it.
func (r Role) Raw() *ast.Object { return r.raw }

func decodeRole(d *decoder) Role {
	var nh types.NICHandle
	if hs := d.nicHandles("nic-hdl", "object/role-nic-hdl"); len(hs) > 0 {
		nh = hs[0]
	}
	return Role{
		Common:       d.common("role"),
		Registry:     d.registry("role"),
		Name:         d.key("role"),
		NicHdl:       nh,
		Trouble:      d.all("trouble"),
		Address:      d.all("address"),
		Phone:        d.all("phone"),
		FaxNo:        d.all("fax-no"),
		Email:        d.all("e-mail"),
		Contact:      d.all("contact"),
		AbuseMailbox: d.str("abuse-mailbox"),
		raw:          d.o,
	}
}

// Route is an IPv4 route object binding a prefix to an originating ASN. A
// non-IPv4 prefix, host bits in the prefix, or a hole outside it is a Warning.
// Inject, Components, AggrBndry, AggrMtd and ExportComps (RFC 2622 §8.1
// aggregation) are kept as raw text.
type Route struct {
	Common
	Registry
	Prefix      netip.Prefix
	Origin      types.ASN
	MemberOf    []types.SetName
	Holes       []netip.Prefix
	Pingable    []netip.Addr
	PingHdl     []types.NICHandle
	Inject      []policy.Inject
	Components  policy.Components
	AggrBndry   policy.ASExpr
	AggrMtd     policy.AggrMtd
	ExportComps policy.Filter
	GeoIdx      []string // geoidx: (IRRd), as written
	RoaURI      string   // roa-uri: (IRRd), as written
	raw         *ast.Object
}

// Class returns "route".
func (r Route) Class() string { return "route" }

// Raw returns the object's lossless source, or nil for one built without it.
func (r Route) Raw() *ast.Object { return r.raw }

func decodeRoute(d *decoder) Route {
	pfx := d.routePrefix("route", false)
	return Route{
		Common:      d.common("route"),
		Registry:    d.registry("route"),
		Prefix:      pfx,
		Origin:      d.asn("origin", "object/route-origin"),
		MemberOf:    d.memberOf("route", types.ClassRouteSet),
		Holes:       d.holes("route", pfx),
		Pingable:    d.pingable("route"),
		PingHdl:     d.nicHandles("ping-hdl", "object/route-ping-hdl"),
		Inject:      d.injects("route"),
		Components:  d.components("route"),
		AggrBndry:   d.asExpr("route", "aggr-bndry"),
		AggrMtd:     d.aggrMtd("route"),
		ExportComps: d.filterAttr("route", "export-comps"),
		GeoIdx:      d.all("geoidx"),
		RoaURI:      d.str("roa-uri"),
		raw:         d.o,
	}
}

// Route6 is the IPv6 counterpart of Route (RFC 4012), with the same attributes
// and warnings.
type Route6 struct {
	Common
	Registry
	Prefix      netip.Prefix
	Origin      types.ASN
	MemberOf    []types.SetName
	Holes       []netip.Prefix
	Pingable    []netip.Addr
	PingHdl     []types.NICHandle
	Inject      []policy.Inject
	Components  policy.Components
	AggrBndry   policy.ASExpr
	AggrMtd     policy.AggrMtd
	ExportComps policy.Filter
	GeoIdx      []string // geoidx: (IRRd), as written
	RoaURI      string   // roa-uri: (IRRd), as written
	raw         *ast.Object
}

// Class returns "route6".
func (r Route6) Class() string { return "route6" }

// Raw returns the object's lossless source, or nil for one built without it.
func (r Route6) Raw() *ast.Object { return r.raw }

func decodeRoute6(d *decoder) Route6 {
	pfx := d.routePrefix("route6", true)
	return Route6{
		Common:      d.common("route6"),
		Registry:    d.registry("route6"),
		Prefix:      pfx,
		Origin:      d.asn("origin", "object/route6-origin"),
		MemberOf:    d.memberOf("route6", types.ClassRouteSet),
		Holes:       d.holes("route6", pfx),
		Pingable:    d.pingable("route6"),
		PingHdl:     d.nicHandles("ping-hdl", "object/route6-ping-hdl"),
		Inject:      d.injects("route6"),
		Components:  d.components("route6"),
		AggrBndry:   d.asExpr("route6", "aggr-bndry"),
		AggrMtd:     d.aggrMtd("route6"),
		ExportComps: d.filterAttr("route6", "export-comps"),
		GeoIdx:      d.all("geoidx"),
		RoaURI:      d.str("roa-uri"),
		raw:         d.o,
	}
}

// AsSet is an as-set: a named, possibly nested collection of ASNs. MpMembers
// carries mp-members: values. RFC 4012 defines mp-members only for route-set
// and rtr-set and RIPE's template has none on as-set, so both profiles flag
// it, but it is still read so that a set from an IRR that accepts it expands in
// full.
type AsSet struct {
	Common
	Registry
	Name      types.SetName
	Members   []SetMember
	MpMembers []SetMember
	MbrsByRef []string
	raw       *ast.Object
}

// Class returns "as-set".
func (s AsSet) Class() string { return "as-set" }

// Raw returns the object's lossless source, or nil for one built without it.
func (s AsSet) Raw() *ast.Object { return s.raw }

func decodeAsSet(d *decoder) AsSet {
	return AsSet{
		Common:    d.common("as-set"),
		Registry:  d.registry("as-set"),
		Name:      d.setKey("as-set", "object/as-set-name", types.ClassAsSet),
		Members:   d.members("members", "object/as-set-members", types.ClassAsSet),
		MpMembers: d.members("mp-members", "object/as-set-mp-members", types.ClassAsSet),
		MbrsByRef: d.list("mbrs-by-ref"),
		raw:       d.o,
	}
}

// RouteSet is a route-set: a named collection of prefixes, prefix-ranges, set
// names, and ASNs. MpMembers carries the RFC 4012 mp-members: list.
type RouteSet struct {
	Common
	Registry
	Name      types.SetName
	Members   []SetMember
	MpMembers []SetMember
	MbrsByRef []string
	raw       *ast.Object
}

// Class returns "route-set".
func (s RouteSet) Class() string { return "route-set" }

// Raw returns the object's lossless source, or nil for one built without it.
func (s RouteSet) Raw() *ast.Object { return s.raw }

func decodeRouteSet(d *decoder) RouteSet {
	return RouteSet{
		Common:    d.common("route-set"),
		Registry:  d.registry("route-set"),
		Name:      d.setKey("route-set", "object/route-set-name", types.ClassRouteSet),
		Members:   d.members("members", "object/route-set-members", types.ClassRouteSet),
		MpMembers: d.members("mp-members", "object/route-set-mp-members", types.ClassRouteSet),
		MbrsByRef: d.list("mbrs-by-ref"),
		raw:       d.o,
	}
}
