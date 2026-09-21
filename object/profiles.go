package object

// This file is the data-driven class/attribute dictionary (design §10, §13).
// RFCStrict follows the RFC 2622/4012 attribute tables — including the §3.1
// attributes common to every class — and rejects anything else. RIPE mirrors
// the RIPE Database: RIPE's own required attributes, tolerating its many
// extensions (org:, created:, …) via AllowUnknown. Adding a class or attribute
// is a data edit here; TestDecoderSurfacesEveryProfiledAttribute then requires
// the class's typed decoder (if it has one) to surface it.

// attr is a compact dictionary entry used only to build ClassSpecs below.
type attr struct {
	name   string
	req    bool
	single bool
}

func req(n string) attr  { return attr{n, true, false} }
func reqS(n string) attr { return attr{n, true, true} }
func opt(n string) attr  { return attr{n, false, false} }
func optS(n string) attr { return attr{n, false, true} }

// spec builds a ClassSpec. Later entries override earlier ones with the same
// name, so class tables can refine the common attributes.
func spec(allowUnknown bool, oneOf [][]string, entries ...attr) ClassSpec {
	m := make(map[string]AttrSpec, len(entries))
	for _, e := range entries {
		m[e.name] = AttrSpec{Required: e.req, Single: e.single}
	}
	return ClassSpec{Attrs: m, AllowUnknown: allowUnknown, OneOf: oneOf}
}

func with(entries []attr, more ...attr) []attr {
	return append(append([]attr{}, entries...), more...)
}

// RFC 4012 lets a peering-set carry only mp-peering and a filter-set only
// mp-filter, so each pair is "at least one of".
var (
	peeringOneOf = [][]string{{"peering", "mp-peering"}}
	filterOneOf  = [][]string{{"filter", "mp-filter"}}
)

// rfcCommon is RFC 2622 §3.1: the attributes of every class. admin-c is
// mandatory only for aut-num.
func rfcCommon() []attr {
	return []attr{reqS("descr"), req("tech-c"), opt("admin-c"), opt("remarks"),
		opt("notify"), req("mnt-by"), req("changed"), reqS("source")}
}

// rfcClasses is the RFC 2622 / RFC 4012 table. inetnum, inet6num, as-block,
// irt, domain and organisation are not RFC classes; they carry the RFC common
// attributes plus their RIPE-defined ones.
func rfcClasses() map[string]ClassSpec {
	c := map[string]ClassSpec{}
	set := func(name string, oneOf [][]string, entries ...attr) {
		c[name] = spec(false, oneOf, with(rfcCommon(), entries...)...)
	}
	route := func(key string) []attr {
		return []attr{reqS(key), reqS("origin"), opt("member-of"), opt("inject"),
			optS("components"), optS("aggr-bndry"), optS("aggr-mtd"), optS("export-comps"), opt("holes")}
	}
	set("aut-num", nil, reqS("aut-num"), reqS("as-name"), req("admin-c"), opt("member-of"),
		opt("import"), opt("export"), opt("default"), opt("mp-import"), opt("mp-export"), opt("mp-default"))
	set("mntner", nil, reqS("mntner"), req("auth"), req("upd-to"), opt("mnt-nfy"))
	set("person", nil, reqS("person"), reqS("nic-hdl"), req("address"), req("phone"), opt("fax-no"), req("e-mail"))
	set("role", nil, reqS("role"), reqS("nic-hdl"), opt("trouble"), req("address"), req("phone"),
		opt("fax-no"), req("e-mail"))
	set("route", nil, route("route")...)
	set("route6", nil, route("route6")...)
	set("as-set", nil, reqS("as-set"), opt("members"), opt("mp-members"), opt("mbrs-by-ref"))
	set("route-set", nil, reqS("route-set"), opt("members"), opt("mp-members"), opt("mbrs-by-ref"))
	set("rtr-set", nil, reqS("rtr-set"), opt("members"), opt("mp-members"), opt("mbrs-by-ref"))
	set("peering-set", peeringOneOf, reqS("peering-set"), opt("peering"), opt("mp-peering"))
	set("filter-set", filterOneOf, reqS("filter-set"), optS("filter"), optS("mp-filter"))
	set("inet-rtr", nil, reqS("inet-rtr"), opt("alias"), reqS("local-as"), req("ifaddr"), opt("interface"),
		opt("peer"), opt("mp-peer"), opt("member-of"))
	set("dictionary", nil, reqS("dictionary"), opt("rp-attribute"), opt("typedef"), opt("protocol"))
	set("inetnum", nil, reqS("inetnum"), req("netname"), req("country"), req("status"), req("admin-c"))
	set("inet6num", nil, reqS("inet6num"), req("netname"), req("country"), req("status"), req("admin-c"))
	set("as-block", nil, reqS("as-block"))
	set("irt", nil, reqS("irt"), req("address"), req("e-mail"), req("auth"))
	set("domain", nil, reqS("domain"), req("nserver"), opt("zone-c"))
	set("organisation", nil, reqS("organisation"), req("org-name"), reqS("org-type"), opt("address"))
	return c
}

// ripeCommon is what every RIPE class requires or commonly carries; RIPE's
// generated and extension attributes are admitted by AllowUnknown.
func ripeCommon() []attr {
	return []attr{req("mnt-by"), reqS("source"), opt("descr"), opt("remarks"), opt("notify")}
}

// ripeClasses is the RIPE Database table.
func ripeClasses() map[string]ClassSpec {
	c := map[string]ClassSpec{}
	set := func(name string, oneOf [][]string, entries ...attr) {
		c[name] = spec(true, oneOf, with(ripeCommon(), entries...)...)
	}
	route := func(key string) []attr {
		return []attr{reqS(key), reqS("origin"), opt("holes"), opt("member-of"), opt("pingable")}
	}
	set("aut-num", nil, reqS("aut-num"), reqS("as-name"), req("admin-c"), req("tech-c"), opt("member-of"),
		opt("import"), opt("export"), opt("default"), opt("mp-import"), opt("mp-export"), opt("mp-default"))
	set("mntner", nil, reqS("mntner"), req("admin-c"), opt("tech-c"), opt("upd-to"), opt("mnt-nfy"), req("auth"))
	set("person", nil, reqS("person"), reqS("nic-hdl"), req("address"), opt("phone"), opt("fax-no"), opt("e-mail"))
	set("role", nil, reqS("role"), reqS("nic-hdl"), req("address"), opt("phone"), opt("fax-no"),
		opt("e-mail"), opt("admin-c"), opt("tech-c"))
	set("route", nil, route("route")...)
	set("route6", nil, route("route6")...)
	set("as-set", nil, reqS("as-set"), opt("members"), opt("mp-members"), opt("mbrs-by-ref"))
	set("route-set", nil, reqS("route-set"), opt("members"), opt("mp-members"), opt("mbrs-by-ref"))
	set("rtr-set", nil, reqS("rtr-set"), opt("members"), opt("mp-members"), opt("mbrs-by-ref"))
	set("peering-set", peeringOneOf, reqS("peering-set"), opt("peering"), opt("mp-peering"))
	set("filter-set", filterOneOf, reqS("filter-set"), optS("filter"), optS("mp-filter"))
	set("inet-rtr", nil, reqS("inet-rtr"), opt("alias"), reqS("local-as"), req("ifaddr"), opt("interface"),
		opt("peer"), opt("mp-peer"), opt("member-of"))
	set("inetnum", nil, reqS("inetnum"), req("netname"), req("country"), req("status"), req("admin-c"), req("tech-c"))
	set("inet6num", nil, reqS("inet6num"), req("netname"), req("country"), req("status"), req("admin-c"), req("tech-c"))
	set("as-block", nil, reqS("as-block"))
	set("irt", nil, reqS("irt"), req("address"), req("e-mail"), req("auth"), opt("admin-c"), opt("tech-c"))
	set("domain", nil, reqS("domain"), req("nserver"), opt("admin-c"), opt("tech-c"), opt("zone-c"))
	set("organisation", nil, reqS("organisation"), req("org-name"), reqS("org-type"), opt("address"),
		opt("admin-c"), opt("tech-c"))
	// RIPE classes without a typed decoder (they decode to Generic).
	set("key-cert", nil, reqS("key-cert"), req("certif"), opt("admin-c"), opt("tech-c"))
	set("poem", nil, reqS("poem"), reqS("form"), req("text"), opt("author"))
	set("poetic-form", nil, reqS("poetic-form"), req("admin-c"))
	return c
}

// RFCStrict admits only the attributes RFC 2622/4012 define for each class,
// including the §3.1 common attributes (descr, tech-c, mnt-by, changed and
// source are mandatory everywhere); anything else — e.g. RIPE's created: — is
// flagged dict/unknown-attr.
var RFCStrict = Profile{Name: "RFC-strict", Classes: rfcClasses()}

// RIPE mirrors the RIPE Database: it enforces RIPE's required attributes and
// cardinality but tolerates RIPE-only attributes (org:, created:,
// last-modified:, …) and legacy ones such as changed:.
var RIPE = Profile{Name: "RIPE", Classes: ripeClasses()}
