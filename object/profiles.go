package object

// This file is the data-driven class/attribute dictionary (design §10, §13).
// RFCStrict follows the RFC 2622, 2725, 2726 and 4012 attribute tables —
// including the RFC 2622 §3.1 attributes common to every class — and RIPE the
// RIPE Database's templates; both flag any other attribute. Adding a class or
// attribute is a data edit here; TestEveryAttributeLandsInItsOwnField then
// requires the class's typed decoder (if it has one) to surface it.

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

// rfcClasses is the RFC table: RFC 2622, with RFC 2725 (as-block, referral-by,
// mnt-routes, mnt-lower), RFC 2726 (key-cert) and RFC 4012 (route6, inet6num,
// mp-*). inetnum, irt, domain and organisation have no RFC table; they carry
// the RFC common attributes plus their RIPE-defined ones.
func rfcClasses() map[string]ClassSpec {
	c := map[string]ClassSpec{}
	set := func(name string, oneOf [][]string, entries ...attr) {
		c[name] = spec(false, oneOf, with(rfcCommon(), entries...)...)
	}
	route := func(key string) []attr {
		return []attr{reqS(key), reqS("origin"), opt("member-of"), opt("inject"),
			optS("components"), optS("aggr-bndry"), optS("aggr-mtd"), optS("export-comps"), opt("holes"),
			opt("mnt-lower"), opt("mnt-routes")}
	}
	set("aut-num", nil, reqS("aut-num"), reqS("as-name"), req("admin-c"), opt("member-of"),
		opt("import"), opt("export"), opt("default"), opt("mp-import"), opt("mp-export"), opt("mp-default"),
		opt("mnt-routes"), opt("mnt-lower"))
	set("mntner", nil, reqS("mntner"), req("auth"), req("upd-to"), opt("mnt-nfy"), req("referral-by"))
	set("person", nil, reqS("person"), reqS("nic-hdl"), req("address"), req("phone"), opt("fax-no"), req("e-mail"))
	set("role", nil, reqS("role"), reqS("nic-hdl"), opt("trouble"), req("address"), req("phone"),
		opt("fax-no"), req("e-mail"))
	set("route", nil, route("route")...)
	set("route6", nil, route("route6")...)
	set("as-set", nil, reqS("as-set"), opt("members"), opt("mbrs-by-ref"))
	set("route-set", nil, reqS("route-set"), opt("members"), opt("mp-members"), opt("mbrs-by-ref"))
	set("rtr-set", nil, reqS("rtr-set"), opt("members"), opt("mp-members"), opt("mbrs-by-ref"))
	set("peering-set", peeringOneOf, reqS("peering-set"), opt("peering"), opt("mp-peering"))
	set("filter-set", filterOneOf, reqS("filter-set"), optS("filter"), optS("mp-filter"))
	set("inet-rtr", nil, reqS("inet-rtr"), opt("alias"), reqS("local-as"), req("ifaddr"), opt("interface"),
		opt("peer"), opt("mp-peer"), opt("member-of"))
	set("dictionary", nil, reqS("dictionary"), opt("rp-attribute"), opt("typedef"), opt("protocol"))
	set("inetnum", nil, reqS("inetnum"), req("netname"), req("country"), req("status"), req("admin-c"),
		opt("mnt-lower"), opt("mnt-routes"))
	set("inet6num", nil, reqS("inet6num"), reqS("netname"), req("descr"), req("country"), req("admin-c"),
		opt("mnt-lower"), opt("mnt-routes"))
	set("as-block", nil, reqS("as-block"), opt("descr"), req("admin-c"), opt("mnt-lower"))
	set("irt", nil, reqS("irt"), req("address"), req("e-mail"), req("auth"))
	set("domain", nil, reqS("domain"), req("nserver"), opt("zone-c"))
	set("organisation", nil, reqS("organisation"), req("org-name"), reqS("org-type"), opt("address"))
	// RFC 2726 §2.1 defines key-cert whole: it has no descr, admin-c or tech-c.
	c["key-cert"] = spec(false, nil, reqS("key-cert"), optS("method"), opt("owner"), optS("fingerpr"),
		reqS("certif"), opt("remarks"), opt("notify"), req("mnt-by"), req("changed"), reqS("source"))
	return c
}

// ripeClasses is the RIPE Database table, transcribed from the RIPE templates
// (whois -t <class>; see testdata/ripe-templates): "mandatory" attributes are
// required, "optional", "conditional" and "generated" ones allowed, and
// "single" ones may appear once. Attributes outside a template are flagged.
// TestRIPEProfileMatchesTemplates keeps the two in step.
func ripeClasses() map[string]ClassSpec {
	c := map[string]ClassSpec{}
	set := func(name string, oneOf [][]string, entries ...attr) {
		c[name] = spec(false, oneOf, entries...)
	}
	set("as-block", nil,
		reqS("as-block"), opt("descr"), opt("remarks"), opt("org"), opt("notify"), req("mnt-by"),
		opt("mnt-lower"), optS("created"), optS("last-modified"), reqS("source"))
	set("as-set", nil,
		reqS("as-set"), opt("descr"), opt("members"), opt("mbrs-by-ref"), opt("remarks"), opt("org"),
		req("tech-c"), req("admin-c"), opt("notify"), req("mnt-by"), opt("mnt-lower"), optS("created"),
		optS("last-modified"), reqS("source"))
	set("aut-num", nil,
		reqS("aut-num"), reqS("as-name"), opt("descr"), opt("member-of"), opt("import-via"),
		opt("import"), opt("mp-import"), opt("export-via"), opt("export"), opt("mp-export"),
		opt("default"), opt("mp-default"), opt("remarks"), optS("org"), optS("sponsoring-org"),
		req("admin-c"), req("tech-c"), optS("abuse-c"), optS("status"), opt("notify"), req("mnt-by"),
		optS("created"), optS("last-modified"), reqS("source"))
	set("domain", nil,
		reqS("domain"), opt("descr"), opt("org"), req("admin-c"), req("tech-c"), req("zone-c"),
		req("nserver"), opt("ds-rdata"), opt("remarks"), opt("notify"), req("mnt-by"), optS("created"),
		optS("last-modified"), reqS("source"))
	set("filter-set", filterOneOf,
		reqS("filter-set"), opt("descr"), optS("filter"), optS("mp-filter"), opt("remarks"), opt("org"),
		req("tech-c"), req("admin-c"), opt("notify"), req("mnt-by"), opt("mnt-lower"), optS("created"),
		optS("last-modified"), reqS("source"))
	set("inet-rtr", nil,
		reqS("inet-rtr"), opt("descr"), opt("alias"), reqS("local-as"), req("ifaddr"), opt("interface"),
		opt("peer"), opt("mp-peer"), opt("member-of"), opt("remarks"), opt("org"), req("admin-c"),
		req("tech-c"), opt("notify"), req("mnt-by"), optS("created"), optS("last-modified"),
		reqS("source"))
	set("inet6num", nil,
		reqS("inet6num"), reqS("netname"), opt("descr"), req("country"), optS("geofeed"), optS("geoloc"),
		optS("prefixlen"), opt("language"), optS("org"), optS("sponsoring-org"), req("admin-c"),
		req("tech-c"), optS("abuse-c"), reqS("status"), optS("assignment-size"), opt("remarks"),
		opt("notify"), req("mnt-by"), opt("mnt-lower"), opt("mnt-routes"), opt("mnt-domains"), opt("mnt-irt"),
		optS("created"), optS("last-modified"), reqS("source"))
	set("inetnum", nil,
		reqS("inetnum"), reqS("netname"), opt("descr"), req("country"), optS("geofeed"), optS("geoloc"),
		optS("prefixlen"), opt("language"), optS("org"), optS("sponsoring-org"), req("admin-c"),
		req("tech-c"), optS("abuse-c"), reqS("status"), optS("assignment-size"), opt("remarks"),
		opt("notify"), req("mnt-by"), opt("mnt-lower"), opt("mnt-domains"), opt("mnt-routes"), opt("mnt-irt"),
		optS("created"), optS("last-modified"), reqS("source"))
	set("irt", nil,
		reqS("irt"), req("address"), opt("phone"), opt("fax-no"), req("e-mail"), opt("signature"),
		opt("contact"), opt("encryption"), opt("org"), req("admin-c"), req("tech-c"), req("auth"),
		opt("remarks"), opt("irt-nfy"), opt("notify"), req("mnt-by"), opt("mnt-ref"), optS("created"),
		optS("last-modified"), reqS("source"))
	set("key-cert", nil,
		reqS("key-cert"), optS("method"), opt("owner"), optS("fingerpr"), req("certif"), opt("org"),
		opt("remarks"), opt("notify"), opt("admin-c"), opt("tech-c"), req("mnt-by"), optS("created"),
		optS("last-modified"), reqS("source"))
	set("mntner", nil,
		reqS("mntner"), opt("descr"), opt("org"), req("admin-c"), opt("tech-c"), req("upd-to"),
		opt("mnt-nfy"), req("auth"), opt("remarks"), opt("notify"), req("mnt-by"), opt("mnt-ref"),
		optS("created"), optS("last-modified"), reqS("source"))
	set("organisation", nil,
		reqS("organisation"), reqS("org-name"), reqS("org-type"), opt("descr"), opt("remarks"),
		req("address"), optS("country"), opt("phone"), opt("fax-no"), req("e-mail"), opt("contact"),
		optS("geoloc"), opt("language"), optS("reg-nr"), opt("org"), opt("admin-c"), opt("tech-c"),
		optS("abuse-c"), opt("ref-nfy"), req("mnt-ref"), opt("notify"), req("mnt-by"), optS("created"),
		optS("last-modified"), reqS("source"))
	set("peering-set", peeringOneOf,
		reqS("peering-set"), opt("descr"), opt("peering"), opt("mp-peering"), opt("remarks"), opt("org"),
		req("tech-c"), req("admin-c"), opt("notify"), req("mnt-by"), opt("mnt-lower"), optS("created"),
		optS("last-modified"), reqS("source"))
	set("person", nil,
		reqS("person"), opt("address"), opt("phone"), opt("fax-no"), req("e-mail"), opt("contact"),
		opt("org"), reqS("nic-hdl"), opt("remarks"), opt("notify"), req("mnt-by"), opt("mnt-ref"),
		optS("created"), optS("last-modified"), reqS("source"))
	set("poem", nil,
		reqS("poem"), opt("descr"), reqS("form"), req("text"), opt("author"), opt("remarks"),
		opt("notify"), reqS("mnt-by"), optS("created"), optS("last-modified"), reqS("source"))
	set("poetic-form", nil,
		reqS("poetic-form"), opt("descr"), req("admin-c"), opt("remarks"), opt("notify"), reqS("mnt-by"),
		optS("created"), optS("last-modified"), reqS("source"))
	set("role", nil,
		reqS("role"), opt("address"), opt("phone"), opt("fax-no"), req("e-mail"), opt("contact"),
		opt("org"), opt("admin-c"), opt("tech-c"), reqS("nic-hdl"), opt("remarks"), opt("notify"),
		optS("abuse-mailbox"), req("mnt-by"), opt("mnt-ref"), optS("created"), optS("last-modified"),
		reqS("source"))
	set("route-set", nil,
		reqS("route-set"), opt("descr"), opt("members"), opt("mp-members"), opt("mbrs-by-ref"),
		opt("remarks"), opt("org"), req("tech-c"), req("admin-c"), opt("notify"), req("mnt-by"),
		opt("mnt-lower"), optS("created"), optS("last-modified"), reqS("source"))
	set("route", nil,
		reqS("route"), opt("descr"), reqS("origin"), opt("pingable"), opt("ping-hdl"), opt("holes"),
		opt("org"), opt("member-of"), opt("inject"), optS("aggr-mtd"), optS("aggr-bndry"),
		optS("export-comps"), optS("components"), opt("remarks"), opt("notify"), opt("mnt-lower"),
		opt("mnt-routes"), req("mnt-by"), optS("created"), optS("last-modified"), reqS("source"))
	set("route6", nil,
		reqS("route6"), opt("descr"), reqS("origin"), opt("pingable"), opt("ping-hdl"), opt("holes"),
		opt("org"), opt("member-of"), opt("inject"), optS("aggr-mtd"), optS("aggr-bndry"),
		optS("export-comps"), optS("components"), opt("remarks"), opt("notify"), opt("mnt-lower"),
		opt("mnt-routes"), req("mnt-by"), optS("created"), optS("last-modified"), reqS("source"))
	set("rtr-set", nil,
		reqS("rtr-set"), opt("descr"), opt("members"), opt("mp-members"), opt("mbrs-by-ref"),
		opt("remarks"), opt("org"), req("tech-c"), req("admin-c"), opt("notify"), req("mnt-by"),
		opt("mnt-lower"), optS("created"), optS("last-modified"), reqS("source"))
	return c
}

// RFCStrict admits only the attributes RFC 2622, 2725, 2726 and 4012 define for
// each class, including the RFC 2622 §3.1 common attributes (descr, tech-c,
// mnt-by, changed and source are mandatory on every class but as-block and
// key-cert, which RFC 2725 and RFC 2726 define whole); anything else — e.g.
// RIPE's created: — is flagged dict/unknown-attr.
var RFCStrict = Profile{name: "RFC-strict", classes: rfcClasses()}

// RIPE mirrors the RIPE Database: each class is exactly RIPE's template —
// required attributes, cardinality, and no attributes outside it (a misspelled
// attribute is dict/unknown-attr). Legacy attributes RIPE no longer has, such
// as changed:, are flagged too.
var RIPE = Profile{name: "RIPE", classes: ripeClasses()}
