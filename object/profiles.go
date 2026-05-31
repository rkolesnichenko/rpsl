package object

// This file is the data-driven class/attribute dictionary (design §10, §13). The
// RFC-strict profile lists the attributes RFC 2622/2650/4012 define per class and
// rejects anything else; the RIPE profile reuses the same required/cardinality
// rules but tolerates RIPE's many extensions (org:, created:, changed:, …) via
// AllowUnknown. Adding a class or attribute is a one-line data edit here.

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

func classSpec(allowUnknown bool, entries ...attr) ClassSpec {
	m := make(map[string]AttrSpec, len(entries))
	for _, e := range entries {
		m[e.name] = AttrSpec{Required: e.req, Single: e.single}
	}
	return ClassSpec{Attrs: m, AllowUnknown: allowUnknown}
}

// own is the common ownership/provenance tail shared by every class.
func own() []attr {
	return []attr{req("mnt-by"), reqS("source"), opt("remarks")}
}

func with(entries []attr, more ...attr) []attr {
	return append(append([]attr{}, entries...), more...)
}

// rfcClasses builds the strict (RFC-only) class table. The RIPE table is derived
// from it by relaxing AllowUnknown (see ripeClasses).
func rfcClasses() map[string]ClassSpec {
	c := map[string]ClassSpec{}
	set := func(name string, entries ...attr) { c[name] = classSpec(false, entries...) }

	set("aut-num", with(own(),
		reqS("aut-num"), reqS("as-name"), opt("descr"),
		opt("import"), opt("export"), opt("default"),
		opt("mp-import"), opt("mp-export"), opt("mp-default"),
		req("admin-c"), req("tech-c"), opt("member-of"))...)

	set("mntner", with(own(),
		reqS("mntner"), opt("descr"), req("admin-c"), opt("tech-c"),
		opt("upd-to"), opt("mnt-nfy"), req("auth"))...)

	set("person", with(own(),
		reqS("person"), reqS("nic-hdl"), req("address"), opt("phone"),
		opt("fax-no"), opt("e-mail"))...)

	set("role", with(own(),
		reqS("role"), reqS("nic-hdl"), req("address"), opt("phone"),
		opt("e-mail"), opt("admin-c"), opt("tech-c"))...)

	set("route", with(own(),
		reqS("route"), reqS("origin"), opt("descr"), opt("holes"),
		opt("member-of"), opt("pingable"))...)

	set("route6", with(own(),
		reqS("route6"), reqS("origin"), opt("descr"), opt("holes"),
		opt("member-of"), opt("pingable"))...)

	set("as-set", with(own(),
		reqS("as-set"), opt("descr"), opt("members"), opt("mp-members"),
		opt("mbrs-by-ref"))...)

	set("route-set", with(own(),
		reqS("route-set"), opt("descr"), opt("members"), opt("mp-members"),
		opt("mbrs-by-ref"))...)

	set("peering-set", with(own(),
		reqS("peering-set"), opt("descr"), req("peering"), opt("mp-peering"))...)

	set("filter-set", with(own(),
		reqS("filter-set"), opt("descr"), optS("filter"), optS("mp-filter"))...)

	set("rtr-set", with(own(),
		reqS("rtr-set"), opt("descr"), opt("members"), opt("mp-members"),
		opt("mbrs-by-ref"))...)

	set("inetnum", with(own(),
		reqS("inetnum"), req("netname"), req("country"), req("status"),
		req("admin-c"), req("tech-c"))...)

	set("inet6num", with(own(),
		reqS("inet6num"), req("netname"), req("country"), req("status"),
		req("admin-c"), req("tech-c"))...)

	set("as-block", with(own(), reqS("as-block"), opt("descr"))...)

	set("inet-rtr", with(own(),
		reqS("inet-rtr"), reqS("local-as"), req("ifaddr"), opt("peer"),
		opt("mp-peer"), opt("member-of"))...)

	set("irt", with(own(),
		reqS("irt"), req("address"), req("e-mail"), req("auth"),
		opt("admin-c"), opt("tech-c"))...)

	set("domain", with(own(),
		reqS("domain"), opt("descr"), req("nserver"), opt("admin-c"),
		opt("tech-c"), opt("zone-c"))...)

	set("organisation", with(own(),
		reqS("organisation"), req("org-name"), reqS("org-type"),
		opt("address"), opt("admin-c"), opt("tech-c"))...)

	return c
}

// ripeClasses derives the RIPE profile from the RFC table: the same required and
// cardinality rules, but tolerant of RIPE's extension attributes.
func ripeClasses() map[string]ClassSpec {
	out := make(map[string]ClassSpec, len(rfcClasses()))
	for name, cs := range rfcClasses() {
		cs.AllowUnknown = true
		out[name] = cs
	}
	return out
}

// RFCStrict admits only the attributes RFC 2622/2650/4012 define for each class;
// anything else (e.g. RIPE's changed:) is flagged dict/unknown-attr.
var RFCStrict = Profile{Name: "RFC-strict", Classes: rfcClasses()}

// RIPE mirrors IRRd/RIPE reality: it enforces required attributes and cardinality
// but tolerates RIPE-only attributes (org:, created:, last-modified:, changed:, …).
var RIPE = Profile{Name: "RIPE", Classes: ripeClasses()}
