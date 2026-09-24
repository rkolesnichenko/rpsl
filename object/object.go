// Package object provides typed wrappers over the generic ast.Object for the
// RPSL classes: aut-num, mntner, person, role, route, route6, as-set, route-set,
// peering-set, filter-set, rtr-set, inet-rtr, inetnum, inet6num, as-block, irt,
// domain, organisation, key-cert, dictionary, poem and poetic-form. Every attribute a validation profile lists for a
// class is surfaced on its typed struct (the RFC 2622 §3.1 common attributes via
// the embedded Common, RIPE's cross-class ones via the embedded Registry).
// Decoding is fallible per-attribute: a malformed value is skipped with a
// Diagnostic, never aborting the whole object, and Raw always drops back to the
// lossless ast.Object. Other classes decode to Generic.
package object

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/lexer"
	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/types"
)

// Object is the common interface implemented by every typed class. Raw returns
// the underlying lossless object so callers can always recover the exact source.
type Object interface {
	Class() string
	Raw() *ast.Object
}

// Generic wraps a class with no typed decoder, degrading gracefully so unknown
// classes still satisfy Object.
type Generic struct{ raw *ast.Object }

// Class returns the class name of the underlying object.
func (g Generic) Class() string { return g.raw.Class() }

// Raw returns the object's lossless source, or nil for one built without it.
func (g Generic) Raw() *ast.Object { return g.raw }

// decoder removes per-attribute boilerplate and centralizes diagnostics. Each
// failed parse appends an Error diagnostic keyed to the offending attribute's
// span and skips that value; sibling attributes still decode.
type decoder struct {
	o     *ast.Object
	diags []ast.Diagnostic
}

func newDecoder(o *ast.Object) *decoder { return &decoder{o: o} }

// errf records a parse failure against an attribute span.
func (d *decoder) errf(a ast.Attribute, rule, msg string) {
	d.diagAt(ast.Error, a.Span, rule, msg)
}

// diagAt records a diagnostic at an explicit span (e.g. one list item).
func (d *decoder) diagAt(sev ast.Severity, span lexer.Span, rule, msg string) {
	d.diags = append(d.diags, ast.Diagnostic{Severity: sev, Message: msg, Span: span, Rule: rule})
}

// rebase attaches policy-layer diagnostics onto the owning attribute. Each
// policy diagnostic carries its position as a byte range within the attribute's
// logical value (in Span.StartByte/EndByte); rebase translates that range into a
// precise source span via the attribute's segment map, so a diagnostic points at
// the offending token even across folded continuation lines.
func (d *decoder) rebase(a ast.Attribute, ds []ast.Diagnostic) {
	for _, diag := range ds {
		diag.Span = a.SpanAt(diag.Span.StartByte, diag.Span.EndByte)
		d.diags = append(d.diags, diag)
	}
}

func (d *decoder) warnf(a ast.Attribute, rule, msg string) {
	d.diagAt(ast.Warning, a.Span, rule, msg)
}

// listItem is one non-empty item of a list-valued attribute, paired with its
// attribute so diagnostics can point at the item itself.
type listItem struct {
	ast.ListItem
	attr ast.Attribute
}

func (it listItem) span() lexer.Span { return it.attr.SpanAt(it.Start, it.End) }

// listItems returns the items of every name attribute in document order,
// recording a Warning for each empty item and one per attribute whose items a
// line break separates without a comma: RPSL separates them with commas (RFC
// 2622 §2), and IRRd reads a line break as one (see ast.Attribute.List).
func (d *decoder) listItems(name string) []listItem {
	var out []listItem
	for _, a := range d.o.GetAll(name) {
		items := a.List()
		for i, it := range items {
			if i > 0 && !strings.Contains(a.Value[items[i-1].End:it.Start], ",") {
				d.diagAt(ast.Warning, a.SpanAt(it.Start, it.End), "object/list-line-break",
					name+" items are separated by a line break without a comma; they are read as separate items, as IRRd does")
				break
			}
		}
		for _, it := range items {
			if it.Value == "" {
				d.diagAt(ast.Warning, a.SpanAt(it.Start, it.End), "object/list-empty-item",
					"empty item in "+name+" list")
				continue
			}
			out = append(out, listItem{ListItem: it, attr: a})
		}
	}
	return out
}

// list returns the items of every list-valued name attribute, in order.
func (d *decoder) list(name string) []string {
	var out []string
	for _, it := range d.listItems(name) {
		out = append(out, it.Value)
	}
	return out
}

// scalar returns a's logical value trimmed at both ends. A "+" or comment-only
// continuation line contributes an empty line to the value, so without this
// "route: 192.0.2.0/24" followed by a "+" line would be "192.0.2.0/24\n" and
// fail to parse. Interior line breaks are kept; the raw text is untouched.
func scalar(a ast.Attribute) string { return strings.Trim(a.Value, " \t\r\n") }

// str returns the first value for name, or "" if absent.
func (d *decoder) str(name string) string {
	if a, ok := d.o.GetFirst(name); ok {
		return scalar(a)
	}
	return ""
}

// all returns every value for name, in document order.
func (d *decoder) all(name string) []string {
	attrs := d.o.GetAll(name)
	if len(attrs) == 0 {
		return nil
	}
	out := make([]string, len(attrs))
	for i, a := range attrs {
		out[i] = scalar(a)
	}
	return out
}

// emptyKey reports a class's key attribute that has no value, with one Error
// ("object/empty-key") for every class alike, and returns true so the caller
// skips its own parse error.
func (d *decoder) emptyKey(a ast.Attribute) bool {
	if a.Name != d.o.Class() || scalar(a) != "" {
		return false
	}
	d.errf(a, "object/empty-key", a.Name+" object has an empty key")
	return true
}

// asn parses the first value of name as an ASN; diag + zero value on failure.
func (d *decoder) asn(name, rule string) types.ASN {
	a, ok := d.o.GetFirst(name)
	if !ok || d.emptyKey(a) {
		return 0
	}
	v, err := types.ParseASN(scalar(a))
	if err != nil {
		d.errf(a, rule, err.Error())
		return 0
	}
	return v
}

// prefix parses the first value of name as a netip.Prefix.
func (d *decoder) prefix(name, rule string) netip.Prefix {
	a, ok := d.o.GetFirst(name)
	if !ok || d.emptyKey(a) {
		return netip.Prefix{}
	}
	p, err := types.ParsePrefix(scalar(a))
	if err != nil {
		d.errf(a, rule, err.Error())
		return netip.Prefix{}
	}
	if types.PaddedIPv4(scalar(a)) {
		d.warnf(a, d.leadingZerosRule(), paddedMessage(scalar(a), p.String()))
	}
	if types.AbbreviatedIPv4(scalar(a)) {
		d.warnf(a, d.abbreviatedRule(), abbreviatedMessage(scalar(a), p.String()))
	}
	return p
}

// leadingZerosRule is the rule for an IPv4 value with zero-padded octets in
// any attribute of the object being decoded.
func (d *decoder) leadingZerosRule() string { return "object/" + d.o.Class() + "-leading-zeros" }

// paddedMessage explains how a zero-padded IPv4 value was read.
func paddedMessage(text, canonical string) string {
	return fmt.Sprintf("%q has zero-padded octets; it is read as %s (decimal)", text, canonical)
}

// abbreviatedRule is the rule for an IPv4 prefix written with fewer than four
// octets in any attribute of the object being decoded.
func (d *decoder) abbreviatedRule() string { return "object/" + d.o.Class() + "-abbreviated-prefix" }

// abbreviatedMessage explains how an abbreviated IPv4 prefix was read.
func abbreviatedMessage(text, canonical string) string {
	return fmt.Sprintf("%q is abbreviated; it is read as %s", text, canonical)
}

// addrRange parses the first value of name as an inetnum address range
// "lo - hi" (e.g. "192.0.2.0 - 192.0.2.255") of IPv4 addresses with lo <= hi.
// Returns the zero Addrs on failure.
func (d *decoder) addrRange(name, rule string) (lo, hi netip.Addr) {
	a, ok := d.o.GetFirst(name)
	if !ok || d.emptyKey(a) {
		return netip.Addr{}, netip.Addr{}
	}
	l, h, found := strings.Cut(scalar(a), "-")
	if !found {
		d.errf(a, rule, "expected 'lo - hi' address range")
		return netip.Addr{}, netip.Addr{}
	}
	lo, err1 := types.ParseAddr(strings.TrimSpace(l))
	hi, err2 := types.ParseAddr(strings.TrimSpace(h))
	if err1 == nil && err2 == nil && (types.PaddedIPv4(strings.TrimSpace(l)) || types.PaddedIPv4(strings.TrimSpace(h))) {
		d.warnf(a, d.leadingZerosRule(), paddedMessage(scalar(a), lo.String()+" - "+hi.String()))
	}
	switch {
	case err1 != nil || err2 != nil:
		d.errf(a, rule, "invalid address range "+scalar(a))
	case !lo.Is4() || !hi.Is4():
		d.errf(a, rule, "address range "+scalar(a)+" is not IPv4")
	case lo.Compare(hi) > 0:
		d.errf(a, rule, fmt.Sprintf("address range starts at %s, after its end %s", lo, hi))
	default:
		return lo, hi
	}
	return netip.Addr{}, netip.Addr{}
}

// asnRange parses the first value of name as an as-block range "ASlo - AShi"
// (e.g. "AS1 - AS10") with lo <= hi. Returns zero ASNs on failure.
func (d *decoder) asnRange(name, rule string) (lo, hi types.ASN) {
	a, ok := d.o.GetFirst(name)
	if !ok || d.emptyKey(a) {
		return 0, 0
	}
	l, h, found := strings.Cut(scalar(a), "-")
	if !found {
		d.errf(a, rule, "expected 'ASlo - AShi' range")
		return 0, 0
	}
	lo, err1 := types.ParseASN(strings.TrimSpace(l))
	hi, err2 := types.ParseASN(strings.TrimSpace(h))
	if err1 != nil || err2 != nil {
		d.errf(a, rule, "invalid as-block range "+scalar(a))
		return 0, 0
	}
	if lo > hi {
		d.errf(a, rule, fmt.Sprintf("as-block range starts at %s, after its end %s", lo, hi))
		return 0, 0
	}
	return lo, hi
}

// nicHandles parses every value of name as a NIC handle, skipping bad ones.
func (d *decoder) nicHandles(name, rule string) []types.NICHandle {
	var out []types.NICHandle
	for _, a := range d.o.GetAll(name) {
		h, err := types.ParseNICHandle(scalar(a))
		if err != nil {
			d.errf(a, rule, err.Error())
			continue
		}
		out = append(out, h)
	}
	return out
}

// Common holds the attributes RFC 2622 §3.1 defines for every class. It is
// embedded in each typed class, so its fields read as the class's own
// (obj.MntBy, obj.Source).
type Common struct {
	Descr   []string
	AdminC  []types.NICHandle
	TechC   []types.NICHandle
	Remarks []string
	Notify  []string
	MntBy   []string
	Changed []Changed
	Source  string
}

// common decodes the RFC 2622 §3.1 common attributes of a class object.
func (d *decoder) common(class string) Common {
	return Common{
		Descr:   d.all("descr"),
		AdminC:  d.nicHandles("admin-c", "object/"+class+"-admin-c"),
		TechC:   d.nicHandles("tech-c", "object/"+class+"-tech-c"),
		Remarks: d.all("remarks"),
		Notify:  d.list("notify"),
		MntBy:   d.list("mnt-by"),
		Changed: d.changed(class),
		Source:  d.str("source"),
	}
}

// Registry holds the attributes RIPE's templates add across classes: the
// owning organisation, the abuse contact, the maintainers of lower-level
// objects, and the timestamps RIPE sets on every object. It is embedded in each
// typed class beside Common; a field stays empty on a class whose template does
// not list its attribute.
type Registry struct {
	Org           []string           // org: organisation handles
	SponsoringOrg string             // sponsoring-org: the sponsoring LIR's organisation
	AbuseC        types.NICHandle    // abuse-c: the role object holding the abuse mailbox
	MntLower      []string           // mnt-lower: maintainers of more-specific objects
	MntRoutes     []policy.MntRoutes // mnt-routes: a maintainer and the space it may authorise
	MntDomains    []string           // mnt-domains: maintainers of reverse domains
	MntIrt        []string           // mnt-irt: irt objects
	MntRef        []string           // mnt-ref: maintainers allowed to reference an organisation
	Created       Timestamp          // created: the RFC 3339 time RIPE sets
	LastModified  Timestamp          // last-modified: the RFC 3339 time RIPE sets
}

// registry decodes the RIPE registry attributes of a class object.
func (d *decoder) registry(class string) Registry {
	var abuse types.NICHandle
	if hs := d.nicHandles("abuse-c", "object/"+class+"-abuse-c"); len(hs) > 0 {
		abuse = hs[0]
	}
	return Registry{
		Org:           d.list("org"),
		SponsoringOrg: d.str("sponsoring-org"),
		AbuseC:        abuse,
		MntLower:      d.list("mnt-lower"),
		MntRoutes:     d.mntRoutes(class),
		MntDomains:    d.list("mnt-domains"),
		MntIrt:        d.list("mnt-irt"),
		MntRef:        d.list("mnt-ref"),
		Created:       d.timestamp(class, "created"),
		LastModified:  d.timestamp(class, "last-modified"),
	}
}

// changed decodes the changed: lines. A line that carries no usable date is
// kept with a warning: the attribute is legacy and real dumps are full of odd
// spellings, and Raw preserves whatever was written.
func (d *decoder) changed(class string) []Changed {
	var out []Changed
	for _, a := range d.o.GetAll("changed") {
		c, err := ParseChanged(a.Value)
		if err != nil {
			d.warnf(a, "object/"+class+"-changed", err.Error())
		}
		out = append(out, c)
	}
	return out
}

// timestamp decodes created:/last-modified:. An unparsable stamp is kept with a
// warning, since Raw still round-trips it.
func (d *decoder) timestamp(class, name string) Timestamp {
	a, ok := d.o.GetFirst(name)
	if !ok {
		return Timestamp{}
	}
	t, err := ParseTimestamp(a.Value)
	if err != nil {
		d.warnf(a, "object/"+class+"-"+name, err.Error())
	}
	return t
}

// mntRoutes decodes the mnt-routes: lines, whose scope is a prefix list or ANY.
func (d *decoder) mntRoutes(class string) []policy.MntRoutes {
	var out []policy.MntRoutes
	for _, a := range d.o.GetAll("mnt-routes") {
		m, ds := policy.ParseMntRoutes(a.Value)
		d.rebase(a, ds)
		out = append(out, m)
	}
	return out
}

// key returns the value of a class's own (key) attribute, diagnosing an empty
// one.
func (d *decoder) key(class string) string {
	a, ok := d.o.GetFirst(class)
	if !ok || d.emptyKey(a) {
		return ""
	}
	return scalar(a)
}

// setKey parses the set's own name from its class-defining first attribute
// (e.g. "as-set", "peering-set"), recording an Error on a malformed name and a
// Warning when the name's prefix denotes a different class ("route-set: AS-FOO").
func (d *decoder) setKey(class, rule string, want types.SetClass) types.SetName {
	a, ok := d.o.GetFirst(class)
	if !ok || d.emptyKey(a) {
		return types.SetName{}
	}
	n, err := types.ParseSetName(scalar(a))
	if err != nil {
		d.errf(a, rule, err.Error())
		return types.SetName{}
	}
	if n.Class() != want {
		d.warnf(a, "object/"+class+"-name-class",
			fmt.Sprintf("%s %q is named like a %s", class, scalar(a), n.Class()))
	}
	return n
}

// routePrefix decodes a route/route6 key, warning when it is of the wrong
// family or has host bits set (the network is what the route denotes).
func (d *decoder) routePrefix(class string, v6 bool) netip.Prefix {
	p := d.prefix(class, "object/"+class+"-prefix")
	a, ok := d.o.GetFirst(class)
	if !p.IsValid() || !ok {
		return p
	}
	if p.Addr().Is6() != v6 {
		want := "IPv4"
		if v6 {
			want = "IPv6"
		}
		d.warnf(a, "object/"+class+"-afi", class+" prefix is not "+want)
	} else if p != p.Masked() {
		d.warnf(a, "object/"+class+"-host-bits",
			fmt.Sprintf("prefix %s has host bits set; the network is %s", p, p.Masked()))
	}
	return p
}

// holes decodes a route's holes: list, warning on a hole with host bits set
// (it is read as its network) and on one that is not a more-specific of route
// itself.
func (d *decoder) holes(class string, route netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, it := range d.listItems("holes") {
		h, err := types.ParsePrefix(it.Value)
		if err != nil {
			d.diagAt(ast.Error, it.span(), "object/"+class+"-holes", err.Error())
			continue
		}
		if types.PaddedIPv4(it.Value) {
			d.diagAt(ast.Warning, it.span(), d.leadingZerosRule(), paddedMessage(it.Value, h.String()))
		}
		if types.AbbreviatedIPv4(it.Value) {
			d.diagAt(ast.Warning, it.span(), d.abbreviatedRule(), abbreviatedMessage(it.Value, h.String()))
		}
		if h != h.Masked() {
			d.diagAt(ast.Warning, it.span(), "object/"+class+"-holes-host-bits",
				fmt.Sprintf("hole %s has host bits set; it is read as %s", h, h.Masked()))
			h = h.Masked()
		}
		if route.IsValid() && (!route.Masked().Contains(h.Addr()) || h.Bits() < route.Bits()) {
			d.diagAt(ast.Warning, it.span(), "object/"+class+"-holes-outside",
				fmt.Sprintf("hole %s is not inside %s", h, route))
		}
		out = append(out, h)
	}
	return out
}

// memberOf decodes a member-of: list, skipping names that do not parse and
// warning on a set of a class the object cannot join (RFC 2622 §5: an aut-num
// joins as-sets, a route route-sets, an inet-rtr rtr-sets). Such a name is
// kept; the engine never reads it, as it takes only the claims its class rules
// allow.
func (d *decoder) memberOf(class string, want types.SetClass) []types.SetName {
	rule := "object/" + class + "-member-of"
	var out []types.SetName
	for _, it := range d.listItems("member-of") {
		n, err := types.ParseSetName(it.Value)
		if err != nil {
			d.diagAt(ast.Error, it.span(), rule, err.Error())
			continue
		}
		if n.Class() != want {
			d.diagAt(ast.Warning, it.span(), rule+"-class",
				fmt.Sprintf("%s %s is a %s; a %s can only be a member of a %s", class, n, n.Class(), class, want))
		}
		out = append(out, n)
	}
	return out
}

// Sub-value decoders for the attributes whose values are small languages of
// their own: the authentication schemes of RFC 2622 §3.2, the aggregation
// attributes of RFC 2622 §8.1, and the inet-rtr attributes of RFC 2622 §9.
// Each parses through the policy layer and re-anchors its diagnostics onto the
// attribute, so a bad value costs that one value and nothing else.

// auth decodes the auth: lines of a mntner or irt. An unrecognised scheme is a
// warning, not an error: the value is kept whole in Raw, and registries add
// schemes this library does not know.
func (d *decoder) auth(class string) []Auth {
	var out []Auth
	for _, a := range d.o.GetAll("auth") {
		v, err := ParseAuth(a.Value)
		if err != nil {
			d.warnf(a, "object/"+class+"-auth", err.Error())
		}
		out = append(out, v)
	}
	return out
}

// pingable decodes the pingable: addresses of a route or route6.
func (d *decoder) pingable(class string) []netip.Addr {
	var out []netip.Addr
	for _, a := range d.o.GetAll("pingable") {
		addr, err := types.ParseAddr(scalar(a))
		if err != nil {
			d.errf(a, "object/"+class+"-pingable", "invalid address "+strconv.Quote(scalar(a)))
			continue
		}
		if types.PaddedIPv4(scalar(a)) {
			d.warnf(a, d.leadingZerosRule(), paddedMessage(scalar(a), addr.String()))
		}
		out = append(out, addr.Unmap().WithZone(""))
	}
	return out
}

// injects decodes the inject: lines of a route or route6.
func (d *decoder) injects(class string) []policy.Inject {
	var out []policy.Inject
	for _, a := range d.o.GetAll("inject") {
		v, ds := policy.ParseInject(a.Value)
		d.rebase(a, ds)
		out = append(out, v)
	}
	return out
}

// components decodes the single components: value of a route or route6.
func (d *decoder) components(class string) policy.Components {
	a, ok := d.o.GetFirst("components")
	if !ok {
		return policy.Components{}
	}
	v, ds := policy.ParseComponents(a.Value)
	d.rebase(a, ds)
	return v
}

// aggrMtd decodes the single aggr-mtd: value of a route or route6.
func (d *decoder) aggrMtd(class string) policy.AggrMtd {
	a, ok := d.o.GetFirst("aggr-mtd")
	if !ok {
		return policy.AggrMtd{}
	}
	v, ds := policy.ParseAggrMtd(a.Value)
	d.rebase(a, ds)
	return v
}

// asExpr decodes an attribute whose value is an AS expression (aggr-bndry:).
func (d *decoder) asExpr(class, name string) policy.ASExpr {
	a, ok := d.o.GetFirst(name)
	if !ok {
		return nil
	}
	v, ds := policy.ParseASExpression(a.Value)
	d.rebase(a, ds)
	return v
}

// filterAttr decodes an attribute whose value is a policy filter (export-comps:).
func (d *decoder) filterAttr(class, name string) policy.Filter {
	a, ok := d.o.GetFirst(name)
	if !ok {
		return nil
	}
	v, ds := policy.ParseFilter(a.Value)
	d.rebase(a, ds)
	return v
}

// ifaddrs decodes the ifaddr: lines of an inet-rtr.
func (d *decoder) ifaddrs() []policy.Ifaddr {
	var out []policy.Ifaddr
	for _, a := range d.o.GetAll("ifaddr") {
		v, ds := policy.ParseIfaddr(a.Value)
		d.rebase(a, ds)
		out = append(out, v)
	}
	return out
}

// interfaces decodes the RFC 4012 interface: lines of an inet-rtr.
func (d *decoder) interfaces() []policy.Interface {
	var out []policy.Interface
	for _, a := range d.o.GetAll("interface") {
		v, ds := policy.ParseInterface(a.Value)
		d.rebase(a, ds)
		out = append(out, v)
	}
	return out
}

// peers decodes the peer: or mp-peer: lines of an inet-rtr.
func (d *decoder) peers(name string) []policy.Peer {
	var out []policy.Peer
	for _, a := range d.o.GetAll(name) {
		v, ds := policy.ParsePeer(a.Value)
		d.rebase(a, ds)
		out = append(out, v)
	}
	return out
}

// rtrMembers decodes the members:/mp-members: items of an rtr-set.
func (d *decoder) rtrMembers(name, rule string) []RtrSetMember {
	var out []RtrSetMember
	for _, it := range d.listItems(name) {
		m, err := ParseRtrSetMember(it.Value)
		if err != nil {
			d.diagAt(ast.Error, it.span(), rule, err.Error())
		}
		out = append(out, m)
	}
	return out
}
