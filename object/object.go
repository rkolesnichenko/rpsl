// Package object provides typed wrappers over the generic ast.Object for the
// RPSL classes: aut-num, mntner, person, role, route, route6, as-set, route-set,
// peering-set, filter-set, rtr-set, inet-rtr, inetnum, inet6num, as-block, irt,
// domain and organisation. Every attribute a validation profile lists for a
// class is surfaced on its typed struct (the RFC 2622 §3.1 common attributes via
// the embedded Common). Decoding is fallible per-attribute: a malformed value is
// skipped with a Diagnostic, never aborting the whole object, and Raw always
// drops back to the lossless ast.Object. Other classes decode to Generic.
package object

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/lexer"
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

func (g Generic) Class() string    { return g.raw.Class() }
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

// listItems returns the comma-separated items (RFC 2622 §2) of every name
// attribute in document order, recording a Warning for each empty item.
func (d *decoder) listItems(name string) []listItem {
	var out []listItem
	for _, a := range d.o.GetAll(name) {
		for _, it := range a.List() {
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

// str returns the first value for name, or "" if absent.
func (d *decoder) str(name string) string {
	if a, ok := d.o.GetFirst(name); ok {
		return a.Value
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
		out[i] = a.Value
	}
	return out
}

// asn parses the first value of name as an ASN; diag + zero value on failure.
func (d *decoder) asn(name, rule string) types.ASN {
	a, ok := d.o.GetFirst(name)
	if !ok {
		return 0
	}
	v, err := types.ParseASN(a.Value)
	if err != nil {
		d.errf(a, rule, err.Error())
		return 0
	}
	return v
}

// prefix parses the first value of name as a netip.Prefix.
func (d *decoder) prefix(name, rule string) netip.Prefix {
	a, ok := d.o.GetFirst(name)
	if !ok {
		return netip.Prefix{}
	}
	p, err := netip.ParsePrefix(a.Value)
	if err != nil {
		d.errf(a, rule, err.Error())
		return netip.Prefix{}
	}
	return p
}

// addrRange parses the first value of name as an inetnum-style address range
// "lo - hi" (e.g. "192.0.2.0 - 192.0.2.255"). Returns the zero Addrs on failure.
func (d *decoder) addrRange(name, rule string) (lo, hi netip.Addr) {
	a, ok := d.o.GetFirst(name)
	if !ok {
		return netip.Addr{}, netip.Addr{}
	}
	l, h, found := strings.Cut(a.Value, "-")
	if !found {
		d.errf(a, rule, "expected 'lo - hi' address range")
		return netip.Addr{}, netip.Addr{}
	}
	lo, err1 := netip.ParseAddr(strings.TrimSpace(l))
	hi, err2 := netip.ParseAddr(strings.TrimSpace(h))
	if err1 != nil || err2 != nil {
		d.errf(a, rule, "invalid address range "+a.Value)
		return netip.Addr{}, netip.Addr{}
	}
	return lo, hi
}

// asnRange parses the first value of name as an as-block range "ASlo - AShi"
// (e.g. "AS1 - AS10"). Returns zero ASNs on failure.
func (d *decoder) asnRange(name, rule string) (lo, hi types.ASN) {
	a, ok := d.o.GetFirst(name)
	if !ok {
		return 0, 0
	}
	l, h, found := strings.Cut(a.Value, "-")
	if !found {
		d.errf(a, rule, "expected 'ASlo - AShi' range")
		return 0, 0
	}
	lo, err1 := types.ParseASN(strings.TrimSpace(l))
	hi, err2 := types.ParseASN(strings.TrimSpace(h))
	if err1 != nil || err2 != nil {
		d.errf(a, rule, "invalid as-block range "+a.Value)
		return 0, 0
	}
	return lo, hi
}

// nicHandles parses every value of name as a NIC handle, skipping bad ones.
func (d *decoder) nicHandles(name, rule string) []types.NICHandle {
	var out []types.NICHandle
	for _, a := range d.o.GetAll(name) {
		h, err := types.ParseNICHandle(a.Value)
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
	Changed []string
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
		Changed: d.all("changed"),
		Source:  d.str("source"),
	}
}

// key returns the value of a class's own (key) attribute, diagnosing an empty
// one.
func (d *decoder) key(class string) string {
	a, ok := d.o.GetFirst(class)
	if !ok {
		return ""
	}
	if a.Value == "" {
		d.errf(a, "object/empty-key", class+" object has an empty key")
	}
	return a.Value
}

// setKey parses the set's own name from its class-defining first attribute
// (e.g. "as-set", "peering-set"), recording an Error on a malformed name and a
// Warning when the name's prefix denotes a different class ("route-set: AS-FOO").
func (d *decoder) setKey(class, rule string, want types.SetClass) types.SetName {
	a, ok := d.o.GetFirst(class)
	if !ok {
		return types.SetName{}
	}
	n, err := types.ParseSetName(a.Value)
	if err != nil {
		d.errf(a, rule, err.Error())
		return types.SetName{}
	}
	if n.Class() != want {
		d.warnf(a, "object/"+class+"-name-class",
			fmt.Sprintf("%s %q is named like a %s", class, a.Value, n.Class()))
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

// holes decodes a route's holes: list, warning on a hole that is not a
// more-specific of route itself.
func (d *decoder) holes(class string, route netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, it := range d.listItems("holes") {
		h, err := netip.ParsePrefix(it.Value)
		if err != nil {
			d.diagAt(ast.Error, it.span(), "object/"+class+"-holes", err.Error())
			continue
		}
		if route.IsValid() && (!route.Masked().Contains(h.Addr()) || h.Bits() < route.Bits()) {
			d.diagAt(ast.Warning, it.span(), "object/"+class+"-holes-outside",
				fmt.Sprintf("hole %s is not inside %s", h, route))
		}
		out = append(out, h)
	}
	return out
}

// setNames parses every list item of name as a SetName, skipping bad ones.
func (d *decoder) setNames(name, rule string) []types.SetName {
	var out []types.SetName
	for _, it := range d.listItems(name) {
		n, err := types.ParseSetName(it.Value)
		if err != nil {
			d.diagAt(ast.Error, it.span(), rule, err.Error())
			continue
		}
		out = append(out, n)
	}
	return out
}
