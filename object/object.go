// Package object provides typed, validated wrappers over the generic ast.Object
// for the common non-policy RPSL classes (mntner, person, role, route, route6,
// as-set, route-set). Decoding is fallible per-attribute: a malformed value is
// skipped with a Diagnostic, never aborting the whole object, and Raw always
// drops back to the lossless ast.Object.
package object

import (
	"net/netip"
	"strings"

	"github.com/rkolesnichenko/rpsl/ast"
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
	d.diags = append(d.diags, ast.Diagnostic{
		Severity: ast.Error,
		Message:  msg,
		Span:     a.Span,
		Rule:     rule,
	})
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
	d.diags = append(d.diags, ast.Diagnostic{
		Severity: ast.Warning,
		Message:  msg,
		Span:     a.Span,
		Rule:     rule,
	})
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

// prefixes parses every value of name as a netip.Prefix, skipping bad ones.
func (d *decoder) prefixes(name, rule string) []netip.Prefix {
	var out []netip.Prefix
	for _, a := range d.o.GetAll(name) {
		p, err := netip.ParsePrefix(a.Value)
		if err != nil {
			d.errf(a, rule, err.Error())
			continue
		}
		out = append(out, p)
	}
	return out
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

// setKey parses the set's own name from its class-defining first attribute
// (e.g. "as-set", "peering-set"), recording a diagnostic on a malformed name.
func (d *decoder) setKey(class, rule string) types.SetName {
	a, ok := d.o.GetFirst(class)
	if !ok {
		return types.SetName{}
	}
	n, err := types.ParseSetName(a.Value)
	if err != nil {
		d.errf(a, rule, err.Error())
		return types.SetName{}
	}
	return n
}

// setNames parses every value of name as a SetName, skipping bad ones.
func (d *decoder) setNames(name, rule string) []types.SetName {
	var out []types.SetName
	for _, a := range d.o.GetAll(name) {
		n, err := types.ParseSetName(a.Value)
		if err != nil {
			d.errf(a, rule, err.Error())
			continue
		}
		out = append(out, n)
	}
	return out
}
