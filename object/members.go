package object

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/types"
)

// MemberKind tags the shape of a set member.
type MemberKind uint8

const (
	MemberInvalid     MemberKind = iota // unparseable (the zero value); only Raw is meaningful
	MemberAS                            // an ASN, optionally with a range operator (route-set only)
	MemberSet                           // a nested set name, optionally with a range operator (route-set only)
	MemberPrefixRange                   // a prefix with optional range op (route-set only)
)

// String returns the kind's name, e.g. "as" or "prefix-range".
func (k MemberKind) String() string {
	switch k {
	case MemberAS:
		return "as"
	case MemberSet:
		return "set"
	case MemberPrefixRange:
		return "prefix-range"
	default:
		return "invalid"
	}
}

// SetMember is a single item from a members:/mp-members: list. It is a tagged
// union: exactly one of AS/Set/Range is meaningful per Kind, and Op may qualify
// an AS or Set member of a route-set ("AS1^24", "RS-FOO^+"; RFC 2622 §5.2). Raw
// preserves the item's text regardless, so a member of unexpected shape is
// still kept.
type SetMember struct {
	Kind  MemberKind
	AS    types.ASN
	Set   types.SetName
	Range types.PrefixRange
	Op    types.RangeOperator
	Raw   string
}

// ParseSetMember parses one list item of a members:/mp-members: value for a
// set of class container. Range operators and prefix-ranges are accepted only
// for types.ClassRouteSet. On failure it returns a MemberInvalid member (never a
// MemberAS) carrying Raw, plus an error. A nested set of a different class is
// not an error here; the decoder flags it separately.
func ParseSetMember(item string, container types.SetClass) (SetMember, error) {
	m := SetMember{Raw: item}
	s := strings.TrimSpace(item)
	if s == "" || strings.ContainsFunc(s, unicode.IsSpace) {
		return m, fmt.Errorf("invalid %s member %q", container, item)
	}
	routeSet := container == types.ClassRouteSet
	base, opText, hasOp := strings.Cut(s, "^")

	var op types.RangeOperator
	if hasOp {
		o, err := types.ParseRangeOperator(opText)
		if err == nil {
			op = o
		} else {
			hasOp = false // not an AS/set operator; may still be a prefix-range
			base = ""
		}
	}
	if base != "" {
		kind := MemberInvalid
		if as, err := types.ParseASN(base); err == nil {
			kind, m.AS = MemberAS, as
		} else if sn, err := types.ParseSetName(base); err == nil {
			kind, m.Set = MemberSet, sn
		}
		if kind != MemberInvalid {
			if hasOp && !routeSet {
				m.AS, m.Set = 0, types.SetName{}
				return m, fmt.Errorf("range operator not valid in %s member %q", container, item)
			}
			m.Kind, m.Op = kind, op
			return m, nil
		}
	}
	if pr, err := types.ParsePrefixRange(s); err == nil {
		if !routeSet {
			return m, fmt.Errorf("prefix-range member %q not valid in %s", item, container)
		}
		m.Kind, m.Range = MemberPrefixRange, pr
		return m, nil
	}
	return m, fmt.Errorf("invalid %s member %q", container, item)
}

// nestable reports whether a set of class member may be listed in a set of
// class container (RFC 2622 §5.1-5.2): as-sets list as-sets; route-sets list
// route-sets and as-sets (the routes their ASes originate).
func nestable(container, member types.SetClass) bool {
	switch container {
	case types.ClassRouteSet:
		return member == types.ClassRouteSet || member == types.ClassAsSet
	case types.ClassUnknown:
		return true
	}
	return member == container
}

// members parses every item of every name attribute into SetMembers for a set
// of class container. An unparseable item is kept as MemberInvalid with an
// Error at the item's own span (the engine skips it); a nested set of a class
// the container may not list is kept but flagged with a Warning.
func (d *decoder) members(name, rule string, container types.SetClass) []SetMember {
	var out []SetMember
	for _, it := range d.listItems(name) {
		m, err := ParseSetMember(it.Value, container)
		switch {
		case err != nil: // dropped from the typed struct (and from expansion): an Error
			d.diagAt(ast.Error, it.span(), rule, err.Error())
		case m.Kind == MemberSet && !nestable(container, m.Set.Class()):
			d.diagAt(ast.Warning, it.span(), rule, fmt.Sprintf("set member %q has class %s, expected %s",
				it.Value, m.Set.Class(), container))
		case m.Kind == MemberPrefixRange && hasHostBits(it.Value):
			d.diagAt(ast.Warning, it.span(), rule+"-host-bits", fmt.Sprintf(
				"member %q has host bits set; it is read as %s", it.Value, m.Range))
		case m.Kind == MemberPrefixRange && name == "members" && m.Range.Prefix().Addr().Is6():
			d.diagAt(ast.Warning, it.span(), rule+"-afi", fmt.Sprintf(
				"IPv6 member %q belongs in mp-members: (RFC 4012 §4.2); members: is IPv4 only", it.Value))
		}
		if m.Kind == MemberPrefixRange {
			base, _, _ := strings.Cut(strings.TrimSpace(it.Value), "^")
			if types.PaddedIPv4(base) {
				d.diagAt(ast.Warning, it.span(), d.leadingZerosRule(), paddedMessage(it.Value, m.Range.String()))
			}
			if types.AbbreviatedIPv4(base) {
				d.diagAt(ast.Warning, it.span(), d.abbreviatedRule(), abbreviatedMessage(it.Value, m.Range.String()))
			}
		}
		out = append(out, m)
	}
	return out
}

// hasHostBits reports whether the prefix of a prefix-range text ("a/n" or
// "a/n^op") has bits set beyond its length, which ParsePrefixRange clears.
func hasHostBits(text string) bool {
	base, _, _ := strings.Cut(strings.TrimSpace(text), "^")
	p, err := types.ParsePrefix(base)
	return err == nil && p != p.Masked()
}
