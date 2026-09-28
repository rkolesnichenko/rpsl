package object

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/types"
)

// ParseSrcMember parses one src-members: list item for a set of class
// container (draft-ietf-grow-rpsl-registry-scoped-members-00 §2.1, §2.2).
// An as-set lists an ASN or REG::as-set; a route-set also a prefix range and
// REG::route-set, which alone may carry a range operator. A set reference
// without a registry, a nested set of a class the container may not list, and
// an operator on an ASN or a scoped as-set are errors. On failure it returns a
// MemberInvalid member carrying Raw, as ParseSetMember does.
func ParseSrcMember(item string, container types.SetClass) (SetMember, error) {
	bad := SetMember{Raw: item}
	s := strings.TrimSpace(item)
	if s == "" || strings.ContainsFunc(s, unicode.IsSpace) {
		return bad, fmt.Errorf("invalid %s src-members item %q", container, item)
	}
	routeSet := container == types.ClassRouteSet
	// A prefix first: "2001:db8::/32" contains "::" too.
	if pr, err := types.ParsePrefixRange(withLength(s)); err == nil {
		if !routeSet {
			return bad, fmt.Errorf("prefix-range %q not valid in %s src-members", item, container)
		}
		return SetMember{Kind: MemberPrefixRange, Range: pr, Raw: item}, nil
	}
	base, opText, hasOp := strings.Cut(s, "^")
	var op types.RangeOperator
	if hasOp {
		o, err := types.ParseRangeOperator(opText)
		if err != nil {
			return bad, fmt.Errorf("invalid range operator in %s src-members item %q", container, item)
		}
		op = o
	}
	if as, err := types.ParseASN(base); err == nil {
		if hasOp {
			return bad, fmt.Errorf("range operator not valid on an AS number in src-members: %q", item)
		}
		return SetMember{Kind: MemberAS, AS: as, Raw: item}, nil
	}
	src, name, scoped := strings.Cut(base, "::")
	if !scoped {
		if _, err := types.ParseSetName(base); err == nil {
			return bad, fmt.Errorf("set %q in src-members needs a registry, as in RIPE::%s", item, base)
		}
		return bad, fmt.Errorf("invalid %s src-members item %q", container, item)
	}
	ref, err := types.ParseSetRef(src + "::" + name)
	if err != nil {
		return bad, fmt.Errorf("invalid %s src-members item %q: %v", container, item, err)
	}
	cls := ref.Name().Class()
	if !nestable(container, cls) {
		return bad, fmt.Errorf("%s src-members item %q is a %s", container, item, cls)
	}
	if hasOp && !(routeSet && cls == types.ClassRouteSet) {
		return bad, fmt.Errorf("range operator not valid on a scoped %s in src-members: %q", cls, item)
	}
	return SetMember{Kind: MemberSet, Set: ref.Name(), Source: ref.Source(), Op: op, Raw: item}, nil
}

// memberKey is a member's primary key with the registry removed (spec §5.2):
// the set name, the AS number, or the prefix range itself. The draft compares
// members by it (§2.3 step 2, §3.1, §3.3).
type memberKey struct {
	kind MemberKind
	as   types.ASN
	set  types.SetName
	rng  types.PrefixRange
}

// keyOf returns m's key, and false for a MemberInvalid member.
func keyOf(m SetMember) (memberKey, bool) {
	switch m.Kind {
	case MemberAS:
		return memberKey{kind: MemberAS, as: m.AS}, true
	case MemberSet:
		return memberKey{kind: MemberSet, set: m.Set}, true
	case MemberPrefixRange:
		return memberKey{kind: MemberPrefixRange, rng: m.Range}, true
	}
	return memberKey{}, false
}

// srcMembers decodes src-members: for a set of class container whose
// members:/mp-members: are listed. An item that does not parse is an Error
// (rule) and left out. One set name under two registries (§3.3) is an Error at
// each item (rule-conflict), and both are left out, so the name resolves
// through members: by precedence. An item missing from members:/mp-members:
// (§3.1) is a Warning (rule-unlisted) and kept: the resolver follows it. An
// item repeated under the same registry is kept once.
func (d *decoder) srcMembers(rule string, container types.SetClass, listed ...[]SetMember) []SetMember {
	type parsed struct {
		m  SetMember
		it listItem
	}
	var ps []parsed
	registries := map[types.SetName]map[string]bool{}
	for _, it := range d.listItems("src-members") {
		m, err := ParseSrcMember(it.Value, container)
		if err != nil {
			d.diagAt(ast.Error, it.span(), rule, err.Error())
			continue
		}
		ps = append(ps, parsed{m, it})
		if m.Kind == MemberSet {
			if registries[m.Set] == nil {
				registries[m.Set] = map[string]bool{}
			}
			registries[m.Set][m.Source] = true
		}
	}
	in := map[memberKey]bool{}
	for _, l := range listed {
		for _, m := range l {
			if k, ok := keyOf(m); ok {
				in[k] = true
			}
		}
	}
	var out []SetMember
	kept := map[memberKey]bool{}
	for _, p := range ps {
		if p.m.Kind == MemberSet && len(registries[p.m.Set]) > 1 {
			d.diagAt(ast.Error, p.it.span(), rule+"-conflict", fmt.Sprintf(
				"%s is named under %d registries; src-members: may name a set once (draft-ietf-grow-rpsl-registry-scoped-members §3.3), so it is resolved through members: instead",
				p.m.Set, len(registries[p.m.Set])))
			continue
		}
		k, _ := keyOf(p.m)
		if !in[k] {
			d.diagAt(ast.Warning, p.it.span(), rule+"-unlisted", fmt.Sprintf(
				"src-members: item %q is not in members: or mp-members: (draft-ietf-grow-rpsl-registry-scoped-members §3.1); it is still resolved",
				p.it.Value))
		}
		if !kept[k] {
			kept[k] = true
			out = append(out, p.m)
		}
	}
	return out
}

// DirectMembers returns the members a resolver follows
// (draft-ietf-grow-rpsl-registry-scoped-members §2.3 steps 1-2): every
// src-members: member, then each members:/mp-members: member whose key (spec
// §5.2) no src-members: member has. A set name under two registries in
// src-members: is left out of it, as the decoder leaves it out, so that name
// is followed through members:. It reads one object and does no I/O.
func DirectMembers(s Set) []SetMember {
	src, listed := s.SetSrcMembers(), s.SetMembers()
	if len(src) == 0 {
		return listed
	}
	registries := map[types.SetName]map[string]bool{}
	for _, m := range src {
		if m.Kind == MemberSet {
			if registries[m.Set] == nil {
				registries[m.Set] = map[string]bool{}
			}
			registries[m.Set][m.Source] = true
		}
	}
	have := map[memberKey]bool{}
	out := make([]SetMember, 0, len(src)+len(listed))
	for _, m := range src {
		if m.Kind == MemberSet && len(registries[m.Set]) > 1 {
			continue
		}
		if k, ok := keyOf(m); ok && !have[k] {
			have[k] = true
			out = append(out, m)
		}
	}
	for _, m := range listed {
		if k, ok := keyOf(m); ok && have[k] {
			continue
		}
		out = append(out, m)
	}
	return out
}
