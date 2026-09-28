package object

import (
	"fmt"
	"strings"
	"unicode"

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
