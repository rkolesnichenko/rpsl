package resolve

import (
	"strings"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/types"
)

// ClaimAllowed reports whether o's indirect membership in set is honored under
// the RFC 2622 mbrs-by-ref rules: o must name the set in its member-of, the
// set's mbrs-by-ref must contain ANY or share a maintainer with o's mnt-by, and
// o must come from the set's own source. Maintainer names are unique only within
// one registry, so a claim from another IRR is never honored (IRRd applies the
// same rule). Maintainers and sources compare case-insensitively; an absent
// source matches only an absent source.
//
// Only aut-num, route and route6 objects claim membership (as values or
// pointers); they are judged by their typed fields (MemberOf, MntBy, Source), so
// objects a Source builds itself, without source text, work too.
//
// This is the single implementation of the mntner check. Sources should use it
// in MembersByRef, and the Expander re-applies it to every object a Source
// returns, so a lenient Source cannot widen a set.
func ClaimAllowed(o object.Object, set object.NamedSet) bool {
	memberOf, mntBy, source, ok := claimant(o)
	if !ok || set == nil || !names(memberOf, set.SetName()) ||
		!equalFoldASCII(strings.TrimSpace(source), strings.TrimSpace(set.SetSource())) {
		return false
	}
	allow := map[string]bool{}
	for _, m := range set.RefMntners() {
		m = lowerASCII(strings.TrimSpace(m))
		if m == "any" {
			return true
		}
		if m != "" {
			allow[m] = true
		}
	}
	for _, m := range mntBy {
		if allow[lowerASCII(strings.TrimSpace(m))] {
			return true
		}
	}
	return false
}

// lowerASCII lower-cases the ASCII letters of s and nothing else. RPSL names
// are ASCII; Unicode case folding would let a look-alike — the Kelvin sign
// folds to "k" — pass for a maintainer or source it is not.
func lowerASCII(s string) string {
	for i := 0; i < len(s); i++ {
		if 'A' <= s[i] && s[i] <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if 'A' <= b[j] && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

// equalFoldASCII is strings.EqualFold for ASCII letters only (see lowerASCII).
func equalFoldASCII(a, b string) bool {
	return len(a) == len(b) && lowerASCII(a) == lowerASCII(b)
}

// claimant returns the fields a membership claim is judged by, for the classes
// that can claim membership (RFC 2622 §5.1-5.2).
func claimant(o object.Object) (memberOf []types.SetName, mntBy []string, source string, ok bool) {
	switch t := value(o).(type) {
	case object.AutNum:
		if t.AS == 0 && !asnDecodes(t, "aut-num") {
			return nil, nil, "", false // an aut-num whose key did not decode is no AS
		}
		return t.MemberOf, t.MntBy, t.Source, true
	case object.Route:
		return t.MemberOf, t.MntBy, t.Source, true
	case object.InetRtr:
		return t.MemberOf, t.MntBy, t.Source, true
	case object.Route6:
		return t.MemberOf, t.MntBy, t.Source, true
	}
	return nil, nil, "", false
}

// asnDecodes reports whether o's attr holds an AS number — telling a real AS0
// from the zero an undecodable value leaves. An object built without text is
// taken at its word.
func asnDecodes(o object.Object, attr string) bool {
	raw := o.Raw()
	if raw == nil {
		return true
	}
	a, ok := raw.GetFirst(attr)
	if !ok {
		return false
	}
	_, err := types.ParseASN(strings.TrimSpace(a.Value))
	return err == nil
}

// names reports whether list holds set.
func names(list []types.SetName, set types.SetName) bool {
	for _, n := range list {
		if n == set {
			return true
		}
	}
	return false
}

// value returns o with a pointer to one of the object package's types replaced
// by the value it points to (nil for a nil pointer), so the engine's type
// switches see one form. Other objects are returned unchanged.
func value(o object.Object) object.Object {
	switch t := o.(type) {
	case *object.AutNum:
		if t != nil {
			return *t
		}
	case *object.Route:
		if t != nil {
			return *t
		}
	case *object.Route6:
		if t != nil {
			return *t
		}
	case *object.AsSet:
		if t != nil {
			return *t
		}
	case *object.RouteSet:
		if t != nil {
			return *t
		}
	case *object.RtrSet:
		if t != nil {
			return *t
		}
	case *object.PeeringSet:
		if t != nil {
			return *t
		}
	case *object.FilterSet:
		if t != nil {
			return *t
		}
	case *object.InetRtr:
		if t != nil {
			return *t
		}
	default:
		return o
	}
	return nil
}
