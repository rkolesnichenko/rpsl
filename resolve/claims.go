package resolve

import (
	"strings"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/types"
)

// ClaimAllowed reports whether o's indirect membership in set is honored under
// the RFC 2622 mbrs-by-ref rules: o must name set in a member-of attribute, and
// mbrsByRef must contain ANY or share a maintainer with o's mnt-by. Names are
// compared case-insensitively and list values are split on commas.
//
// This is the single implementation of the mntner check. Sources should use it
// in MembersByRef, and the Expander re-applies it to every object a Source
// returns, so a lenient Source cannot widen a set.
func ClaimAllowed(o object.Object, set types.SetName, mbrsByRef []string) bool {
	raw := o.Raw()
	if raw == nil || !claims(raw.GetAll("member-of"), set) {
		return false
	}
	allow := make(map[string]bool, len(mbrsByRef))
	for _, m := range mbrsByRef {
		m = strings.ToLower(strings.TrimSpace(m))
		if m == "any" {
			return true
		}
		allow[m] = true
	}
	for _, a := range raw.GetAll("mnt-by") {
		for _, it := range a.List() {
			if allow[strings.ToLower(it.Value)] {
				return true
			}
		}
	}
	return false
}

// claims reports whether any member-of item names set.
func claims(memberOf []ast.Attribute, set types.SetName) bool {
	for _, a := range memberOf {
		for _, it := range a.List() {
			if n, err := types.ParseSetName(it.Value); err == nil && n.Canonical() == set.Canonical() {
				return true
			}
		}
	}
	return false
}
