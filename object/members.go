package object

import (
	"fmt"

	"github.com/rkolesnichenko/rpsl/types"
)

// MemberKind tags the shape of a set member.
type MemberKind uint8

const (
	MemberAS          MemberKind = iota // a bare ASN
	MemberSet                           // a nested set name
	MemberPrefixRange                   // a prefix with optional range op (route-set only)
)

// SetMember is a single entry from a members:/mp-members: list. It is a tagged
// union: exactly one of AS/Set/Range is meaningful per Kind. Raw preserves the
// original token regardless, so a member of unexpected shape is still kept.
type SetMember struct {
	Kind  MemberKind
	AS    types.ASN
	Set   types.SetName
	Range types.PrefixRange
	Raw   string
}

// members parses every value of name into SetMembers. as-set members may be a
// bare ASN or a nested set; route-set members additionally allow prefix-ranges
// (allowRange). containerClass is the expected class of nested set references
// (AsSet for as-set, RouteSet for route-set); a mismatch is kept but flagged
// with a Warning. A token of unexpected shape for the class is kept best-effort
// and flagged rather than dropped.
func (d *decoder) members(name, rule string, allowRange bool, containerClass types.SetClass) []SetMember {
	var out []SetMember
	for _, a := range d.o.GetAll(name) {
		if as, err := types.ParseASN(a.Value); err == nil {
			out = append(out, SetMember{Kind: MemberAS, AS: as, Raw: a.Value})
			continue
		}
		if sn, err := types.ParseSetName(a.Value); err == nil {
			if containerClass != types.SetClassUnknown && sn.Class != containerClass {
				d.warnf(a, rule, fmt.Sprintf("set member %q has class %s, expected %s",
					a.Value, sn.Class, containerClass))
			}
			out = append(out, SetMember{Kind: MemberSet, Set: sn, Raw: a.Value})
			continue
		}
		if pr, err := types.ParsePrefixRange(a.Value); err == nil {
			if !allowRange {
				d.warnf(a, rule, "prefix-range member not valid for this set class")
			}
			out = append(out, SetMember{Kind: MemberPrefixRange, Range: pr, Raw: a.Value})
			continue
		}
		d.warnf(a, rule, fmt.Sprintf("unrecognized set member %q", a.Value))
		out = append(out, SetMember{Raw: a.Value})
	}
	return out
}
