package object

import (
	"testing"

	"github.com/rkolesnichenko/rpsl/types"
)

// FuzzParseSrcMember: never panics; an accepted set member's Ref round-trips
// through types.ParseSetRef, and a failed parse is MemberInvalid with Raw kept.
func FuzzParseSrcMember(f *testing.F) {
	for _, s := range []string{
		"RIPE::AS-FOO", "RIPE::RS-FOO^+", "2001:db8::/32", "AS1", "192.0.2.0/24^24-32",
		"ɐ::RS-X", "RIPE::ɐ", "::", "RIPE::RS-FOO^", "RIPE::AS-FOO^+",
	} {
		f.Add(s, true)
		f.Add(s, false)
	}
	f.Fuzz(func(t *testing.T, item string, routeSet bool) {
		c := types.ClassAsSet
		if routeSet {
			c = types.ClassRouteSet
		}
		m, err := ParseSrcMember(item, c)
		if m.Raw != item {
			t.Fatalf("Raw = %q, want %q", m.Raw, item)
		}
		if err != nil {
			if m.Kind != MemberInvalid {
				t.Fatalf("ParseSrcMember(%q) failed with Kind %s", item, m.Kind)
			}
			return
		}
		if m.Kind == MemberSet {
			back, err := types.ParseSetRef(m.Ref().String())
			if err != nil || back != m.Ref() || !back.IsScoped() {
				t.Fatalf("ParseSrcMember(%q).Ref() = %v, parses back to %v, %v", item, m.Ref(), back, err)
			}
		}
	})
}
