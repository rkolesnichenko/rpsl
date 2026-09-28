package object

import (
	"testing"

	"github.com/rkolesnichenko/rpsl/types"
)

func TestParseSrcMember(t *testing.T) {
	as, rs := types.ClassAsSet, types.ClassRouteSet
	for _, tc := range []struct {
		item      string
		container types.SetClass
		kind      MemberKind
		ref       string // m.Ref().String() for sets, m.Range.String() for prefixes, m.AS.String() for ASNs
		op        string
		ok        bool
	}{
		// as-set (draft §2.1): an ASN or REG::as-set, no operators.
		{"AS65000", as, MemberAS, "AS65000", "", true},
		{"RIPE::AS-FOO", as, MemberSet, "RIPE::AS-FOO", "", true},
		{"ripe::as-foo", as, MemberSet, "RIPE::AS-FOO", "", true},
		{"AS-FOO", as, 0, "", "", false},       // a set needs a registry
		{"RIPE::RS-FOO", as, 0, "", "", false}, // an as-set lists as-sets
		{"192.0.2.0/24", as, 0, "", "", false}, // no prefixes in an as-set
		{"AS65000^24", as, 0, "", "", false},   // no operators in an as-set
		{"RIPE::AS-FOO^+", as, 0, "", "", false},
		// route-set (draft §2.2).
		{"192.0.2.0/24", rs, MemberPrefixRange, "192.0.2.0/24", "", true},
		{"192.0.2.0/24^+", rs, MemberPrefixRange, "192.0.2.0/24^+", "", true},
		{"RIPE::RS-FOO", rs, MemberSet, "RIPE::RS-FOO", "", true},
		{"RIPE::RS-FOO^24-32", rs, MemberSet, "RIPE::RS-FOO", "^24-32", true},
		{"RIPE::AS-FOO", rs, MemberSet, "RIPE::AS-FOO", "", true},
		{"AS65000", rs, MemberAS, "AS65000", "", true},
		{"RIPE::AS-FOO^+", rs, 0, "", "", false}, // no operator on a scoped as-set
		{"AS65000^24", rs, 0, "", "", false},     // no operator on an ASN
		{"RS-FOO", rs, 0, "", "", false},         // a set needs a registry
		{"RIPE::FLTR-FOO", rs, 0, "", "", false}, // not a class a route-set lists
		{"RI PE::RS-FOO", rs, 0, "", "", false},
		{"", rs, 0, "", "", false},
	} {
		m, err := ParseSrcMember(tc.item, tc.container)
		if (err == nil) != tc.ok {
			t.Errorf("ParseSrcMember(%q, %s) error = %v; want ok=%v", tc.item, tc.container, err, tc.ok)
			continue
		}
		if m.Raw != tc.item {
			t.Errorf("ParseSrcMember(%q).Raw = %q", tc.item, m.Raw)
		}
		if !tc.ok {
			if m.Kind != MemberInvalid {
				t.Errorf("ParseSrcMember(%q) failed but Kind = %s", tc.item, m.Kind)
			}
			continue
		}
		var got string
		switch m.Kind {
		case MemberSet:
			got = m.Ref().String()
		case MemberPrefixRange:
			got = m.Range.String()
		case MemberAS:
			got = m.AS.String()
		}
		op := ""
		if !m.Op.IsZero() {
			op = m.Op.String()
		}
		if m.Kind != tc.kind || got != tc.ref || op != tc.op {
			t.Errorf("ParseSrcMember(%q) = %s %q op %q; want %s %q op %q", tc.item, m.Kind, got, op, tc.kind, tc.ref, tc.op)
		}
	}
}

// TestParseSrcMemberIPv6IsAPrefix: "::" in an IPv6 prefix is not a registry
// separator (Review Focus 3).
func TestParseSrcMemberIPv6IsAPrefix(t *testing.T) {
	for _, item := range []string{"2001:db8::/32", "2001:db8::/32^+", "::/0^48", "2001:db8::1"} {
		m, err := ParseSrcMember(item, types.ClassRouteSet)
		if err != nil || m.Kind != MemberPrefixRange || m.Source != "" {
			t.Errorf("ParseSrcMember(%q) = %+v, %v; want an IPv6 prefix member", item, m, err)
		}
	}
	if _, err := ParseSrcMember("2001:db8::/32", types.ClassAsSet); err == nil {
		t.Error("an IPv6 prefix was accepted in an as-set's src-members")
	}
}

func TestSetMemberRef(t *testing.T) {
	m, _ := ParseSetMember("AS-FOO", types.ClassAsSet)
	if r := m.Ref(); r.IsScoped() || r.String() != "AS-FOO" {
		t.Errorf("members: AS-FOO Ref = %v", r)
	}
	s, _ := ParseSrcMember("RIPE::AS-FOO", types.ClassAsSet)
	if r := s.Ref(); r.Source() != "RIPE" || r.Name().String() != "AS-FOO" {
		t.Errorf("src-members: RIPE::AS-FOO Ref = %v", r)
	}
	a, _ := ParseSetMember("AS1", types.ClassAsSet)
	if !a.Ref().IsZero() {
		t.Errorf("an AS member's Ref is %v, want zero", a.Ref())
	}
}
