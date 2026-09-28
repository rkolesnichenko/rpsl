package object

import (
	"strings"
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

func refsOf(ms []SetMember) []string {
	var out []string
	for _, m := range ms {
		switch m.Kind {
		case MemberSet:
			s := m.Ref().String()
			if !m.Op.IsZero() {
				s += m.Op.String()
			}
			out = append(out, s)
		case MemberAS:
			s := m.AS.String()
			if !m.Op.IsZero() {
				s += m.Op.String()
			}
			out = append(out, s)
		case MemberPrefixRange:
			out = append(out, m.Range.String())
		}
	}
	return out
}

func TestDirectMembers(t *testing.T) {
	for _, tc := range []struct {
		name, src string
		want      []string
	}{
		{"no src-members", "route-set: RS-X\nmembers: RS-A, AS1\n", []string{"RS-A", "AS1"}},
		{"draft figure 1", "route-set: RS-FIRST\nmembers: RS-SECOND\nmp-members: RS-LEGACY\nsrc-members: RIPE::RS-SECOND\n",
			[]string{"RIPE::RS-SECOND", "RS-LEGACY"}},
		{"src operator wins", "route-set: RS-X\nmembers: RS-Y^-\nsrc-members: RIPE::RS-Y^+\n", []string{"RIPE::RS-Y^+"}},
		{"ASN key ignores operator", "route-set: RS-X\nmembers: AS1^24\nsrc-members: AS1\n", []string{"AS1"}},
		{"prefix key keeps operator", "route-set: RS-X\nmembers: 192.0.2.0/24^+\nsrc-members: 192.0.2.0/24\n",
			[]string{"192.0.2.0/24", "192.0.2.0/24^+"}},
		{"unlisted is followed", "as-set: AS-X\nmembers: AS1\nsrc-members: RIPE::AS-Z\n", []string{"RIPE::AS-Z", "AS1"}},
		{"conflict falls back to members", "as-set: AS-X\nmembers: AS-O\nsrc-members: RIPE::AS-O, ARIN::AS-O\n", []string{"AS-O"}},
	} {
		obj, _ := Decode(parse(tc.src))
		got := refsOf(DirectMembers(obj.(Set)))
		if strings.Join(got, " ") != strings.Join(tc.want, " ") {
			t.Errorf("%s: DirectMembers = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A set built by hand, bypassing the decoder, gets the same conflict rule.
func TestDirectMembersConflictOnHandBuiltSet(t *testing.T) {
	o, _ := ParseSetMember("AS-O", types.ClassAsSet)
	a, _ := ParseSrcMember("RIPE::AS-O", types.ClassAsSet)
	b, _ := ParseSrcMember("ARIN::AS-O", types.ClassAsSet)
	set := AsSet{Members: []SetMember{o}, SrcMembers: []SetMember{a, b}}
	if got := refsOf(DirectMembers(set)); strings.Join(got, " ") != "AS-O" {
		t.Errorf("DirectMembers = %v, want [AS-O]", got)
	}
}
