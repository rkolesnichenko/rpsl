package object

import (
	"reflect"
	"testing"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/types"
)

func TestParseSetMember(t *testing.T) {
	op := func(s string) types.RangeOperator {
		o, err := types.ParseRangeOperator(s)
		if err != nil {
			t.Fatalf("ParseRangeOperator(%q): %v", s, err)
		}
		return o
	}
	cases := []struct {
		item      string
		container types.SetClass
		kind      MemberKind
		as        types.ASN
		set       string // canonical
		rng       string
		op        types.RangeOperator
	}{
		{"AS1", types.ClassAsSet, MemberAS, 1, "", "", types.RangeOperator{}},
		{"AS-FOO", types.ClassAsSet, MemberSet, 0, "AS-FOO", "", types.RangeOperator{}},
		{"RS-FOO", types.ClassAsSet, MemberSet, 0, "RS-FOO", "", types.RangeOperator{}}, // mismatch is a decoder warning, not a parse error
		{"AS1^24", types.ClassRouteSet, MemberAS, 1, "", "", op("24")},
		{"RS-FOO^+", types.ClassRouteSet, MemberSet, 0, "RS-FOO", "", op("+")},
		{"AS-FOO^-", types.ClassRouteSet, MemberSet, 0, "AS-FOO", "", op("-")},
		{"10.0.0.0/8^16-24", types.ClassRouteSet, MemberPrefixRange, 0, "", "10.0.0.0/8^16-24", types.RangeOperator{}},
	}
	for _, c := range cases {
		m, err := ParseSetMember(c.item, c.container)
		if err != nil {
			t.Errorf("ParseSetMember(%q, %v) unexpected err: %v", c.item, c.container, err)
			continue
		}
		if m.Kind != c.kind || m.AS != c.as || m.Set.String() != c.set || m.Op != c.op || m.Raw != c.item {
			t.Errorf("ParseSetMember(%q, %v) = %+v", c.item, c.container, m)
		}
		if c.rng != "" && m.Range.String() != c.rng {
			t.Errorf("ParseSetMember(%q).Range = %s, want %s", c.item, m.Range, c.rng)
		}
	}
}

// Failures are MemberInvalid — never the zero-valued MemberAS (which the
// engine used to read as a phantom AS0).
func TestParseSetMemberRejects(t *testing.T) {
	for _, c := range []struct {
		item      string
		container types.SetClass
	}{
		{"garbage!!", types.ClassRouteSet},
		{"AS1 AS2", types.ClassAsSet},       // whitespace is not a list separator
		{"AS1^+", types.ClassAsSet},         // operators are route-set only
		{"192.0.2.0/24", types.ClassAsSet},  // prefixes are route-set only
		{"AS1^", types.ClassRouteSet},       // empty operator
		{"RS-FOO^+24", types.ClassRouteSet}, // signed operator
		{"RS-FOO^+^+", types.ClassRouteSet}, // doubled operator
		{"", types.ClassAsSet},
	} {
		m, err := ParseSetMember(c.item, c.container)
		if err == nil || m.Kind != MemberInvalid || m.Raw != c.item {
			t.Errorf("ParseSetMember(%q, %v) = %+v, %v; want MemberInvalid with Raw and an error",
				c.item, c.container, m, err)
		}
	}
	if (SetMember{}).Kind != MemberInvalid {
		t.Error("the zero SetMember must be MemberInvalid")
	}
}

func TestDecodeCommaSeparatedMembers(t *testing.T) {
	obj, diags := Decode(parse("as-set: AS-X\nmembers: AS1, AS2, AS-BAR\nmp-members: AS3\n"))
	if len(diags) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", diags)
	}
	s := obj.(AsSet)
	var got []string
	for _, m := range s.SetMembers() {
		got = append(got, m.Raw)
	}
	if !reflect.DeepEqual(got, []string{"AS1", "AS2", "AS-BAR", "AS3"}) {
		t.Errorf("members = %q, want [AS1 AS2 AS-BAR AS3]", got)
	}
	if s.Members[2].Kind != MemberSet || s.Members[2].Set.String() != "AS-BAR" {
		t.Errorf("member 2 = %+v, want set AS-BAR", s.Members[2])
	}
}

func TestDecodeRouteSetMemberOperators(t *testing.T) {
	obj, diags := Decode(parse("route-set: RS-A\nmembers: RS-B^+, AS5^24, 10.0.0.0/8^16-24\n"))
	if len(diags) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", diags)
	}
	m := obj.(RouteSet).Members
	if len(m) != 3 {
		t.Fatalf("members = %+v, want 3", m)
	}
	if m[0].Kind != MemberSet || m[0].Set.String() != "RS-B" || m[0].Op.String() != "^+" {
		t.Errorf("member 0 = %+v, want RS-B with ^+", m[0])
	}
	if m[1].Kind != MemberAS || m[1].AS != 5 || m[1].Op.String() != "^24" {
		t.Errorf("member 1 = %+v, want AS5 with ^24", m[1])
	}
	if m[2].Kind != MemberPrefixRange || m[2].Range.String() != "10.0.0.0/8^16-24" {
		t.Errorf("member 2 = %+v, want 10.0.0.0/8^16-24", m[2])
	}
}

// An unparseable item is kept as MemberInvalid between its valid neighbours,
// and its Error points at the item itself, not the whole attribute.
func TestInvalidMemberDiagnosedAtItem(t *testing.T) {
	obj, diags := Decode(parse("as-set: AS-X\nmembers: AS1, garbage!!, AS2\n"))
	m := obj.(AsSet).Members
	if len(m) != 3 || m[0].AS != 1 || m[1].Kind != MemberInvalid || m[1].Raw != "garbage!!" || m[2].AS != 2 {
		t.Fatalf("members = %+v, want AS1, invalid garbage!!, AS2", m)
	}
	if len(diags) != 1 || diags[0].Severity != ast.Error || diags[0].Rule != "object/as-set-members" {
		t.Fatalf("diags = %+v, want one object/as-set-members error", diags)
	}
	if sp := diags[0].Span; sp.StartLine != 2 || sp.StartCol != 15 || sp.EndCol != 24 {
		t.Errorf("error span = %d:%d-%d, want 2:15-24 (the item)", sp.StartLine, sp.StartCol, sp.EndCol)
	}
}

func TestEmptyListItemsWarn(t *testing.T) {
	obj, diags := Decode(parse("as-set: AS-X\nmembers: AS1,,AS2,\n"))
	if m := obj.(AsSet).Members; len(m) != 2 || m[0].AS != 1 || m[1].AS != 2 {
		t.Errorf("members = %+v, want [AS1 AS2]", m)
	}
	n := 0
	for _, d := range diags {
		if d.Rule == "object/list-empty-item" && d.Severity == ast.Warning {
			n++
		}
	}
	if n != 2 || len(diags) != 2 {
		t.Errorf("diags = %+v, want two object/list-empty-item warnings", diags)
	}
}

// Every RFC 2622 list-valued attribute the decoders read is split on commas.
func TestListAttributesSplit(t *testing.T) {
	keys := map[string]string{
		"aut-num": "AS1", "mntner": "MNT-X", "person": "P", "role": "R",
		"route": "192.0.2.0/24", "route6": "2001:db8::/32", "as-set": "AS-X",
		"route-set": "RS-X", "inetnum": "192.0.2.0 - 192.0.2.255",
		"inet6num": "2001:db8::/32", "as-block": "AS1 - AS10", "inet-rtr": "r.example",
		"irt": "IRT-X", "domain": "2.0.192.in-addr.arpa", "organisation": "ORG-X",
		"peering-set": "PRNG-X", "filter-set": "FLTR-X", "rtr-set": "RTRS-X",
	}
	for class, key := range keys {
		obj, _ := Decode(parse(class + ": " + key + "\nmnt-by: MNT-A, MNT-B\n"))
		f := reflect.ValueOf(obj).FieldByName("MntBy")
		if !f.IsValid() {
			t.Fatalf("%s: decoded %T has no MntBy field", class, obj)
		}
		if got := f.Interface().([]string); !reflect.DeepEqual(got, []string{"MNT-A", "MNT-B"}) {
			t.Errorf("%s: MntBy = %q, want [MNT-A MNT-B]", class, got)
		}
	}

	for _, class := range []string{"as-set", "route-set", "rtr-set"} {
		obj, _ := Decode(parse(class + ": " + keys[class] + "\nmbrs-by-ref: MNT-A, MNT-B\n"))
		got := reflect.ValueOf(obj).FieldByName("MbrsByRef").Interface().([]string)
		if !reflect.DeepEqual(got, []string{"MNT-A", "MNT-B"}) {
			t.Errorf("%s: MbrsByRef = %q, want [MNT-A MNT-B]", class, got)
		}
	}

	canon := func(ns []types.SetName) []string {
		var out []string
		for _, n := range ns {
			out = append(out, n.String())
		}
		return out
	}
	r := mustDecode(t, "route: 192.0.2.0/24\norigin: AS1\nmember-of: RS-A, rs-b\nholes: 192.0.2.0/25, 192.0.2.128/26\n").(Route)
	if got := canon(r.MemberOf); !reflect.DeepEqual(got, []string{"RS-A", "RS-B"}) {
		t.Errorf("route MemberOf = %q, want [RS-A RS-B]", got)
	}
	if len(r.Holes) != 2 || r.Holes[1].String() != "192.0.2.128/26" {
		t.Errorf("route Holes = %v, want 2 holes", r.Holes)
	}
	r6 := mustDecode(t, "route6: 2001:db8::/32\norigin: AS1\nmember-of: RS-A, RS-B\nholes: 2001:db8::/48, 2001:db8:1::/48\n").(Route6)
	if got := canon(r6.MemberOf); !reflect.DeepEqual(got, []string{"RS-A", "RS-B"}) || len(r6.Holes) != 2 {
		t.Errorf("route6 MemberOf = %q, Holes = %v", got, r6.Holes)
	}
	ir := mustDecode(t, "inet-rtr: r.example\nmember-of: RTRS-A, RTRS-B\n").(InetRtr)
	if got := canon(ir.MemberOf); !reflect.DeepEqual(got, []string{"RTRS-A", "RTRS-B"}) {
		t.Errorf("inet-rtr MemberOf = %q, want [RTRS-A RTRS-B]", got)
	}
	rs := mustDecode(t, "rtr-set: RTRS-X\nmembers: r1.example, RTRS-Y\nmp-members: 2001:db8::1, r2.example\n").(RtrSet)
	if !reflect.DeepEqual(rs.Members, []string{"r1.example", "RTRS-Y"}) ||
		!reflect.DeepEqual(rs.MpMembers, []string{"2001:db8::1", "r2.example"}) {
		t.Errorf("rtr-set Members = %q, MpMembers = %q", rs.Members, rs.MpMembers)
	}
}

// mustDecode decodes src and fails on any diagnostic.
func mustDecode(t *testing.T, src string) Object {
	t.Helper()
	obj, diags := Decode(parse(src))
	if len(diags) != 0 {
		t.Fatalf("Decode(%q) diagnostics: %+v", src, diags)
	}
	return obj
}
