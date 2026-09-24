package object

import (
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/ast"
)

// A route-set member written as an address without a length is the host
// prefix, as IRRd reads it (ARIN's rs-HCHBNET lists "206.197.238.0"), with one
// Warning per member at the member's own span.
func TestNoLengthMembers(t *testing.T) {
	src := "route-set: RS-X\n" +
		"members: 192.0.2.0/24, 206.197.238.0, 198.51.100.7^+\n" +
		"mp-members: 2001:db8::32\n"
	obj, diags := Decode(parse(src))
	rs := obj.(RouteSet)
	var got []string
	for _, m := range append(rs.Members, rs.MpMembers...) {
		got = append(got, m.Range.String())
	}
	if want := "192.0.2.0/24 206.197.238.0/32 198.51.100.7/32 2001:db8::32/128"; strings.Join(got, " ") != want {
		t.Errorf("members %q, want %q", got, want)
	}
	want := []struct {
		rule string
		col  int
	}{
		{"object/route-set-members-no-length", 24},
		{"object/route-set-members-no-length", 39},
		{"object/route-set-mp-members-no-length", 13},
	}
	if len(diags) != len(want) {
		t.Fatalf("diagnostics %+v, want %d", diags, len(want))
	}
	for i, d := range diags {
		if d.Rule != want[i].rule || d.Severity != ast.Warning || d.Span.StartCol != want[i].col ||
			!strings.Contains(d.Message, "no prefix length") {
			t.Errorf("diagnostic %d = %+v, want %s Warning at column %d", i, d, want[i].rule, want[i].col)
		}
	}

	// An IPv6 address in members: is reported for both reasons.
	_, diags = Decode(parse("route-set: RS-X\nmembers: 2001:db8::1\n"))
	rules := map[string]bool{}
	for _, d := range diags {
		rules[d.Rule] = true
	}
	if len(diags) != 2 || !rules["object/route-set-members-no-length"] || !rules["object/route-set-members-afi"] {
		t.Errorf("diagnostics %v, want no-length and afi", diags)
	}

	// Zero-padded as well: both are reported.
	_, diags = Decode(parse("route-set: RS-X\nmembers: 010.0.0.1\n"))
	rules = map[string]bool{}
	for _, d := range diags {
		rules[d.Rule] = true
	}
	if len(diags) != 2 || !rules["object/route-set-members-no-length"] || !rules["object/route-set-leading-zeros"] {
		t.Errorf("diagnostics %v, want no-length and leading-zeros", diags)
	}

	// Not a prefix at all in an as-set: still the member Error.
	_, diags = Decode(parse("as-set: AS-X\nmembers: 192.0.2.1\n"))
	if len(diags) != 1 || diags[0].Rule != "object/as-set-members" || diags[0].Severity != ast.Error {
		t.Errorf("as-set diagnostics %v, want one object/as-set-members Error", diags)
	}
}
