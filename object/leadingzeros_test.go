package object

import (
	"net/netip"
	"strings"
	"testing"
)

// A zero-padded IPv4 octet is decimal (RFC 2622 §2 addresses are dotted
// decimal, and IRRd reads them so): the value is used in its canonical form,
// with one Warning per attribute that had one. ARIN's IRR holds routes written
// this way.
func TestLeadingZeros(t *testing.T) {
	warnings := func(t *testing.T, src, rule string, lines ...int) Object {
		t.Helper()
		obj, diags := Decode(parse(src))
		var got []int
		for _, d := range diags {
			if d.Rule != rule || d.Severity.String() != "warning" || !strings.Contains(d.Message, "decimal") {
				t.Errorf("unexpected diagnostic %+v", d)
				continue
			}
			got = append(got, d.Span.StartLine)
		}
		if len(got) != len(lines) {
			t.Fatalf("warnings on lines %v, want %v", got, lines)
		}
		for i := range got {
			if got[i] != lines[i] {
				t.Fatalf("warnings on lines %v, want %v", got, lines)
			}
		}
		return obj
	}

	r := warnings(t, "route:    064.006.160.000/19\norigin:   AS1\nholes:    064.006.161.000/24\npingable: 064.006.160.001\n",
		"object/route-leading-zeros", 1, 3, 4).(Route)
	if r.Prefix != netip.MustParsePrefix("64.6.160.0/19") ||
		len(r.Holes) != 1 || r.Holes[0] != netip.MustParsePrefix("64.6.161.0/24") ||
		len(r.Pingable) != 1 || r.Pingable[0] != netip.MustParseAddr("64.6.160.1") {
		t.Errorf("route decoded as %v holes %v pingable %v", r.Prefix, r.Holes, r.Pingable)
	}

	n := warnings(t, "inetnum: 064.006.160.000 - 064.006.191.255\n", "object/inetnum-leading-zeros", 1).(Inetnum)
	if n.Lo != netip.MustParseAddr("64.6.160.0") || n.Hi != netip.MustParseAddr("64.6.191.255") {
		t.Errorf("inetnum decoded as %v - %v", n.Lo, n.Hi)
	}

	rs := warnings(t, "route-set: RS-X\nmembers:   064.006.160.000/19^+, 192.0.2.0/24\n",
		"object/route-set-leading-zeros", 2).(RouteSet)
	if len(rs.Members) != 2 || rs.Members[0].Range.String() != "64.6.160.0/19^+" {
		t.Errorf("route-set members %+v", rs.Members)
	}

	// A padded prefix with host bits set is reported for both.
	_, diags := Decode(parse("route-set: RS-X\nmembers:   064.006.160.001/19\n"))
	rules := map[string]bool{}
	for _, d := range diags {
		rules[d.Rule] = true
	}
	if !rules["object/route-set-leading-zeros"] || !rules["object/route-set-members-host-bits"] {
		t.Errorf("diagnostics %v, want both leading-zeros and host-bits", diags)
	}
}
