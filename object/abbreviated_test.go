package object

import (
	"net/netip"
	"strings"
	"testing"
)

// An IPv4 prefix written with fewer than four octets reads with the missing
// ones zero, as IRRd reads it, with one Warning per value; RADB route-sets
// hold members such as "191.243.44/22".
func TestAbbreviatedPrefixes(t *testing.T) {
	warnings := func(t *testing.T, src, rule string, lines ...int) Object {
		t.Helper()
		obj, diags := Decode(parse(src))
		var got []int
		for _, d := range diags {
			if d.Rule != rule || d.Severity.String() != "warning" || !strings.Contains(d.Message, "abbreviated") {
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

	r := warnings(t, "route: 143.208.148/22\norigin: AS1\nholes: 143.208.149/24\n", "object/route-abbreviated-prefix", 1, 3).(Route)
	if r.Prefix != netip.MustParsePrefix("143.208.148.0/22") || len(r.Holes) != 1 || r.Holes[0] != netip.MustParsePrefix("143.208.149.0/24") {
		t.Errorf("route decoded as %v holes %v", r.Prefix, r.Holes)
	}

	rs := warnings(t, "route-set: RS-X\nmembers: 191.243.44/22, 192.0.2.0/24, 10/8^+\n", "object/route-set-abbreviated-prefix", 2, 2).(RouteSet)
	if len(rs.Members) != 3 || rs.Members[0].Range.String() != "191.243.44.0/22" || rs.Members[2].Range.String() != "10.0.0.0/8^+" {
		t.Errorf("route-set members %+v", rs.Members)
	}

	// Zero-padded and abbreviated at once: both are reported.
	_, diags := Decode(parse("route-set: RS-X\nmembers: 010.1/16\n"))
	rules := map[string]bool{}
	for _, d := range diags {
		rules[d.Rule] = true
	}
	if len(diags) != 2 || !rules["object/route-set-abbreviated-prefix"] || !rules["object/route-set-leading-zeros"] {
		t.Errorf("diagnostics %v, want abbreviated-prefix and leading-zeros", diags)
	}
}
