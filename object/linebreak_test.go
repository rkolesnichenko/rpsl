package object

import (
	"slices"
	"testing"

	"github.com/rkolesnichenko/rpsl/ast"
)

// Members on separate lines without commas are separate members, as IRRd
// reads them (RADB holds hundreds of such sets), with one Warning per
// attribute at the first item a line break separates.
func TestListLineBreaks(t *testing.T) {
	raws := func(ms []SetMember) []string {
		var out []string
		for _, m := range ms {
			out = append(out, m.Raw)
		}
		return out
	}
	lineBreaks := func(ds []ast.Diagnostic) []int {
		var lines []int
		for _, d := range ds {
			if d.Rule != "object/list-line-break" {
				t.Errorf("unexpected diagnostic %v", d)
				continue
			}
			if d.Severity != ast.Warning {
				t.Errorf("%v: want a Warning", d)
			}
			lines = append(lines, d.Span.StartLine)
		}
		return lines
	}

	obj, ds := Decode(parse("as-set:  AS-X\nmembers: AS1\n AS2, AS3\n AS-Y\nmembers: AS4, AS5\nsource: RADB\n"))
	if got := raws(obj.(AsSet).Members); !slices.Equal(got, []string{"AS1", "AS2", "AS3", "AS-Y", "AS4", "AS5"}) {
		t.Errorf("as-set members %q", got)
	}
	if got := lineBreaks(ds); !slices.Equal(got, []int{3}) {
		t.Errorf("Warnings on lines %v, want [3]: once per attribute, at the first item after a break", got)
	}

	obj, ds = Decode(parse("route-set: RS-X\nmp-members: 2001:db8::/32\n 2001:db8:1::/48^+\nsource: RADB\n"))
	if got := raws(obj.(RouteSet).MpMembers); !slices.Equal(got, []string{"2001:db8::/32", "2001:db8:1::/48^+"}) {
		t.Errorf("route-set mp-members %q", got)
	}
	if got := lineBreaks(ds); !slices.Equal(got, []int{3}) {
		t.Errorf("Warnings on lines %v, want [3]", got)
	}

	// Commas at line ends, a "+" line and a comment: no line break separates
	// items, so there is nothing to report.
	obj, ds = Decode(parse("as-set: AS-X\nmembers: AS1,\n AS2 # two\n+\n , AS3\nsource: RADB\n"))
	if got := raws(obj.(AsSet).Members); !slices.Equal(got, []string{"AS1", "AS2", "AS3"}) || len(ds) != 0 {
		t.Errorf("members %q, diagnostics %v", got, ds)
	}
}
