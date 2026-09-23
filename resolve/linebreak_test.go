package resolve

import (
	"context"
	"reflect"
	"testing"

	"github.com/rkolesnichenko/rpsl/resolve/internal/irrtest"
)

// A set whose members are on separate lines without commas expands to all of
// them, as IRRd (and so bgpq4) reads it, and irrtest answers !i the same way.
func TestLineSeparatedMembers(t *testing.T) {
	ctx := context.Background()
	asx := "as-set: AS-X\nmembers: AS1\n AS2\n AS-Y\nsource: TEST\n"
	src := corpus(t, asx, asSet("AS-Y", "AS3"),
		"route-set: RS-X\nmembers: 192.0.2.0/24\n 198.51.100.0/24^+\nsource: TEST\n")
	got, err := (&Expander{Src: src}).ExpandAS(ctx, mustSet(t, "AS-X"))
	if err != nil || !reflect.DeepEqual(asnList(got), []uint32{1, 2, 3}) {
		t.Errorf("ExpandAS(AS-X) = %v, %v; want [1 2 3]", asnList(got), err)
	}
	rs, err := (&Expander{Src: src}).ExpandPrefixRanges(ctx, mustSet(t, "RS-X"))
	if err != nil || len(rs.List()) != 2 {
		t.Errorf("ExpandPrefixRanges(RS-X) = %v, %v; want two ranges", rs.List(), err)
	}
	if m, ok := irrtest.New(asx).Members([]string{"TEST"}, "AS-X"); !ok || !reflect.DeepEqual(m, []string{"AS1", "AS2", "AS-Y"}) {
		t.Errorf("irrtest !iAS-X = %q, %v; want [AS1 AS2 AS-Y]", m, ok)
	}
}
