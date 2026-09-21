package rpsl

import (
	"os"
	"reflect"
	"testing"

	"github.com/rkolesnichenko/rpsl/object"
)

// A RADB-style as-set using comma-separated, folded lists decodes item by item
// (RFC 2622 §2), with no diagnostics, while still round-tripping (TestRoundTrip).
func TestCorpusListDecoding(t *testing.T) {
	src, err := os.ReadFile("testdata/corpus/as-set-radb-lists.txt")
	if err != nil {
		t.Fatal(err)
	}
	obj, diags := ParseObject(string(src))
	typed, ddiags := Decode(obj)
	if len(diags)+len(ddiags) != 0 {
		t.Fatalf("diagnostics: %+v %+v", diags, ddiags)
	}
	s := typed.(object.AsSet)
	var members []string
	for _, m := range s.Members {
		members = append(members, m.Raw)
	}
	if want := []string{"AS65001", "AS65002", "AS65003", "AS-EXAMPLE-DOWN", "AS65010", "AS65011"}; !reflect.DeepEqual(members, want) {
		t.Errorf("members = %q, want %q", members, want)
	}
	if want := []string{"MAINT-EXAMPLE", "MAINT-OTHER"}; !reflect.DeepEqual(s.MbrsByRef, want) || !reflect.DeepEqual(s.MntBy, want) {
		t.Errorf("MbrsByRef = %q, MntBy = %q, want %q", s.MbrsByRef, s.MntBy, want)
	}
}
