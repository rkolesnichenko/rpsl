package types

import (
	"strings"
	"testing"
)

// FuzzParseSetName: never panics; anything accepted is confined to the RPSL
// name alphabet (so it is safe to interpolate into an IRRd/whois query) and
// re-parses to an identical value.
func FuzzParseSetName(f *testing.F) {
	for _, s := range []string{
		"AS-FOO", "as1:as-x:AS2", "AS1.10:RS-Y", "AS-FOO^+", "AS-A, AS-B",
		"AS-FOO\n!iAS-B", "PeerAS:AS-X", "AS-X::AS-Y", "fltr-a_b-9",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		n, err := ParseSetName(s)
		if err != nil {
			return
		}
		str := n.String()
		if strings.Trim(str, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-.:") != "" {
			t.Fatalf("ParseSetName(%q) accepted out-of-alphabet name %q", s, str)
		}
		again, err := ParseSetName(str)
		if err != nil || again != n {
			t.Fatalf("re-parse of %q = %+v, %v; want %+v", str, again, err, n)
		}
	})
}

// FuzzParseRangeOperator: never panics; accepted operators round-trip through
// String and never exceed the 128-bit family length.
func FuzzParseRangeOperator(f *testing.F) {
	for _, s := range []string{"+", "-", "24", "24-32", "+24", "129", "0-128"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		op, err := ParseRangeOperator(s)
		if err != nil {
			return
		}
		if op.N > 128 || op.M > 128 || op.N > op.M {
			t.Fatalf("ParseRangeOperator(%q) = %+v out of bounds", s, op)
		}
		again, err := ParseRangeOperator(strings.TrimPrefix(op.String(), "^"))
		if err != nil || again != op {
			t.Fatalf("round-trip of %q via %q = %+v, %v", s, op.String(), again, err)
		}
	})
}
