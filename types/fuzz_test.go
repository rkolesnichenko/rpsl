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

// FuzzParsePrefixRange: never panics; an accepted range is canonical (its
// prefix masked, and re-parsing its String gives the identical value), and a
// small window enumerates exactly the number of prefixes it spans.
func FuzzParsePrefixRange(f *testing.F) {
	for _, s := range []string{
		"10.0.0.0/8", "10.0.0.1/8^+", "10.0.0.0/8^24-24", "0.0.0.0/0^0-32",
		"192.0.2.1/32^-", "2001:db8::/32^48", "10.0.0.0/8^9-32", "::/0^+",
		"064.006.160.000/19^+", "010.0.0.0/8",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		// Whatever ParsePrefix accepts, zero-padded or not, its canonical form
		// parses back to the same prefix and is not padded.
		if p, err := ParsePrefix(s); err == nil {
			if again, err := ParsePrefix(p.String()); err != nil || again != p || PaddedIPv4(p.String()) {
				t.Fatalf("ParsePrefix(%q) = %v, whose form parses back as %v, %v (padded %v)", s, p, again, err, PaddedIPv4(p.String()))
			}
		}
		r, err := ParsePrefixRange(s)
		if err != nil {
			return
		}
		if r.Prefix() != r.Prefix().Masked() {
			t.Fatalf("ParsePrefixRange(%q) kept host bits: %s", s, r.Prefix())
		}
		again, err := ParsePrefixRange(r.String())
		if err != nil || again != r {
			t.Fatalf("re-parse of %q via %q = %+v, %v; want %+v", s, r.String(), again, err, r)
		}
		c, ok := NewPrefixRange(r.Prefix(), r.Lo(), r.Hi())
		if ok == r.IsEmpty() || (ok && c != r) {
			t.Fatalf("ParsePrefixRange(%q) = %+v is not canonical (%+v, %v)", s, r, c, ok)
		}
		if !ok || c.Hi()-c.Prefix().Bits() > 12 {
			return
		}
		want := 0
		for l := c.Lo(); l <= c.Hi(); l++ {
			want += 1 << (l - c.Prefix().Bits())
		}
		n := 0
		for range c.All() {
			n++
		}
		if n != want {
			t.Fatalf("%s enumerates %d prefixes, want %d", c, n, want)
		}
	})
}
