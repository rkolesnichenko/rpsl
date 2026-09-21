package types

import "testing"

func TestParseRangeOperator(t *testing.T) {
	cases := []struct {
		in   string
		want RangeOperator
		str  string
	}{
		{"+", RangeOperator{Op: RangePlus}, "^+"},
		{"-", RangeOperator{Op: RangeMinus}, "^-"},
		{"0", RangeOperator{Op: RangeLength, N: 0, M: 0}, "^0"},
		{"24", RangeOperator{Op: RangeLength, N: 24, M: 24}, "^24"},
		{"128", RangeOperator{Op: RangeLength, N: 128, M: 128}, "^128"},
		{"24-32", RangeOperator{Op: RangeRange, N: 24, M: 32}, "^24-32"},
		{"24-24", RangeOperator{Op: RangeRange, N: 24, M: 24}, "^24-24"},
	}
	for _, c := range cases {
		got, err := ParseRangeOperator(c.in)
		if err != nil {
			t.Errorf("ParseRangeOperator(%q) unexpected err: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseRangeOperator(%q) = %+v, want %+v", c.in, got, c.want)
		}
		if got.String() != c.str {
			t.Errorf("ParseRangeOperator(%q).String() = %q, want %q", c.in, got.String(), c.str)
		}
		if got.IsZero() {
			t.Errorf("ParseRangeOperator(%q).IsZero() = true", c.in)
		}
	}
	if (RangeOperator{}).String() != "" || !(RangeOperator{}).IsZero() {
		t.Error("zero RangeOperator must render as \"\" and report IsZero")
	}
}

func TestParseRangeOperatorRejects(t *testing.T) {
	for _, in := range []string{
		"", "+24", "24-", "-24", "32-24", "129", "24-129",
		" 24", "24 ", "2 4", "x", "0x10", "٣", "+-", "--",
	} {
		if got, err := ParseRangeOperator(in); err == nil {
			t.Errorf("ParseRangeOperator(%q) = %+v, want error", in, got)
		}
	}
}

// TestRangeOperatorApply pins RFC 2622 §5.2 composition: an outer ^n-m over an
// inner ^k-l becomes ^max(n,k)-m when m >= max(n,k); otherwise the prefix is
// deleted. ^+ / ^- resolve against the inner prefix's own length.
func TestRangeOperatorApply(t *testing.T) {
	cases := []struct {
		outer, inner string
		want         string // "" = prefix deleted
	}{
		// The two worked examples in RFC 2622 §5.2.
		{"-", "128.9.0.0/16^+", "128.9.0.0/16^-"},
		{"26-28", "128.9.0.0/16^20-24", "128.9.0.0/16^26-28"},
		// m < max(n,k): deleted.
		{"16", "10.0.0.0/8^24", ""},
		{"-", "192.0.2.1/32", ""}, // a host route has no more-specifics
		{"33", "10.0.0.0/8", ""},  // beyond the IPv4 bit length
		// Operators over exact prefixes (what an AS's originated routes are).
		{"+", "10.0.0.0/8", "10.0.0.0/8^+"},
		{"24", "10.0.0.0/8", "10.0.0.0/8^24"},
		{"24-48", "10.0.0.0/8", "10.0.0.0/8^24-32"}, // m clamped to the family
		{"48", "2001:db8::/32", "2001:db8::/32^48"},
		// Outer upper bound wins, lower bound is the max.
		{"+", "10.0.0.0/8^24-28", "10.0.0.0/8^24-32"},
		{"-", "10.0.0.0/8^24", "10.0.0.0/8^24-32"},
		// Results normalize to the canonical operator form.
		{"8", "10.0.0.0/8", "10.0.0.0/8"},
		{"0-8", "10.0.0.0/8^+", "10.0.0.0/8"},
	}
	for _, c := range cases {
		op, err := ParseRangeOperator(c.outer)
		if err != nil {
			t.Fatalf("ParseRangeOperator(%q): %v", c.outer, err)
		}
		in, err := ParsePrefixRange(c.inner)
		if err != nil {
			t.Fatalf("ParsePrefixRange(%q): %v", c.inner, err)
		}
		got, ok := op.Apply(in)
		switch {
		case c.want == "" && ok:
			t.Errorf("{%s}^%s = %s, want deleted", c.inner, c.outer, got)
		case c.want != "" && !ok:
			t.Errorf("{%s}^%s deleted, want %s", c.inner, c.outer, c.want)
		case ok && got.String() != c.want:
			t.Errorf("{%s}^%s = %s, want %s", c.inner, c.outer, got, c.want)
		}
	}

	// The zero operator is the identity.
	in, _ := ParsePrefixRange("10.0.0.0/8^+")
	if got, ok := (RangeOperator{}).Apply(in); !ok || got != in {
		t.Errorf("zero operator Apply = %v, %v; want %v unchanged", got, ok, in)
	}
}
