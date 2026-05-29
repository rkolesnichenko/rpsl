package types

import (
	"net/netip"
	"testing"
)

func TestParseASN(t *testing.T) {
	cases := []struct {
		in   string
		want ASN
		ok   bool
	}{
		{"AS65001", 65001, true},
		{"as65001", 65001, true},
		{"AS1.10", 1<<16 | 10, true}, // asdot
		{"AS0", 0, true},
		{"AS4294967295", 4294967295, true},
		{"AS4294967296", 0, false}, // overflow
		{"65001", 0, false},        // no prefix
		{"ASfoo", 0, false},
		{"AS", 0, false},
	}
	for _, c := range cases {
		got, err := ParseASN(c.in)
		if (err == nil) != c.ok {
			t.Errorf("ParseASN(%q) err=%v, ok=%v", c.in, err, c.ok)
			continue
		}
		if c.ok && got != c.want {
			t.Errorf("ParseASN(%q) = %d, want %d", c.in, got, c.want)
		}
	}
	if got := ASN(65001).String(); got != "AS65001" {
		t.Errorf("String = %q, want AS65001", got)
	}
}

func TestParseSetName(t *testing.T) {
	cases := []struct {
		in    string
		ok    bool
		class SetClass
	}{
		{"AS-FOO", true, AsSet},
		{"RS-BAR", true, RouteSet},
		{"RTRS-X", true, RtrSet},
		{"FLTR-Y", true, FilterSet},
		{"PRNG-Z", true, PeeringSet},
		{"AS3333:AS-CUSTOMERS", true, AsSet},
		{"AS3333:AS-CUSTOMERS:RS-FOO", true, RouteSet},
		{"AS3333", false, SetClassUnknown}, // bare ASN: no set component
		{"AS3333::AS-FOO", false, SetClassUnknown},
		{"random", false, SetClassUnknown},
	}
	for _, c := range cases {
		n, err := ParseSetName(c.in)
		if (err == nil) != c.ok {
			t.Errorf("ParseSetName(%q) err=%v, ok=%v", c.in, err, c.ok)
			continue
		}
		if !c.ok {
			continue
		}
		if n.Class != c.class {
			t.Errorf("ParseSetName(%q).Class = %v, want %v", c.in, n.Class, c.class)
		}
		if n.String() != c.in {
			t.Errorf("String = %q, want %q", n.String(), c.in)
		}
	}
	n, _ := ParseSetName("as3333:as-foo")
	if n.Canonical() != "AS3333:AS-FOO" {
		t.Errorf("Canonical = %q, want AS3333:AS-FOO", n.Canonical())
	}
}

func TestParsePrefixRange(t *testing.T) {
	cases := []struct {
		in   string
		ok   bool
		op   RangeOp
		lo   uint8
		hi   uint8
	}{
		{"192.0.2.0/24", true, RangeExact, 24, 24},
		{"192.0.2.0/24^+", true, RangePlus, 24, 32},
		{"192.0.2.0/24^-", true, RangeMinus, 25, 32},
		{"192.0.2.0/24^26", true, RangeLength, 26, 26},
		{"192.0.2.0/24^26-28", true, RangeRange, 26, 28},
		{"2001:db8::/32^48", true, RangeLength, 48, 48},
		{"192.0.2.0/24^20", false, 0, 0, 0},    // shorter than prefix
		{"192.0.2.0/24^28-26", false, 0, 0, 0}, // m < n
		{"192.0.2.0/24^x", false, 0, 0, 0},
		{"notaprefix^+", false, 0, 0, 0},
	}
	for _, c := range cases {
		r, err := ParsePrefixRange(c.in)
		if (err == nil) != c.ok {
			t.Errorf("ParsePrefixRange(%q) err=%v, ok=%v", c.in, err, c.ok)
			continue
		}
		if !c.ok {
			continue
		}
		if r.Op != c.op || r.Lo != c.lo || r.Hi != c.hi {
			t.Errorf("ParsePrefixRange(%q) = {op=%d lo=%d hi=%d}, want {op=%d lo=%d hi=%d}",
				c.in, r.Op, r.Lo, r.Hi, c.op, c.lo, c.hi)
		}
		if r.String() != c.in {
			t.Errorf("String = %q, want %q", r.String(), c.in)
		}
	}
}

func TestMaterialize(t *testing.T) {
	// ^26 over a /24 -> four /26s.
	r, _ := ParsePrefixRange("192.0.2.0/24^26")
	got, err := r.Materialize(100)
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	want := []string{"192.0.2.0/26", "192.0.2.64/26", "192.0.2.128/26", "192.0.2.192/26"}
	if len(got) != len(want) {
		t.Fatalf("got %d prefixes, want %d: %v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i] != netip.MustParsePrefix(w) {
			t.Errorf("prefix %d = %s, want %s", i, got[i], w)
		}
	}

	// Exact yields the prefix itself.
	r, _ = ParsePrefixRange("192.0.2.0/24")
	if got, _ := r.Materialize(10); len(got) != 1 || got[0] != netip.MustParsePrefix("192.0.2.0/24") {
		t.Errorf("exact Materialize = %v, want [192.0.2.0/24]", got)
	}

	// ^- on a host prefix is empty.
	r, _ = ParsePrefixRange("192.0.2.1/32^-")
	if got, err := r.Materialize(10); err != nil || len(got) != 0 {
		t.Errorf("host ^- = %v (err %v), want empty", got, err)
	}

	// ^+ on a /0 blows past the cap.
	r, _ = ParsePrefixRange("0.0.0.0/0^+")
	if _, err := r.Materialize(1000); err != ErrTooManyPrefixes {
		t.Errorf("/0 ^+ err = %v, want ErrTooManyPrefixes", err)
	}
}

func TestParseNICHandle(t *testing.T) {
	for _, in := range []string{"EX1-RIPE", "AUTO-1", "DUMY-RIPE"} {
		if _, err := ParseNICHandle(in); err != nil {
			t.Errorf("ParseNICHandle(%q) unexpected err: %v", in, err)
		}
	}
	for _, in := range []string{"", "1EX-RIPE", "EX@RIPE"} {
		if _, err := ParseNICHandle(in); err == nil {
			t.Errorf("ParseNICHandle(%q) expected error", in)
		}
	}
}
