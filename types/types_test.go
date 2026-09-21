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
		class SetClass
		str   string // String(): the trimmed original spelling
		canon string
	}{
		{"AS-FOO", AsSet, "AS-FOO", "AS-FOO"},
		{"as-foo", AsSet, "as-foo", "AS-FOO"},
		{"AS-51155_customers", AsSet, "AS-51155_customers", "AS-51155_CUSTOMERS"},
		{"RS-BAR", RouteSet, "RS-BAR", "RS-BAR"},
		{"RTRS-X", RtrSet, "RTRS-X", "RTRS-X"},
		{"FLTR-Y", FilterSet, "FLTR-Y", "FLTR-Y"},
		{"PRNG-Z", PeeringSet, "PRNG-Z", "PRNG-Z"},
		{"AS-ANY", AsSet, "AS-ANY", "AS-ANY"},
		{"RS-ANY", RouteSet, "RS-ANY", "RS-ANY"},
		{"AS3333:AS-CUSTOMERS", AsSet, "AS3333:AS-CUSTOMERS", "AS3333:AS-CUSTOMERS"},
		{"AS-X:AS1:AS-Y", AsSet, "AS-X:AS1:AS-Y", "AS-X:AS1:AS-Y"},
		{"as3333:as-foo", AsSet, "as3333:as-foo", "AS3333:AS-FOO"},
		{"AS007:AS-X", AsSet, "AS007:AS-X", "AS7:AS-X"},       // ASN components normalized
		{"AS1.10:AS-X", AsSet, "AS1.10:AS-X", "AS65546:AS-X"}, // asdot normalized
		{"  AS-FOO\t", AsSet, "AS-FOO", "AS-FOO"},             // outer whitespace trimmed
	}
	for _, c := range cases {
		n, err := ParseSetName(c.in)
		if err != nil {
			t.Errorf("ParseSetName(%q) unexpected err: %v", c.in, err)
			continue
		}
		if n.Class() != c.class {
			t.Errorf("ParseSetName(%q).Class() = %v, want %v", c.in, n.Class(), c.class)
		}
		if n.String() != c.str {
			t.Errorf("ParseSetName(%q).String() = %q, want %q", c.in, n.String(), c.str)
		}
		if n.Canonical() != c.canon {
			t.Errorf("ParseSetName(%q).Canonical() = %q, want %q", c.in, n.Canonical(), c.canon)
		}
		if n.IsZero() {
			t.Errorf("ParseSetName(%q).IsZero() = true", c.in)
		}
	}
}

// Everything here was accepted by the old prefix-only check. Each is either
// RFC 2622 §2/§5-invalid or a query-injection vector for the IRRd/whois
// backends, which interpolate SetName.String() into the wire command.
func TestParseSetNameRejects(t *testing.T) {
	for _, in := range []string{
		"", "   ",
		"AS-",                // nothing after the prefix
		"AS-FOO-", "AS-FOO_", // last char must be a letter or digit
		"AS-FOO BAR",            // whitespace
		"AS-A, AS-B",            // an unsplit list
		"AS-FOO^+", "RS-FOO^24", // a range operator glued on
		"AS-FOO\n!iAS-B",            // IRRd command injection
		"AS-FOO -i mnt-by EVIL-MNT", // whois flag injection
		"AS-FO#O", "as-😀",
		"AS-X:RS-Y",                  // set components of different classes
		"AS3333:AS-CUSTOMERS:RS-FOO", // (same rule)
		"AS3333", "AS1:AS2",          // no set component
		"AS-X::AS-Y", ":AS-X", "AS-X:",
		"AS1 :AS-X", "ASx:AS-X", "AS4294967296:AS-X",
		"PeerAS:AS-X", // a policy template, not a set name
		"random",
	} {
		if n, err := ParseSetName(in); err == nil {
			t.Errorf("ParseSetName(%q) = %q, want error", in, n.String())
		}
	}
}

func TestSetNameValueSemantics(t *testing.T) {
	a, _ := ParseSetName("AS1:AS-X")
	b, _ := ParseSetName("AS1:AS-X")
	lower, _ := ParseSetName("as1:as-x")

	// Comparable: usable as a map key, == is spelling-exact.
	seen := map[SetName]bool{a: true}
	if !seen[b] {
		t.Error("identically spelled SetNames are not == (map lookup missed)")
	}
	if a == lower {
		t.Error("differently spelled SetNames compare ==; == must be spelling-exact")
	}
	if a.Canonical() != lower.Canonical() {
		t.Errorf("Canonical differs: %q vs %q", a.Canonical(), lower.Canonical())
	}

	// Components returns a fresh slice; mutating it cannot alter the name.
	comps := a.Components()
	if len(comps) != 2 || comps[0] != "AS1" || comps[1] != "AS-X" {
		t.Fatalf("Components() = %q, want [AS1 AS-X]", comps)
	}
	comps[0] = "AS666"
	if a.String() != "AS1:AS-X" {
		t.Errorf("mutating Components() changed the name to %q", a.String())
	}

	var zero SetName
	if !zero.IsZero() || zero.String() != "" || zero.Class() != SetClassUnknown {
		t.Errorf("zero SetName: IsZero=%v String=%q Class=%v", zero.IsZero(), zero.String(), zero.Class())
	}
}

func TestParsePrefixRange(t *testing.T) {
	cases := []struct {
		in string
		ok bool
		op RangeOp
		lo uint8
		hi uint8
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
		{"192.0.2.0/24^+26", false, 0, 0, 0},     // signed length (strconv.Atoi accepted it)
		{"192.0.2.0/24^+26-+28", false, 0, 0, 0}, // signed bounds
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
