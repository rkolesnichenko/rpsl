package types

import (
	"net/netip"
	"strings"
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
		str   string // String(): the canonical form
	}{
		{"AS-FOO", ClassAsSet, "AS-FOO"},
		{"as-foo", ClassAsSet, "AS-FOO"},
		{"AS-51155_customers", ClassAsSet, "AS-51155_CUSTOMERS"},
		{"RS-BAR", ClassRouteSet, "RS-BAR"},
		{"RTRS-X", ClassRtrSet, "RTRS-X"},
		{"FLTR-Y", ClassFilterSet, "FLTR-Y"},
		{"PRNG-Z", ClassPeeringSet, "PRNG-Z"},
		{"AS-ANY", ClassAsSet, "AS-ANY"},
		{"RS-ANY", ClassRouteSet, "RS-ANY"},
		{"AS3333:AS-CUSTOMERS", ClassAsSet, "AS3333:AS-CUSTOMERS"},
		{"AS-X:AS1:AS-Y", ClassAsSet, "AS-X:AS1:AS-Y"},
		{"as3333:as-foo", ClassAsSet, "AS3333:AS-FOO"},
		{"AS007:AS-X", ClassAsSet, "AS7:AS-X"},      // ASN components normalized
		{"AS1.10:AS-X", ClassAsSet, "AS65546:AS-X"}, // asdot normalized
		{"  AS-FOO\t", ClassAsSet, "AS-FOO"},        // outer whitespace trimmed
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

	// Comparable: usable as a map key, and == ignores spelling.
	seen := map[SetName]bool{a: true}
	if !seen[b] || a != lower {
		t.Error("spellings of one name are not == (map lookup missed)")
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
	if !zero.IsZero() || zero.String() != "" || zero.Class() != ClassUnknown {
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
		if r.Op() != c.op || r.Lo() != int(c.lo) || r.Hi() != int(c.hi) {
			t.Errorf("ParsePrefixRange(%q) = {op=%d lo=%d hi=%d}, want {op=%d lo=%d hi=%d}",
				c.in, r.Op(), r.Lo(), r.Hi(), c.op, c.lo, c.hi)
		}
		if r.String() != c.in {
			t.Errorf("String = %q, want %q", r.String(), c.in)
		}
	}
}

// TestParsePrefixRangeIsCanonical: a parsed range is in canonical form, so
// equal meanings compare equal (and dedup in maps) whatever their spelling.
func TestParsePrefixRangeIsCanonical(t *testing.T) {
	for in, want := range map[string]string{
		"10.0.0.0/8^24-24":  "10.0.0.0/8^24",
		"10.0.0.0/8^8-32":   "10.0.0.0/8^+",
		"10.0.0.0/8^9-32":   "10.0.0.0/8^-",
		"10.0.0.0/8^8":      "10.0.0.0/8",
		"10.0.0.0/8^8-8":    "10.0.0.0/8",
		"0.0.0.0/0^0-32":    "0.0.0.0/0^+",
		"10.0.0.1/8^+":      "10.0.0.0/8^+", // host bits cleared
		"10.0.0.1/8":        "10.0.0.0/8",
		"2001:db8::1/32^48": "2001:db8::/32^48",
		"192.0.2.1/32^-":    "192.0.2.1/32^-", // denotes nothing; kept as written
	} {
		r, err := ParsePrefixRange(in)
		if err != nil {
			t.Errorf("ParsePrefixRange(%q): %v", in, err)
			continue
		}
		if r.String() != want {
			t.Errorf("ParsePrefixRange(%q) = %s, want %s", in, r, want)
		}
		if w, _ := ParsePrefixRange(want); r != w {
			t.Errorf("ParsePrefixRange(%q) = %+v, not == ParsePrefixRange(%q) = %+v", in, r, want, w)
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
	for _, in := range []string{"", "EX@RIPE", "Eric Cluett"} {
		if _, err := ParseNICHandle(in); err == nil {
			t.Errorf("ParseNICHandle(%q) expected error", in)
		}
	}
}

// PrefixRange is opaque and always canonical: NewPrefixRange and
// ParsePrefixRange agree, and == compares meaning.
func TestNewPrefixRange(t *testing.T) {
	p := netip.MustParsePrefix("10.0.0.1/8")
	r, ok := NewPrefixRange(p, 8, 32)
	if !ok || r.Prefix() != netip.MustParsePrefix("10.0.0.0/8") || r.Lo() != 8 || r.Hi() != 32 || r.Op() != RangePlus {
		t.Errorf("NewPrefixRange(10.0.0.1/8, 8, 32) = %v %v (%v %d %d %v)", r, ok, r.Prefix(), r.Lo(), r.Hi(), r.Op())
	}
	if parsed, _ := ParsePrefixRange("10.0.0.0/8^+"); parsed != r {
		t.Errorf("ParsePrefixRange(10.0.0.0/8^+) = %v, not == NewPrefixRange", parsed)
	}
	if r, ok := NewPrefixRange(p, 0, 99); !ok || r.Lo() != 8 || r.Hi() != 32 {
		t.Errorf("window clamps to the prefix and family: %v %v", r, ok)
	}
	for _, bad := range []struct{ lo, hi int }{{25, 24}, {33, 40}} {
		if r, ok := NewPrefixRange(p, bad.lo, bad.hi); ok {
			t.Errorf("NewPrefixRange(/8, %d, %d) = %v, want no range", bad.lo, bad.hi, r)
		}
	}
	if r, ok := NewPrefixRange(netip.Prefix{}, 0, 32); ok || !r.IsZero() {
		t.Errorf("NewPrefixRange(invalid) = %v, %v", r, ok)
	}
	var zero PrefixRange
	if !zero.IsZero() || zero.String() != "" || !zero.IsEmpty() {
		t.Errorf("zero PrefixRange: IsZero %v, String %q, IsEmpty %v", zero.IsZero(), zero.String(), zero.IsEmpty())
	}
	host, err := ParsePrefixRange("192.0.2.1/32^-")
	if err != nil || !host.IsEmpty() || host.IsZero() || host.String() != "192.0.2.1/32^-" {
		t.Errorf("host ^- = %v, %v; want an empty range that prints as written", host, err)
	}
}

// RPSL names are case-insensitive, so SetName stores only the canonical form:
// every spelling of a name is == and one map key, and String is canonical.
func TestSetNameIsCanonical(t *testing.T) {
	a, _ := ParseSetName("as-foo")
	b, _ := ParseSetName("AS-FOO")
	c, _ := ParseSetName("As007:as-x")
	if a != b || a.String() != "AS-FOO" || c.String() != "AS7:AS-X" {
		t.Errorf("as-foo %q, AS-FOO %q, As007:as-x %q", a, b, c)
	}
	seen := map[SetName]bool{a: true}
	if !seen[b] {
		t.Error("AS-FOO is a different map key from as-foo")
	}
	if got := c.Components(); len(got) != 2 || got[0] != "AS7" || got[1] != "AS-X" {
		t.Errorf("Components = %q", got)
	}
	if c.Class() != ClassAsSet {
		t.Errorf("Class = %v", c.Class())
	}
}

// Only ASCII spaces and tabs are trimmed; other whitespace is a malformed value.
// Values are tokens: no whitespace inside.
func TestParsersAreASCIIStrict(t *testing.T) {
	bad := map[string]func(string) error{
		"ASN":         func(s string) error { _, err := ParseASN(s); return err },
		"SetName":     func(s string) error { _, err := ParseSetName(s); return err },
		"NICHandle":   func(s string) error { _, err := ParseNICHandle(s); return err },
		"PrefixRange": func(s string) error { _, err := ParsePrefixRange(s); return err },
		"AddrFamily":  func(s string) error { _, err := ParseAddrFamily(s); return err },
	}
	inputs := map[string][]string{
		"ASN":         {" AS1", "AS1\u0085"},
		"SetName":     {" AS-FOO", "AS-FOO "},
		"NICHandle":   {" EX1-RIPE"},
		"PrefixRange": {" 10.0.0.0/8", "10.0.0.0/8 ^+", "10.0.0.0/ 8"},
		"AddrFamily":  {" ipv4"},
	}
	for kind, ins := range inputs {
		for _, in := range ins {
			if bad[kind](in) == nil {
				t.Errorf("Parse%s(%q) accepted", kind, in)
			}
		}
	}
	if _, err := ParseASN(" \tAS1\t "); err != nil {
		t.Errorf("ASCII spaces and tabs are trimmed: %v", err)
	}
}

// A set name is at most 1,024 bytes: longer names are not real and must not
// reach a query line.
func TestSetNameLengthCap(t *testing.T) {
	if _, err := ParseSetName("AS-" + strings.Repeat("X", 1021)); err != nil {
		t.Errorf("a 1,024-byte name: %v", err)
	}
	if _, err := ParseSetName("AS-" + strings.Repeat("X", 1022)); err == nil {
		t.Error("a 1,025-byte name was accepted")
	}
}

// NIC handles: RFC 2622's object-name characters — letters, digits, '_' and
// single hyphens — starting with a letter or, as ARIN's own handles do, a digit,
// ending with a letter or digit, at most 64 long, stored upper-case so they
// compare case-insensitively. A name with spaces is not a handle.
func TestNICHandleSyntax(t *testing.T) {
	for _, bad := range []string{"A-", "A_", "_A", "-AB", "A--B", "AB1-RIPE-", "AB 1", "Eric Cluett", "a.b", "a@b", "",
		strings.Repeat("A", 65)} {
		if h, err := ParseNICHandle(bad); err == nil {
			t.Errorf("ParseNICHandle(%q) = %q, want error", bad, h)
		}
	}
	a, _ := ParseNICHandle("dumy-ripe")
	b, _ := ParseNICHandle("DUMY-RIPE")
	if a != b || a.String() != "DUMY-RIPE" {
		t.Errorf("dumy-ripe = %q, DUMY-RIPE = %q; want equal, upper-case", a, b)
	}
	for _, ok := range []string{"A", "AUTO-1", "JD123-ARIN", "APPLEC-1-Z", "EX1-RIPE", "1NO-ARIN", "2NOC-ARIN",
		"VAGNER_BRASILEIRO", "AB_1", "1AB", strings.Repeat("A", 64)} {
		if _, err := ParseNICHandle(ok); err != nil {
			t.Errorf("ParseNICHandle(%q): %v", ok, err)
		}
	}
}

// UnmarshalText reads handles with the same grammar as ParseNICHandle.
func TestNICHandleUnmarshalAgrees(t *testing.T) {
	for _, in := range []string{"1NO-ARIN", "VAGNER_BRASILEIRO", "Eric Cluett", "A-", strings.Repeat("A", 65)} {
		want, wantErr := ParseNICHandle(in)
		var got NICHandle
		gotErr := got.UnmarshalText([]byte(in))
		if (gotErr == nil) != (wantErr == nil) || got != want {
			t.Errorf("%q: UnmarshalText = %q, %v; ParseNICHandle = %q, %v", in, got, gotErr, want, wantErr)
		}
	}
}
