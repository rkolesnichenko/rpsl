package rpki

import (
	"math/rand"
	"net/netip"
	"testing"

	"github.com/rkolesnichenko/rpsl/types"
)

func vrp(prefix string, asn types.ASN, maxLength uint8) VRP {
	return VRP{Prefix: netip.MustParsePrefix(prefix), ASN: asn, MaxLength: maxLength, TA: "TEST TA"}
}

// TestValidateIRRdCases is IRRd's test_validate_routes_from_roa_objs
// (irrd/rpki/tests/test_validators.py, v4.5.3): its ROAs, and each route's
// status after validation. Its rpki_excluded and pseudo-IRR routes are left
// out: this package validates a route, not a source.
func TestValidateIRRdCases(t *testing.T) {
	v := mustVRPs(t,
		vrp("192.0.2.0/24", 65546, 28),   // valid for d0_l24, d0_l25, d0_l27
		vrp("192.0.2.0/24", 65547, 24),   // the origin of d128_l25, not its length
		vrp("2001:db8::/30", 65547, 30),  // route_v6's origin, not its length
		vrp("2001:db8::/32", 65548, 32),  // route_v6's length, not its origin
		vrp("2001:db8::/32", 65547, 64),  // route_v6
		vrp("203.0.113.0/32", 65547, 32), // no route
		vrp("203.0.113.1/32", 0, 32),     // AS0 cannot match
	)
	for _, tc := range []struct {
		name   string
		prefix string
		origin types.ASN
		want   State
	}{
		{"pk_route_v4_d0_l24", "192.0.2.0/24", 65546, Valid},
		{"pk_route_v4_d0_l25", "192.0.2.0/25", 65546, Valid},
		{"pk_route_v4_d0_l28", "192.0.2.0/27", 65546, Valid},
		{"pk_route_v4_d64_l32", "192.0.2.64/32", 65546, Invalid},
		{"pk_route_v4_d128_l25", "192.0.2.128/25", 65547, Invalid},
		{"pk_route_v6", "2001:db8::/32", 65547, Valid},
		{"pk_route_v4_no_roa", "192.0.2.0/23", 65549, NotFound},
		{"pk_route_v4_roa_as0", "203.0.113.1/32", 65547, Invalid},
	} {
		if got := v.Validate(netip.MustParsePrefix(tc.prefix), tc.origin); got != tc.want {
			t.Errorf("%s: Validate(%s, AS%d) = %v, want %v", tc.name, tc.prefix, tc.origin, got, tc.want)
		}
	}
}

// TestValidateIRRdFromDatabase is IRRd's test_validate_routes_with_roa_from_database.
func TestValidateIRRdFromDatabase(t *testing.T) {
	v := mustVRPs(t, vrp("192.0.2.0/24", 65546, 25), vrp("192.0.2.0/24", 65547, 24))
	if got := v.Validate(netip.MustParsePrefix("192.0.2.0/25"), 65546); got != Valid {
		t.Errorf("got %v, want valid", got)
	}
}

func TestValidateEdges(t *testing.T) {
	v := mustVRPs(t,
		vrp("10.0.0.0/8", 64500, 16),
		vrp("10.1.0.0/16", 0, 16), // AS0 inside AS64500's space
		vrp("0.0.0.0/0", 0, 0),    // covers only the default route itself
		vrp("2001:db8::/32", 64501, 48),
		vrp("2001:db8:1::/48", 64502, 48),
	)
	for _, tc := range []struct {
		prefix string
		origin types.ASN
		want   State
	}{
		{"10.0.0.0/16", 64500, Valid},
		{"10.0.0.0/17", 64500, Invalid},   // one bit past maxLength
		{"10.0.0.0/8", 64501, Invalid},    // covered, wrong origin
		{"10.1.0.0/16", 64500, Valid},     // AS0 covers, but AS64500 matches
		{"10.1.0.0/16", 0, Invalid},       // an AS0 route never matches, even an AS0 VRP
		{"11.0.0.0/8", 64500, Invalid},    // covered by 0.0.0.0/0 AS0 alone
		{"0.0.0.0/0", 64500, Invalid},     // the default route
		{"2001:db8:1::/48", 64501, Valid}, // either VRP may match
		{"2001:db8:1::/48", 64502, Valid},
		{"2001:db8:1::/49", 64502, Invalid},
		{"2001:db9::/32", 64501, NotFound},
		{"2001:db8::/31", 64501, NotFound}, // a less specific is not covered
	} {
		if got := v.Validate(netip.MustParsePrefix(tc.prefix), tc.origin); got != tc.want {
			t.Errorf("Validate(%s, AS%d) = %v, want %v", tc.prefix, tc.origin, got, tc.want)
		}
	}
	// Families never cover each other: a v4 VRP says nothing about a v4-mapped v6 route.
	if got := mustVRPs(t, vrp("0.0.0.0/0", 0, 32)).Validate(netip.MustParsePrefix("::ffff:10.0.0.0/104"), 1); got != NotFound {
		t.Errorf("v4-mapped route: got %v, want not_found", got)
	}
	// A route with host bits set is validated as its canonical prefix.
	if got := v.Validate(netip.MustParsePrefix("10.0.0.1/16"), 64500); got != Valid {
		t.Errorf("non-canonical route: got %v, want valid", got)
	}
	if got := v.Validate(netip.Prefix{}, 64500); got != NotFound {
		t.Errorf("zero prefix: got %v, want not_found", got)
	}
	var empty *VRPs
	if got := empty.Validate(netip.MustParsePrefix("10.0.0.0/8"), 1); got != NotFound || empty.Len() != 0 {
		t.Errorf("nil VRPs: got %v, len %d", got, empty.Len())
	}
}

func TestNewVRPsRejects(t *testing.T) {
	for _, bad := range []VRP{
		{Prefix: netip.MustParsePrefix("10.0.0.1/8"), MaxLength: 8, ASN: 1},  // host bits
		{Prefix: netip.MustParsePrefix("10.0.0.0/8"), MaxLength: 7, ASN: 1},  // maxLength < length
		{Prefix: netip.MustParsePrefix("10.0.0.0/8"), MaxLength: 33, ASN: 1}, // maxLength > 32
		{Prefix: netip.MustParsePrefix("2001:db8::/32"), MaxLength: 129, ASN: 1},
		{MaxLength: 8, ASN: 1}, // no prefix
	} {
		if _, err := NewVRPs([]VRP{bad}); err == nil {
			t.Errorf("NewVRPs(%+v) accepted", bad)
		}
	}
}

func TestStateString(t *testing.T) {
	for s, want := range map[State]string{NotFound: "not_found", Valid: "valid", Invalid: "invalid", 9: "State(9)"} {
		if got := s.String(); got != want {
			t.Errorf("State(%d).String() = %q, want %q", s, got, want)
		}
	}
}

func TestAllKeepsOrder(t *testing.T) {
	in := []VRP{vrp("10.0.0.0/8", 2, 8), vrp("2001:db8::/32", 1, 32), vrp("10.0.0.0/8", 2, 8)}
	v := mustVRPs(t, in...)
	var got []VRP
	for x := range v.All() {
		got = append(got, x)
	}
	if len(got) != len(in) || v.Len() != len(in) {
		t.Fatalf("All yielded %d, Len %d, want %d", len(got), v.Len(), len(in))
	}
	for i := range in {
		if got[i] != in[i] {
			t.Errorf("All()[%d] = %+v, want %+v", i, got[i], in[i])
		}
	}
	for range v.All() {
		break // early stop must not panic
	}
}

// TestValidateMatchesOracle holds the index to IRRd's rule applied by a
// linear scan over every VRP (validators.py, validate_route).
func TestValidateMatchesOracle(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for round := 0; round < 200; round++ {
		var vs []VRP
		for i := r.Intn(40); i > 0; i-- {
			vs = append(vs, randVRP(r))
		}
		v := mustVRPs(t, vs...)
		for i := 0; i < 200; i++ {
			p := randPrefix(r)
			origin := types.ASN(r.Intn(4))
			if got, want := v.Validate(p, origin), oracle(vs, p, origin); got != want {
				t.Fatalf("round %d: Validate(%s, AS%d) = %v, oracle %v; VRPs %v", round, p, origin, got, want, vs)
			}
		}
	}
}

func oracle(vs []VRP, p netip.Prefix, origin types.ASN) State {
	covered := false
	for _, v := range vs {
		if v.Prefix.Addr().Is4() != p.Addr().Is4() || v.Prefix.Bits() > p.Bits() {
			continue
		}
		if !v.Prefix.Contains(p.Addr()) {
			continue
		}
		covered = true
		if v.ASN != 0 && v.ASN == origin && p.Bits() <= int(v.MaxLength) {
			return Valid
		}
	}
	if covered {
		return Invalid
	}
	return NotFound
}

// randPrefix draws from a small space so that VRPs and routes overlap often.
func randPrefix(r *rand.Rand) netip.Prefix {
	if r.Intn(3) == 0 {
		a := [16]byte{0x20, 0x01, 0x0d, 0xb8, byte(r.Intn(4)) << 6}
		return netip.PrefixFrom(netip.AddrFrom16(a), 32+r.Intn(5)).Masked()
	}
	a := [4]byte{10, byte(r.Intn(4)) << 6, byte(r.Intn(2)) << 7}
	return netip.PrefixFrom(netip.AddrFrom4(a), 8+r.Intn(12)).Masked()
}

func randVRP(r *rand.Rand) VRP {
	p := randPrefix(r)
	bits := 32
	if p.Addr().Is6() {
		bits = 128
	}
	maxLen := p.Bits() + r.Intn(4)
	if maxLen > bits {
		maxLen = bits
	}
	return VRP{Prefix: p, MaxLength: uint8(maxLen), ASN: types.ASN(r.Intn(4)), TA: "rand"}
}

func mustVRPs(t testing.TB, vs ...VRP) *VRPs {
	t.Helper()
	v, err := NewVRPs(vs)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
