package rpki

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/resolve"
)

// FuzzReadJSON: no input panics, and what is accepted is well-formed VRPs
// that validate without panicking and write pseudo objects that load back,
// one route per distinct VRP.
func FuzzReadJSON(f *testing.F) {
	f.Add(importerROAs)
	f.Add(`{"roas": [{"asn": 13335, "prefix": "1.1.1.0/24", "maxLength": 24, "ta": "apnic"}], "aspas": []}`)
	f.Add(`{"roas": [{"asn": "AS0", "prefix": "::/0", "maxLength": "128", "ta": "x\ny"}]}`)
	f.Add(`{"roas": [{"asn": "as1.10", "prefix": "0.0.0.0/0", "maxLength": 0, "ta": ""}]}`)
	f.Fuzz(func(t *testing.T, in string) {
		v, err := ReadJSON(strings.NewReader(in))
		if err != nil {
			return
		}
		distinct := map[VRP]bool{}
		for x := range v.All() {
			if err := check(x); err != nil {
				t.Fatalf("accepted %+v: %v", x, err)
			}
			if got := v.Validate(x.Prefix, x.ASN); x.ASN != 0 && got != Valid {
				t.Fatalf("a VRP's own prefix and AS is %v, want valid: %+v", got, x)
			}
			x.TA = ""
			distinct[x] = true
		}
		var b strings.Builder
		if err := v.WriteRPSL(&b); err != nil {
			t.Fatal(err)
		}
		l := &resolve.DumpLoader{}
		if err := l.Read(strings.NewReader(b.String())); err != nil {
			t.Fatal(err)
		}
		if l.Stats.Kept != len(distinct) || l.Stats.Diagnosed != 0 {
			t.Fatalf("pseudo objects loaded as %+v, want %d kept:\n%s", l.Stats, len(distinct), b.String())
		}
	})
}

// FuzzApplySLURM: no SLURM file panics, and an accepted one only removes
// VRPs that were there and adds VRPs it asserted.
func FuzzApplySLURM(f *testing.F) {
	f.Add(importerSLURM)
	f.Add(`{"slurmVersion": 1}`)
	f.Add(`{"slurmVersion": 1, "validationOutputFilters": {"prefixFilters": [{"asn": 64496}, {"prefix": "::/0"}]}}`)
	base := []VRP{
		{netip.MustParsePrefix("192.0.2.0/24"), 26, 64496, "a"},
		{netip.MustParsePrefix("2001:db8::/32"), 40, 64497, "b"},
		{netip.MustParsePrefix("10.0.0.0/8"), 8, 64498, SLURMTrustAnchor},
	}
	f.Fuzz(func(t *testing.T, in string) {
		v, err := mustVRPs(t, base...).ApplySLURM(strings.NewReader(in))
		if err != nil {
			return
		}
		kept := 0
		for x := range v.All() {
			if err := check(x); err != nil {
				t.Fatalf("accepted %+v: %v", x, err)
			}
			if x.TA != SLURMTrustAnchor {
				kept++
				if kept > 2 || (x != base[0] && x != base[1]) {
					t.Fatalf("VRP %+v neither kept nor asserted", x)
				}
			}
		}
		var sawBase2 bool
		for x := range v.All() {
			sawBase2 = sawBase2 || x == base[2]
		}
		if !sawBase2 {
			t.Fatal("a filter dropped an asserted VRP")
		}
	})
}

// FuzzReadASPAs: no input panics, and what is accepted holds the profile's
// §3.3 and reads back equal through NewASPAs.
func FuzzReadASPAs(f *testing.F) {
	f.Add(rpkiClientASPAs)
	f.Add(routinatorASPAs)
	f.Add(`{"aspas": [{"customer_asid": 1, "providers": [0]}, {"customer": "AS1", "providers": ["AS2"]}]}`)
	f.Add(`{"provider_authorizations": {"ipv4": [{"customer_asid": 1, "providers": [2]}]}}`)
	f.Fuzz(func(t *testing.T, in string) {
		s, err := ReadASPAs(strings.NewReader(in))
		if err != nil {
			return
		}
		var all []ASPA
		for a := range s.All() {
			if err := checkASPA(a); err != nil {
				t.Fatalf("accepted %+v: %v", a, err)
			}
			all = append(all, a)
		}
		again, err := NewASPAs(all)
		if err != nil || again.Len() != s.Len() {
			t.Fatalf("All() read back: %v, %d customers, want %d", err, again.Len(), s.Len())
		}
		for _, a := range all {
			p1, _ := s.Providers(a.Customer)
			p2, _ := again.Providers(a.Customer)
			if !slices.Equal(p1, p2) {
				t.Fatalf("AS%d: %v, read back %v", a.Customer, p1, p2)
			}
		}
	})
}
