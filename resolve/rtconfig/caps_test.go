package rtconfig

import (
	"errors"
	"io"
	"net/netip"
	"testing"

	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/types"
)

func TestCapabilitiesMatchWriters(t *testing.T) {
	to2 := policy.PeeringAS{AS: policy.ASNum{AS: 2}}
	s, p := fixturePolicy(t, "from AS2 accept AS2")
	via := peval.Policy{Clauses: []peval.Clause{{Remote: policy.PeeringAS{AS: policy.ASNum{AS: 3}}, Filter: p.Clauses[0].Filter}}}
	mc := s
	mc.AF.SAFI = types.SAFIMulticast
	try := map[Feature]func(g *Generator) error{
		FeatureDefault: func(g *Generator) error {
			return g.WriteDefault(io.Discard, s, peval.Defaults{Clauses: []peval.DefaultClause{{Peering: to2}}})
		},
		FeatureNetworks: func(g *Generator) error {
			return g.WriteNetworks(io.Discard, []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")})
		},
		FeatureVia:       func(g *Generator) error { return g.WriteImport(io.Discard, s, via) },
		FeatureMulticast: func(g *Generator) error { return g.WriteImport(io.Discard, mc, p) },
	}
	for _, c := range Capabilities() {
		f, ok := try[c.Feature]
		if !ok {
			continue
		}
		for _, v := range Vendors() {
			err := f(&Generator{Vendor: v})
			var ue *UnsupportedError
			switch want := contains(c.Vendors, v); {
			case want && err != nil:
				t.Errorf("%v %s: table says supported, the writer says %v", v, c.Feature, err)
			case !want && (!errors.As(err, &ue) || ue.Cause != c.Cause):
				t.Errorf("%v %s: table says refused with %q, the writer says %v", v, c.Feature, c.Cause, err)
			}
		}
	}
}
