package rtconfig

// Feature is something a policy can ask that not every vendor can express.
type Feature string

// The features whose support differs by vendor. docs/rpslconf.md's capability
// table is generated from Capabilities(), and a test holds both to what the
// printers do.
const (
	FeatureTwoPaths             Feature = "two AS-path regexps in one clause, both to match"
	FeatureAlternation          Feature = "alternation, or repetition of an AS, in an AS-path regexp"
	FeatureInnerAnchor          Feature = "^ or $ inside an AS-path regexp"
	FeatureNegatedClass         Feature = "a negated AS-path class [^…]"
	FeatureCommunityEquals      Feature = "community == {…} as a clause's only community test"
	FeatureCommunityEqualsMixed Feature = "community == {…} negated, or beside other community tests"
	FeatureMEDIGP               Feature = "med = igp_cost"
	FeatureNextHopSelf          Feature = "next-hop = self"
	FeatureDefault              Feature = "default: (rtconfig's default command)"
	FeatureNetworks             Feature = "networks, v6networks"
	FeatureVia                  Feature = "import-via:, export-via:"
	FeatureMulticast            Feature = "a multicast SAFI"
)

// Capability says which vendors can express a Feature, and the Cause the
// others refuse it with.
type Capability struct {
	Feature Feature
	Cause   string
	Vendors []Vendor
}

var capabilities = []Capability{
	{FeatureTwoPaths, CauseTwoPaths, []Vendor{IOSXR, BIRD2}},
	{FeatureAlternation, CausePathShape, []Vendor{IOS, Junos, IOSXR}},
	{FeatureInnerAnchor, CausePathShape, []Vendor{IOS, IOSXR}},
	{FeatureNegatedClass, CauseNegatedClass, nil},
	{FeatureCommunityEquals, CauseCommunityEquals, []Vendor{IOS, BIRD2}},
	{FeatureCommunityEqualsMixed, CauseCommunityEquals, []Vendor{BIRD2}},
	{FeatureMEDIGP, CauseActionValue, []Vendor{IOS, Junos, IOSXR}},
	{FeatureNextHopSelf, CauseActionValue, []Vendor{Junos, IOSXR}},
	{FeatureDefault, CauseDefault, []Vendor{IOS}},
	{FeatureNetworks, CauseNetworks, []Vendor{IOS, IOSXR}},
	{FeatureVia, CauseVia, nil},
	{FeatureMulticast, CauseSAFI, nil},
}

// Capabilities returns the capability table, a copy.
func Capabilities() []Capability {
	out := make([]Capability, len(capabilities))
	for i, c := range capabilities {
		c.Vendors = append([]Vendor(nil), c.Vendors...)
		out[i] = c
	}
	return out
}

// supports reports whether g.Vendor can express f.
func (g *Generator) supports(f Feature) bool {
	for _, c := range capabilities {
		if c.Feature == f {
			for _, v := range c.Vendors {
				if v == g.Vendor {
					return true
				}
			}
			return false
		}
	}
	return false
}
