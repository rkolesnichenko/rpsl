package object

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// classKey is a valid key for each decoded class, and a needle proving it was
// decoded.
var classKey = map[string][2]string{
	"aut-num": {"AS65000", "65000"}, "mntner": {"MNT-KEY", "MNT-KEY"}, "person": {"Key Person", "Key Person"},
	"role": {"Key Role", "Key Role"}, "route": {"192.0.2.0/24", "192.0.2.0/24"}, "route6": {"2001:db8::/32", "2001:db8::/32"},
	"as-set": {"AS-KEY", "AS-KEY"}, "route-set": {"RS-KEY", "RS-KEY"}, "peering-set": {"PRNG-KEY", "PRNG-KEY"},
	"filter-set": {"FLTR-KEY", "FLTR-KEY"}, "rtr-set": {"RTRS-KEY", "RTRS-KEY"},
	"inetnum": {"192.0.2.0 - 192.0.2.255", "192.0.2.255"}, "inet6num": {"2001:db8::/32", "2001:db8::/32"},
	"as-block": {"AS65000 - AS65010", "65010"}, "inet-rtr": {"rtr-key.example", "rtr-key.example"},
	"irt": {"IRT-KEY", "IRT-KEY"}, "domain": {"2.0.192.in-addr.arpa", "2.0.192.in-addr.arpa"},
	"organisation": {"ORG-KEY", "ORG-KEY"},
}

// sample returns a value for attr that must survive decoding in class, and the
// needle proving it did.
func sample(class, attr string) (value, needle string) {
	switch attr {
	case class:
		k := classKey[class]
		return k[0], k[1]
	case "origin", "local-as":
		return "AS65099", "65099"
	case "admin-c", "tech-c", "zone-c", "nic-hdl":
		return "DRIFT1-TEST", "DRIFT1-TEST"
	case "member-of":
		switch class {
		case "aut-num":
			return "AS-DRIFT", "AS-DRIFT"
		case "inet-rtr":
			return "RTRS-DRIFT", "RTRS-DRIFT"
		}
		return "RS-DRIFT", "RS-DRIFT"
	case "holes":
		if class == "route6" {
			return "2001:db8::/48", "2001:db8::/48"
		}
		return "192.0.2.0/25", "192.0.2.0/25"
	case "members", "mp-members":
		if class == "rtr-set" {
			return "rtr-drift.example", "rtr-drift.example"
		}
		return "AS65099", "65099"
	case "import", "mp-import":
		return "from AS65099 accept ANY", "65099"
	case "export", "mp-export":
		return "to AS65099 announce ANY", "65099"
	case "default", "mp-default":
		return "to AS65099", "65099"
	case "peering", "mp-peering", "filter", "mp-filter":
		return "AS65099", "65099"
	}
	return "drift-marker", "drift-marker"
}

// CLAUDE.md: if a profile lists an attribute on a class with a typed decoder,
// the decoder must surface it — otherwise Decode silently drops that data.
func TestDecoderSurfacesEveryProfiledAttribute(t *testing.T) {
	var drift []string
	for _, p := range []Profile{RIPE, RFCStrict} {
		for class, spec := range p.Classes {
			if _, typed := registry[class]; !typed {
				continue // decodes to Generic: data stays reachable via Raw()
			}
			for attr := range spec.Attrs {
				val, needle := sample(class, attr)
				src := class + ": " + classKey[class][0] + "\n" + attr + ": " + val + "\n"
				if attr == class {
					src = class + ": " + val + "\n"
				}
				obj, _ := Decode(parse(src))
				if !strings.Contains(fmt.Sprintf("%+v", obj), needle) {
					drift = append(drift, p.Name+": "+class+"."+attr)
				}
			}
		}
	}
	sort.Strings(drift)
	for _, d := range drift {
		t.Errorf("listed in the profile but not surfaced by the decoder: %s", d)
	}
}
