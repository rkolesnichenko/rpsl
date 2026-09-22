package object

import (
	"reflect"
	"testing"

	"github.com/rkolesnichenko/rpsl/ast"
)

// An empty key is reported the same way for every class: one Error,
// object/empty-key, and no class-specific parse error on top.
func TestEveryEmptyKeyIsOneRule(t *testing.T) {
	for class := range registry {
		_, diags := Decode(parse(class + ":\n"))
		if len(diags) != 1 || diags[0].Rule != "object/empty-key" || diags[0].Severity != ast.Error {
			t.Errorf("%s with an empty key: diagnostics %+v, want one object/empty-key Error", class, diags)
		}
	}
}

// A value that cannot be parsed, and so is missing from the typed struct, is an
// Error — a set member included — so filtering on Severity >= Error sees
// everything Decode (and so the engine) dropped.
func TestDroppedValuesAreErrors(t *testing.T) {
	for _, src := range []string{
		"as-set: AS-X\nmembers: garbage!!\n",
		"route-set: RS-X\nmp-members: AS1^+^-\n",
		"route: 192.0.2.0/24\norigin: AS1\nmember-of: not a set\n",
	} {
		_, diags := Decode(parse(src))
		if len(diags) != 1 || diags[0].Severity != ast.Error {
			t.Errorf("Decode(%q) = %+v, want one Error", src, diags)
		}
	}
}

// Built-in profiles cannot be changed by their users: what a caller gets back
// is a copy, and NewProfile copies what it is given.
func TestProfilesAreReadOnly(t *testing.T) {
	obj := parse("route: 192.0.2.0/24\norigin: AS1\nmnt-by: MNT-X\nsource: RIPE\n")
	before := RIPE.Validate(obj)
	spec, ok := RIPE.Class("route")
	if !ok {
		t.Fatal("RIPE has no route class")
	}
	spec.Attrs["origin"] = AttrSpec{}
	spec.Attrs["must-exist"] = AttrSpec{Required: true}
	spec.AllowUnknown = false
	if after := RIPE.Validate(obj); !reflect.DeepEqual(after, before) {
		t.Errorf("changing a returned ClassSpec changed RIPE: %+v then %+v", before, after)
	}

	classes := map[string]ClassSpec{"route": {Attrs: map[string]AttrSpec{"route": {Required: true}}, AllowUnknown: true}}
	p := NewProfile("mine", classes)
	classes["route"].Attrs["must-exist"] = AttrSpec{Required: true}
	if ds := p.Validate(obj); len(ds) != 0 {
		t.Errorf("changing the map given to NewProfile changed the profile: %+v", ds)
	}
	if p.Name() != "mine" || RIPE.Name() != "RIPE" {
		t.Errorf("names %q %q", p.Name(), RIPE.Name())
	}
}

// Attributes and their RFC 4012 mp- forms are separate fields everywhere, as
// Members/MpMembers and Filter/MpFilter already are.
func TestMPAttributesAreSeparate(t *testing.T) {
	r := mustDecode(t, "inet-rtr: rtr.example.net\nlocal-as: AS1\nmp-peer: BGP4 2001:db8::1 asno(AS2)\npeer: BGP4 192.0.2.1 asno(AS3)\n").(InetRtr)
	if len(r.Peers) != 1 || r.Peers[0].Raw != "BGP4 192.0.2.1 asno(AS3)" ||
		len(r.MpPeers) != 1 || r.MpPeers[0].Raw != "BGP4 2001:db8::1 asno(AS2)" {
		t.Errorf("Peers %q, MpPeers %q", r.Peers, r.MpPeers)
	}
	ps := mustDecode(t, "peering-set: PRNG-X\nmp-peering: AS2\npeering: AS3\n").(PeeringSet)
	if len(ps.Peerings) != 1 || len(ps.MpPeerings) != 1 {
		t.Errorf("Peerings %d, MpPeerings %d; want 1 and 1", len(ps.Peerings), len(ps.MpPeerings))
	}
}

// Decode of a nil object, and reading an object with no source text, are safe.
func TestNilSafety(t *testing.T) {
	o, diags := Decode(nil)
	if o.Class() != "" || o.Raw() != nil || diags != nil {
		t.Errorf("Decode(nil) = %#v, %v", o, diags)
	}
	if (AsSet{}).Raw().String() != "" || len(RIPE.Validate(nil)) != 0 {
		t.Error("nil Raw is not readable")
	}
}
