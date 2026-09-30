package cfgsim

import (
	"net/netip"
	"os"
	"reflect"
	"testing"

	"github.com/rkolesnichenko/rpsl/types"
)

// rtconfig's own IOS-XR output reads as Task 7's IOS output does, but for
// D11.
func TestXRReadsRtconfig(t *testing.T) {
	text, err := os.ReadFile("testdata/rtconfig-xr-import.txt")
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseXR(string(text))
	if err != nil {
		t.Fatal(err)
	}
	if name, ok := c.Attached(netip.MustParseAddr("10.0.0.2"), false); !ok || name != "AS2-IN-1" {
		t.Fatalf("Attached(10.0.0.2) = %q, %v", name, ok)
	}
	for _, x := range []struct {
		name   string
		r      Route
		accept bool
		attrs  Attrs
	}{
		{"AS2-IN-1", route("10.1.0.0/16", []types.ASN{2, 1}), true,
			Attrs{LocalPref: 990, MED: 5, Communities: []string{"1:100"}}},
		{"AS2-IN-1", route("10.11.0.0/16", []types.ASN{2}), true,
			Attrs{LocalPref: 990, MED: 5, Communities: []string{"1:100"}}},
		{"AS2-IN-1", route("10.1.0.0/24", []types.ASN{2}), false, Attrs{}},
		{"AS2-IN-1", route("192.0.2.0/24", []types.ASN{2}), true, Attrs{LocalPref: -1, MED: -1}},
		{"AS4-IN-3", route("10.44.0.0/16", []types.ASN{4, 10, 1}, "4:1"), true, Attrs{LocalPref: -1, MED: -1, Communities: []string{"4:1"}}},
		{"AS4-IN-3", route("10.44.0.0/16", []types.ASN{4, 13}, "4:1"), false, Attrs{}},
		{"AS5-IN-4", route("10.5.0.0/16", []types.ASN{5}), true, Attrs{LocalPref: -1, MED: -1, Prepended: []types.ASN{1, 1}}},
		{"AS5-IN-4", route("10.55.0.0/16", []types.ASN{5}, "5:666"), false, Attrs{}},
		// D11: IOS accepts this route (Task 7); rtconfig's XR rendering
		// refuses it, since "matches-any *" needs a community.
		{"AS5-IN-4", route("10.55.0.0/16", []types.ASN{5}), false, Attrs{}},
	} {
		ok, a, err := c.Policy(x.name, x.r)
		if err != nil || ok != x.accept || ok && !reflect.DeepEqual(a, x.attrs) {
			t.Errorf("%s(%v) = %v %+v, %v; want %v %+v", x.name, x.r, ok, a, err, x.accept, x.attrs)
		}
	}
}

func TestXRPolicyLanguage(t *testing.T) {
	const text = `
prefix-set p1
  10.0.0.0/8 ge 16 le 24,
  192.0.2.0/24
end-set
!
as-path-set a1
  ios-regex '_666_',
  ios-regex '^_65000_'
end-set
!
community-set c1
  1:1,
  1:2
end-set
!
community-set c2
  no-export
end-set
!
route-policy P
  if destination in p1 and not as-path in a1 then
    if community matches-every c1 then
      set local-preference 900
      set community (7:7) additive
      delete community in (1:1)
      prepend as-path 1 2
      prepend as-path 3
      done
    elseif community matches-any c2 then
      set med igp-cost
      set next-hop self
      pass
    else
      set community (9:9)
    endif
  elseif (as-path in a1 or destination in p1) then
    drop
  endif
  set med 7
end-policy
!
route-policy Q
  if destination in p1 then
    delete community all
    done
  endif
end-policy
!
router bgp 1
 neighbor 10.0.0.2
  remote-as 2
  address-family ipv4 unicast
   route-policy P in
   route-policy Q out
  !
 !
!
`
	c, err := ParseXR(text)
	if err != nil {
		t.Fatal(err)
	}
	if name, ok := c.Attached(netip.MustParseAddr("10.0.0.2"), true); !ok || name != "Q" {
		t.Errorf("export policy %q, %v", name, ok)
	}
	for _, x := range []struct {
		name   string
		r      Route
		accept bool
		attrs  Attrs
	}{
		{"P", route("10.1.0.0/16", []types.ASN{2}, "1:1", "1:2"), true,
			Attrs{LocalPref: 900, MED: -1, Communities: []string{"1:2", "7:7"}, Prepended: []types.ASN{3, 1, 1}}},
		// pass, then the statement after the if: accepted with MED 7.
		{"P", route("10.1.0.0/16", []types.ASN{2}, "no-export"), true,
			Attrs{LocalPref: -1, MED: 7, Communities: []string{"65535:65281"}, NextHop: "self"}},
		{"P", route("10.1.0.0/16", []types.ASN{2}), true, Attrs{LocalPref: -1, MED: 7, Communities: []string{"9:9"}}},
		{"P", route("10.1.0.0/16", []types.ASN{2, 666}), false, Attrs{}},
		// No arm matches, but "set med 7" modifies the route: it is passed.
		{"P", route("172.16.0.0/16", []types.ASN{2}), true, Attrs{LocalPref: -1, MED: 7}},
		{"Q", route("10.1.0.0/16", []types.ASN{2}, "1:1"), true, Attrs{LocalPref: -1, MED: -1}},
		// Nothing passes it: default drop.
		{"Q", route("172.16.0.0/16", []types.ASN{2}), false, Attrs{}},
	} {
		ok, a, err := c.Policy(x.name, x.r)
		if err != nil || ok != x.accept || ok && !reflect.DeepEqual(a, x.attrs) {
			t.Errorf("%s(%v) = %v %+v, %v; want %v %+v", x.name, x.r, ok, a, err, x.accept, x.attrs)
		}
	}
	for _, bad := range []string{
		"route-policy P\n  if destination in p1 then\n    frobnicate\n  endif\nend-policy\n",
		"route-policy P\n  if destination in p1\n    done\n  endif\nend-policy\n",
		"route-policy P\n  if destination in p1 then\n    done\nend-policy\n",
		"prefix-set p1\n  10.0.0.0/8 ge\nend-set\n",
		"frobnicate\n",
	} {
		if _, err := ParseXR(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
	c, err = ParseXR("route-policy P\n  if destination in nope then\n    done\n  endif\nend-policy\n")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Policy("P", route("10.1.0.0/16", nil)); err == nil {
		t.Errorf("a missing prefix-set evaluated")
	}
}

// TestXREdgeCases covers oracle gaps the fixture and TestXRPolicyLanguage
// don't exercise: an empty community-set under matches-any/matches-every, an
// uncontested "set med igp-cost", prefix-set "eq n" and a bare "ge n" (no
// "le"), an as-path-set element whose quoted ios-regex contains a comma, a
// non-additive "set community" over a route that already carries other
// communities, and the "prepend as-path A N" bound on N.
func TestXREdgeCases(t *testing.T) {
	const text = `
prefix-set p2
  10.0.0.0/8 eq 16,
  192.0.2.0/24 ge 26
end-set
!
prefix-set pall
  0.0.0.0/0 le 32
end-set
!
as-path-set a2
  ios-regex '^_1(_2){1,3}$',
  ios-regex '^_9_$'
end-set
!
community-set cempty
end-set
!
route-policy REVERY
  if community matches-every cempty then
    done
  endif
end-policy
!
route-policy RANY
  if community matches-any cempty then
    done
  endif
end-policy
!
route-policy RMED
  if destination in pall then
    set med igp-cost
    done
  endif
end-policy
!
route-policy RWIN
  if destination in p2 then
    done
  endif
end-policy
!
route-policy RPATH
  if as-path in a2 then
    done
  endif
end-policy
!
route-policy RCOMM
  if destination in pall then
    set community (9:9)
    done
  endif
end-policy
!
route-policy RPREPEND0
  if destination in pall then
    prepend as-path 1 0
    done
  endif
end-policy
!
route-policy RPREPEND65
  if destination in pall then
    prepend as-path 1 65
    done
  endif
end-policy
`
	c, err := ParseXR(text)
	if err != nil {
		t.Fatal(err)
	}

	// 1. matches-every over an empty set is vacuously true; matches-any over
	// an empty set is always false — whether or not the route carries a
	// community.
	for _, r := range []Route{route("192.0.2.0/24", nil), route("192.0.2.0/24", nil, "1:1")} {
		if ok, _, err := c.Policy("REVERY", r); err != nil || !ok {
			t.Errorf("REVERY(%v) = %v, %v; want true", r, ok, err)
		}
		if ok, _, err := c.Policy("RANY", r); err != nil || ok {
			t.Errorf("RANY(%v) = %v, %v; want false", r, ok, err)
		}
	}

	// 2. "set med igp-cost" with nothing after it to override MED: MEDIGP
	// must land in the final Attrs.
	if ok, a, err := c.Policy("RMED", route("192.0.2.0/24", nil)); err != nil || !ok ||
		!reflect.DeepEqual(a, Attrs{LocalPref: -1, MED: -1, MEDIGP: true}) {
		t.Errorf("RMED = %v %+v, %v; want true {LocalPref:-1 MED:-1 MEDIGP:true}", ok, a, err)
	}

	// 3. prefix-set "eq n" and a bare "ge n" (no "le") windows: one route
	// inside and one outside each.
	for _, x := range []struct {
		p      string
		accept bool
	}{
		{"10.5.0.0/16", true},    // eq 16: exactly a /16 inside 10.0.0.0/8
		{"10.5.0.0/24", false},   // eq 16: wrong length
		{"192.0.2.128/28", true}, // ge 26, no le: /28 is in the window
		{"192.0.2.0/25", false},  // ge 26, no le: /25 is short of it
	} {
		if ok, _, err := c.Policy("RWIN", route(x.p, nil)); err != nil || ok != x.accept {
			t.Errorf("RWIN(%s) = %v, %v; want %v", x.p, ok, err, x.accept)
		}
	}

	// 4. splitElements must not split inside the quoted ios-regex (its
	// "{1,3}" comma is not an element separator), and the surviving element
	// must still work as a regexp: one path it matches, one it doesn't.
	for _, x := range []struct {
		path   []types.ASN
		accept bool
	}{
		{[]types.ASN{1, 2}, true},
		{[]types.ASN{1, 2, 2, 2, 2}, false}, // one rep more than {1,3} allows
	} {
		if ok, _, err := c.Policy("RPATH", route("192.0.2.0/24", x.path)); err != nil || ok != x.accept {
			t.Errorf("RPATH(%v) = %v, %v; want %v", x.path, ok, err, x.accept)
		}
	}

	// 5. "set community (x)" without "additive" replaces the route's
	// communities, it does not add to them.
	if ok, a, err := c.Policy("RCOMM", route("192.0.2.0/24", nil, "1:1", "2:2")); err != nil || !ok ||
		!reflect.DeepEqual(a, Attrs{LocalPref: -1, MED: -1, Communities: []string{"9:9"}}) {
		t.Errorf("RCOMM = %v %+v, %v; want true {LocalPref:-1 MED:-1 Communities:[9:9]}", ok, a, err)
	}

	// 6. "prepend as-path A N": N outside 1..64 is an error from Policy(),
	// not a silent no-op or a parse-time failure.
	if _, _, err := c.Policy("RPREPEND0", route("192.0.2.0/24", nil)); err == nil {
		t.Errorf("prepend count 0 did not error")
	}
	if _, _, err := c.Policy("RPREPEND65", route("192.0.2.0/24", nil)); err == nil {
		t.Errorf("prepend count 65 did not error")
	}
}
