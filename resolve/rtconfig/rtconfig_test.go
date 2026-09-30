package rtconfig

import (
	"bytes"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/internal/cfgsim"
	"github.com/rkolesnichenko/rpsl/types"
)

func TestParseVendor(t *testing.T) {
	for _, v := range Vendors() {
		got, err := ParseVendor(v.String())
		if err != nil || got != v {
			t.Errorf("ParseVendor(%q) = %v, %v", v.String(), got, err)
		}
	}
	if v, err := ParseVendor("CISCO"); err != nil || v != IOS {
		t.Errorf("ParseVendor(CISCO) = %v, %v", v, err)
	}
	if _, err := ParseVendor("huawei"); err == nil {
		t.Errorf("ParseVendor(huawei) accepted")
	}
}

func TestExpand(t *testing.T) {
	for _, c := range []struct {
		pattern string
		nums    []int
		want    string
	}{
		{"MyMap_%d_%d", []int{2, 1}, "MyMap_2_1"},
		{"AS%d-IN-%d", []int{64500, 3}, "AS64500-IN-3"},
		{"mymap", []int{2, 1}, "mymap"},
		{"map-%d", []int{2, 1}, "map-2"},
		{"100%%-%d", []int{7}, "100%-7"},
	} {
		if got := expand(c.pattern, c.nums...); got != c.want {
			t.Errorf("expand(%q, %v) = %q, want %q", c.pattern, c.nums, got, c.want)
		}
	}
}

func TestNamesDefaultFieldByField(t *testing.T) {
	g := &Generator{Names: Naming{MapName: "X_%d_%d"}}
	n := g.names()
	if n.MapName != "X_%d_%d" || n.MapFirstNo != 1 || n.PrefixACLNo != 100 || n.JunosPolicyName != "policy_%d_%d" {
		t.Errorf("names() = %+v", n)
	}
	if (&Generator{}).maxPref() != 1000 || (&Generator{MaxPreference: 255}).maxPref() != 255 {
		t.Errorf("maxPref defaults wrong")
	}
}

func TestUnsupportedError(t *testing.T) {
	err := unsupported(Junos, CauseTwoPaths, "<AS1> AND <AS2>")
	var ue *UnsupportedError
	if !errors.Is(err, ErrUnsupported) || !errors.As(err, &ue) || ue.Vendor != Junos || ue.Cause != CauseTwoPaths {
		t.Fatalf("unsupported() = %v", err)
	}
	if got := err.Error(); got != "rtconfig: junos cannot express <AS1> AND <AS2>: "+CauseTwoPaths {
		t.Errorf("Error() = %q", got)
	}
}

func TestParseCommunity(t *testing.T) {
	for _, c := range []struct {
		in   string
		want string
		ok   bool
	}{
		{"1:2", "1:2", true},
		{" 65535:65281 ", "65535:65281", true},
		{"no_export", "65535:65281", true},
		{"NO_ADVERTISE", "65535:65282", true},
		{"no_export_subconfed", "65535:65283", true},
		{"4294967041", "65535:65281", true},
		{"65536:1", "", false},
		{"1:2:3", "", false},
		{"internet", "", false},
		{"rt:1:2", "", false},
	} {
		got, ok := parseCommunity(c.in)
		if ok != c.ok || ok && got.String() != c.want {
			t.Errorf("parseCommunity(%q) = %v, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
	noExport, _ := parseCommunity("no_export")
	subconfed, _ := parseCommunity("no_export_subconfed")
	plain, _ := parseCommunity("1:2")
	for _, c := range []struct {
		v    Vendor
		comm community
		want string
	}{
		{IOS, noExport, "no-export"}, {Junos, noExport, "no-export"}, {IOSXR, noExport, "no-export"}, {BIRD2, noExport, "(65535,65281)"},
		{IOS, subconfed, "local-AS"}, {Junos, subconfed, "no-export-subconfed"}, {IOSXR, subconfed, "local-AS"},
		{IOS, plain, "1:2"}, {BIRD2, plain, "(1,2)"},
	} {
		if got := c.comm.spell(c.v); got != c.want {
			t.Errorf("%v.spell(%v) = %q, want %q", c.comm, c.v, got, c.want)
		}
	}
}

// A name pattern with fewer than two %d can name two maps alike (ruling R22):
// import and export for one peer, or one direction for two sessions. IOS's
// "no route-map NAME" before the second would give the first neighbour the
// second's policy, so a Generator refuses — with a plain error, not an
// *UnsupportedError — to write a name it has written, and writes nothing.
func TestDuplicateMapName(t *testing.T) {
	s, p := fixturePolicy(t, "from AS2 accept AS2")
	s3 := s
	s3.Peer, s3.PeerRtr = 3, netip.MustParseAddr("10.0.0.3")
	for _, v := range Vendors() {
		for _, pattern := range []string{"mymap", "map-%d"} {
			g := &Generator{Vendor: v, Names: Naming{MapName: pattern, JunosPolicyName: pattern}}
			var b bytes.Buffer
			if err := g.WriteImport(&b, s, p); err != nil {
				t.Fatalf("%v %s: first map: %v", v, pattern, err)
			}
			b.Reset()
			err := g.WriteExport(&b, s, p)
			if pattern == "mymap" && err == nil {
				// "mymap" also collides across sessions; "map-%d" does not.
				t.Errorf("%v %s: a second map of one name was written:\n%s", v, pattern, b.String())
			}
			if err == nil {
				continue
			}
			if errors.Is(err, ErrUnsupported) || b.Len() > 0 || !strings.Contains(err.Error(), "already written") {
				t.Errorf("%v %s: err %v, wrote %q; want a plain error and nothing written", v, pattern, err, b.String())
			}
			if err := g.WriteImport(&b, s3, p); pattern == "map-%d" && err != nil {
				t.Errorf("%v %s: another peer's map: %v", v, pattern, err)
			}
		}
		// Import and export for one peer under map-%d share "map-2".
		g := &Generator{Vendor: v, Names: Naming{MapName: "map-%d", JunosPolicyName: "map-%d"}}
		var b bytes.Buffer
		if err := g.WriteImport(&b, s, p); err != nil {
			t.Fatal(err)
		}
		if err := g.WriteExport(&b, s, p); err == nil {
			t.Errorf("%v map-%%d: import and export for one peer both named map-2", v)
		}
		// The default pattern never collides.
		g = &Generator{Vendor: v}
		for i := 0; i < 3; i++ {
			if err := g.WriteImport(&b, s, p); err != nil {
				t.Errorf("%v default names, map %d: %v", v, i+1, err)
			}
		}
	}
}

// WritePrefixList of a filter with no conjuncts (NOT ANY) writes a list that
// admits nothing: a deny-all entry on IOS, a policy-statement or filter that
// rejects everything on Junos and BIRD, and an empty prefix-set on IOS-XR
// (whether IOS-XR loads an empty prefix-set is not checked offline).
func TestWritePrefixListNothing(t *testing.T) {
	junos := "policy-options {\n    policy-statement prefix-list-100 {\n        term rest {\n            then reject;\n        }\n    }\n}\n"
	bird := "filter pl100 {\n  if false then accept;\n  reject;\n}\n"
	for _, c := range []struct {
		v    Vendor
		afi  types.AFI
		want string
	}{
		{IOS, types.AFIv4, "!\nno ip prefix-list pl100\nip prefix-list pl100 seq 5 deny 0.0.0.0/0 le 32\n"},
		{IOS, types.AFIv6, "!\nno ipv6 prefix-list pl100\nipv6 prefix-list pl100 seq 5 deny ::/0 le 128\n"},
		{Junos, types.AFIv4, junos},
		{Junos, types.AFIv6, junos},
		{IOSXR, types.AFIv4, "!\nprefix-set pl100\nend-set\n"},
		{IOSXR, types.AFIv6, "!\nprefix-set pl100\nend-set\n"},
		{BIRD2, types.AFIv4, bird},
		{BIRD2, types.AFIv6, bird},
	} {
		var b bytes.Buffer
		if err := (&Generator{Vendor: c.v}).WritePrefixList(&b, resolve.NormalFilter{}, c.afi); err != nil || b.String() != c.want {
			t.Errorf("%v %v: %q, %v; want %q", c.v, c.afi, b.String(), err, c.want)
			continue
		}
		if c.v == BIRD2 {
			if err := cfgsim.BIRDSyntax(b.String()); err != nil && !errors.Is(err, cfgsim.ErrNoBIRD) {
				t.Errorf("bird -p: %v", err)
			}
		}
		if c.v == Junos || c.v == BIRD2 { // a policy cfgsim can run a route through
			cfg, err := cfgsim.Parse(c.v.String(), b.String())
			if err != nil {
				t.Fatalf("%v: %v", c.v, err)
			}
			r := rt("10.0.0.0/8", []types.ASN{2})
			if c.afi == types.AFIv6 {
				r = rt("2001:db8::/32", []types.ASN{2})
			}
			if ok, _, err := cfg.Policy(cfg.Policies()[0], r); ok || err != nil {
				t.Errorf("%v %v: the list admits %v: %v, %v", c.v, c.afi, r, ok, err)
			}
		}
	}
}

// A Generator whose Vendor is set to no vendor rtconfig knows refuses every
// write, naming it.
func TestUnknownVendor(t *testing.T) {
	s, p := fixturePolicy(t, "from AS2 accept AS2")
	g := &Generator{Vendor: Vendor(9)}
	var b bytes.Buffer
	for _, err := range []error{g.WriteImport(&b, s, p), g.WritePrefixList(&b, resolve.NormalFilter{}, types.AFIv4), g.WriteSessions(&b)} {
		if err == nil || err.Error() != "rtconfig: unknown vendor Vendor(9)" {
			t.Errorf("err %v, want rtconfig: unknown vendor Vendor(9)", err)
		}
	}
	if b.Len() > 0 {
		t.Errorf("wrote %q", b.String())
	}
	if err := (&Generator{}).WriteSessions(&b); err != errNoVendor {
		t.Errorf("unset vendor: %v", err)
	}
}
