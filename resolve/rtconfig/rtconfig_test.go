package rtconfig

import (
	"bytes"
	"errors"
	"net/netip"
	"strings"
	"testing"
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
