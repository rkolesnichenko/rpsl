package types

import (
	"strings"
	"testing"
)

func TestParseRouterID(t *testing.T) {
	cases := []struct {
		in    string
		want  string // canonical String(), "" when the parse must fail
		isAdr bool
	}{
		{"192.0.2.1", "192.0.2.1", true},
		{"2001:db8::1", "2001:db8::1", true},
		{"::ffff:192.0.2.1", "192.0.2.1", true}, // unmapped
		{"fe80::1%eth0", "fe80::1", true},       // zone dropped
		{" 192.0.2.1 ", "192.0.2.1", true},      // trimmed
		{"rtr.example.net", "rtr.example.net", false},
		{"RTR.Example.NET", "rtr.example.net", false}, // lower-cased
		{"rtr.example.net.", "rtr.example.net", false},
		{"0.0.0.0.", "0.0.0.0", true}, // a trailing dot on an address is still an address
		{"192.0.2.1.", "192.0.2.1", true},
		{"1.2.3.4.5", "1.2.3.4.5", false}, // not an address, so a name
		{"amsix-rtr1.example.com", "amsix-rtr1.example.com", false},
		{"rtr1", "rtr1", false}, // single label: policy warns, types accepts
		{"", "", false},
		{" ", "", false},
		{".", "", false},
		{"a..b", "", false},
		{"-rtr.example.net", "", false},
		{"rtr-.example.net", "", false},
		{"rtr_1.example.net", "", false},
		{"rtr.example.net/24", "", false},
		{strings.Repeat("a", 64) + ".net", "", false},
		{strings.Repeat("a.", 130) + "net", "", false},
	}
	for _, c := range cases {
		got, err := ParseRouterID(c.in)
		if c.want == "" {
			if err == nil {
				t.Errorf("ParseRouterID(%q) = %v, want error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseRouterID(%q): %v", c.in, err)
			continue
		}
		if got.String() != c.want {
			t.Errorf("ParseRouterID(%q) = %q, want %q", c.in, got, c.want)
		}
		addr, isAddr := got.Addr()
		if isAddr != c.isAdr {
			t.Errorf("ParseRouterID(%q).Addr() ok = %v, want %v", c.in, isAddr, c.isAdr)
		}
		if c.isAdr {
			if got.Name() != "" {
				t.Errorf("ParseRouterID(%q).Name() = %q, want \"\"", c.in, got.Name())
			}
			if addr.String() != c.want {
				t.Errorf("ParseRouterID(%q).Addr() = %v, want %v", c.in, addr, c.want)
			}
		} else if got.Name() != c.want {
			t.Errorf("ParseRouterID(%q).Name() = %q, want %q", c.in, got.Name(), c.want)
		}
		if got.IsZero() {
			t.Errorf("ParseRouterID(%q).IsZero() = true", c.in)
		}
	}
}

// Every spelling of one router is the same value, so RouterID works as a map key.
func TestRouterIDCanonical(t *testing.T) {
	groups := [][]string{
		{"rtr.example.net", "RTR.EXAMPLE.NET", "Rtr.Example.Net.", " rtr.example.net "},
		{"192.0.2.1", "::ffff:192.0.2.1"},
		{"2001:db8::1", "2001:0db8:0000::1", "2001:DB8::1"},
	}
	for _, g := range groups {
		first, err := ParseRouterID(g[0])
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range g[1:] {
			got, err := ParseRouterID(s)
			if err != nil {
				t.Fatal(err)
			}
			if got != first {
				t.Errorf("ParseRouterID(%q) = %q, want == ParseRouterID(%q) = %q", s, got, g[0], first)
			}
		}
	}
	// A name and an address never collide.
	name, _ := ParseRouterID("rtr.example.net")
	addr, _ := ParseRouterID("192.0.2.1")
	if name == addr {
		t.Error("a named router equals an addressed one")
	}
}

func TestRouterIDZero(t *testing.T) {
	var z RouterID
	if !z.IsZero() {
		t.Error("zero RouterID: IsZero() = false")
	}
	if z.String() != "" {
		t.Errorf("zero RouterID: String() = %q, want \"\"", z.String())
	}
	if z.Name() != "" {
		t.Errorf("zero RouterID: Name() = %q, want \"\"", z.Name())
	}
	if a, ok := z.Addr(); ok {
		t.Errorf("zero RouterID: Addr() = %v, true; want ok = false", a)
	}
	// The zero value marshals as "" and "" unmarshals back to it (text.go's contract).
	b, err := z.MarshalText()
	if err != nil || len(b) != 0 {
		t.Errorf("zero RouterID: MarshalText() = %q, %v; want \"\"", b, err)
	}
	rtr, _ := ParseRouterID("rtr.example.net")
	if err := rtr.UnmarshalText(nil); err != nil || !rtr.IsZero() {
		t.Errorf("UnmarshalText(\"\") = %q, %v; want the zero RouterID", rtr, err)
	}
	if err := rtr.UnmarshalText([]byte("not a router!")); err == nil {
		t.Error("UnmarshalText accepted garbage")
	}
}

// FuzzParseRouterID: never panics; anything accepted is confined to the router
// alphabet (so it is safe to interpolate into an IRRd/whois query) and
// re-parses to an identical value.
func FuzzParseRouterID(f *testing.F) {
	for _, s := range []string{
		"192.0.2.1", "2001:db8::1", "::ffff:10.0.0.1", "fe80::1%eth0",
		"rtr.example.net", "RTR.EXAMPLE.NET.", "rtr1", "a..b", "-x.net",
		"rtr.example.net\n!irtrs-x", "rtr.example.net, rtr2.example.net",
		strings.Repeat("a", 300),
	} {
		f.Add(s)
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-.:"
	f.Fuzz(func(t *testing.T, s string) {
		r, err := ParseRouterID(s)
		if err != nil {
			return
		}
		str := r.String()
		if str == "" {
			t.Fatalf("ParseRouterID(%q) accepted but renders empty", s)
		}
		if strings.Trim(str, alphabet) != "" {
			t.Fatalf("ParseRouterID(%q) accepted out-of-alphabet router %q", s, str)
		}
		again, err := ParseRouterID(str)
		if err != nil || again != r {
			t.Fatalf("re-parse of %q = %+v, %v; want %+v", str, again, err, r)
		}
		if r.IsZero() {
			t.Fatalf("ParseRouterID(%q) accepted but is the zero value", s)
		}
		// Exactly one of the two representations is present.
		if _, isAddr := r.Addr(); isAddr == (r.Name() != "") {
			t.Fatalf("ParseRouterID(%q): addr and name disagree (%q)", s, str)
		}
	})
}
