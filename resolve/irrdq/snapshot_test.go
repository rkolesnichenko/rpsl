package irrdq

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

func corpusOf(t *testing.T, keepText bool, texts ...string) *resolve.Corpus {
	t.Helper()
	c := &resolve.Corpus{KeepPolicy: true, KeepRouteText: keepText}
	for _, text := range texts {
		o, _ := rpsl.ParseObject(text)
		obj, _ := rpsl.Decode(o)
		c.Put(obj)
	}
	return c
}

func TestNewRegistry(t *testing.T) {
	c := corpusOf(t, true, "as-set: AS-X\nmembers: AS1\nsource: RIPE\n", "as-set: AS-Y\nmembers: AS2\nsource: RADB\n")
	r, err := NewRegistry("ripe", 7, c)
	if err != nil {
		t.Fatal(err)
	}
	if r.Name() != "RIPE" || r.Serial() != 7 || !r.KeepsRouteText() {
		t.Errorf("Name %q Serial %d KeepsRouteText %v", r.Name(), r.Serial(), r.KeepsRouteText())
	}
	if _, err := NewRegistry("NOT A NAME", 0, c); err == nil {
		t.Error("an invalid source name was accepted")
	}
	if _, err := NewRegistry("RIPE", 0, &resolve.Corpus{}); err == nil || !strings.Contains(err.Error(), "KeepPolicy") {
		t.Errorf("a corpus without KeepPolicy: %v", err)
	}
	if _, err := NewRegistry("RIPE", 0, nil); err == nil {
		t.Error("a nil corpus was accepted")
	}
}

// TestRegistryRoutes: a registry holds its own source's routes only, in one
// order (IPv4 first, then address, length, origin), whatever the corpus's.
func TestRegistryRoutes(t *testing.T) {
	c := corpusOf(t, true,
		"route6: 2001:db8::/32\norigin: AS1\nsource: RIPE\n",
		"route: 192.0.2.0/25\norigin: AS2\nsource: RIPE\n",
		"route: 192.0.2.0/24\norigin: AS3\nsource: RIPE\n",
		"route: 192.0.2.0/24\norigin: AS1\nsource: RIPE\n",
		"route: 198.51.100.0/24\norigin: AS1\nsource: RADB\n",
	)
	r, err := NewRegistry("RIPE", 0, c)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, rt := range r.routes {
		got = append(got, rt.prefix.String()+" "+rt.origin.String())
		if !strings.HasPrefix(rt.text, "route") {
			t.Errorf("%s %s: text %q not kept", rt.prefix, rt.origin, rt.text)
		}
	}
	want := "192.0.2.0/24 AS1,192.0.2.0/24 AS3,192.0.2.0/25 AS2,2001:db8::/32 AS1"
	if strings.Join(got, ",") != want {
		t.Errorf("routes %q, want %q", strings.Join(got, ","), want)
	}
	if idx := r.byPrefix[netip.MustParsePrefix("192.0.2.0/24")]; len(idx) != 2 || r.routes[idx[0]].origin != types.ASN(1) {
		t.Errorf("byPrefix 192.0.2.0/24: %v", idx)
	}
	if r2, _ := NewRegistry("RIPE", 0, corpusOf(t, false, "route: 192.0.2.0/24\norigin: AS1\nsource: RIPE\n")); r2.KeepsRouteText() || r2.routes[0].text != "" {
		t.Error("route text kept without KeepRouteText")
	}
}

func TestNewSnapshot(t *testing.T) {
	a, _ := NewRegistry("RIPE", 1, corpusOf(t, false))
	b, _ := NewRegistry("RADB", 1, corpusOf(t, false))
	if _, err := NewSnapshot([]*Registry{a, a}, SnapshotOptions{}); err == nil {
		t.Error("two registries named RIPE were accepted")
	}
	if _, err := NewSnapshot([]*Registry{a}, SnapshotOptions{Default: []string{"RADB"}}); err == nil {
		t.Error("a default naming no registry was accepted")
	}
	if _, err := NewSnapshot([]*Registry{a, nil}, SnapshotOptions{}); err == nil {
		t.Error("a nil registry was accepted")
	}
	s, err := NewSnapshot([]*Registry{a, b}, SnapshotOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(s.dflt, ","); got != "RIPE,RADB" {
		t.Errorf("nil Default: %s, want every registry in order", got)
	}
	b2, _ := NewRegistry("RADB", 2, corpusOf(t, false))
	s2, err := s.With(b2)
	if err != nil {
		t.Fatal(err)
	}
	if s.Registries()[1].Serial() != 1 || s2.Registries()[1].Serial() != 2 {
		t.Error("With changed the old snapshot or did not replace")
	}
	c, _ := NewRegistry("ALTDB", 1, corpusOf(t, false))
	if _, err := s.With(c); err == nil {
		t.Error("With of an unknown registry was accepted")
	}
	if _, err := s.With(nil); err == nil {
		t.Error("With of nil was accepted")
	}
	// With keeps the default the snapshot was built with.
	s3, _ := NewSnapshot([]*Registry{a, b}, SnapshotOptions{Default: []string{"radb"}})
	s4, err := s3.With(b2)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(s4.dflt, ","); got != "RADB" {
		t.Errorf("With's default: %s, want RADB", got)
	}
	// Registries returns a copy.
	s.Registries()[0] = b
	if s.Registries()[0] != a {
		t.Error("Registries handed out the snapshot's own slice")
	}
}
