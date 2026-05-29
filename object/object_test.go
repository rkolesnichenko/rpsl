package object

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/lexer"
)

// parse builds an ast.Object from RPSL text for test fixtures.
func parse(src string) *ast.Object {
	return ast.New(lexer.Tokenize(src))
}

func TestDecodeMntner(t *testing.T) {
	o := parse(`mntner:  MAINT-EXAMPLE
descr:   Example maintainer
admin-c: EX1-RIPE
auth:    MD5-PW $1$abc$xyz
mnt-by:  MAINT-EXAMPLE
source:  RIPE
`)
	obj, diags := Decode(o)
	if len(diags) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", diags)
	}
	m, ok := obj.(Mntner)
	if !ok {
		t.Fatalf("Decode = %T, want Mntner", obj)
	}
	if m.Handle != "MAINT-EXAMPLE" {
		t.Errorf("Handle = %q", m.Handle)
	}
	if len(m.AdminC) != 1 || m.AdminC[0] != "EX1-RIPE" {
		t.Errorf("AdminC = %v", m.AdminC)
	}
	if len(m.Auth) != 1 || m.Auth[0] != "MD5-PW $1$abc$xyz" {
		t.Errorf("Auth = %v", m.Auth)
	}
	if m.Source != "RIPE" {
		t.Errorf("Source = %q", m.Source)
	}
}

func TestDecodeRoute(t *testing.T) {
	o := parse(`route:    192.0.2.0/24
origin:   AS65001
member-of: RS-EXAMPLE
holes:    192.0.2.128/25
mnt-by:   MAINT-EXAMPLE
source:   RIPE
`)
	obj, diags := Decode(o)
	if len(diags) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", diags)
	}
	r := obj.(Route)
	if r.Prefix != netip.MustParsePrefix("192.0.2.0/24") {
		t.Errorf("Prefix = %v", r.Prefix)
	}
	if r.Origin != 65001 {
		t.Errorf("Origin = %v", r.Origin)
	}
	if len(r.MemberOf) != 1 || r.MemberOf[0].Canonical() != "RS-EXAMPLE" {
		t.Errorf("MemberOf = %v", r.MemberOf)
	}
	if len(r.Holes) != 1 {
		t.Errorf("Holes = %v", r.Holes)
	}
}

func TestDecodeRoute6Warns(t *testing.T) {
	o := parse("route6: 192.0.2.0/24\norigin: AS65001\n")
	obj, diags := Decode(o)
	r := obj.(Route6)
	if !r.Prefix.IsValid() {
		t.Error("prefix should still decode")
	}
	if len(diags) != 1 || diags[0].Severity != ast.Warning || diags[0].Rule != "object/route6-afi" {
		t.Errorf("diags = %+v, want one route6-afi warning", diags)
	}
}

func TestDecodeAsSetMembers(t *testing.T) {
	o := parse(`as-set:  AS-CUSTOMERS
members: AS65010
members: AS-DOWNSTREAM
source:  RIPE
`)
	obj, diags := Decode(o)
	if len(diags) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", diags)
	}
	s := obj.(AsSet)
	if s.Name.Canonical() != "AS-CUSTOMERS" {
		t.Errorf("Name = %q", s.Name.Canonical())
	}
	if len(s.Members) != 2 {
		t.Fatalf("Members = %v", s.Members)
	}
	if s.Members[0].Kind != MemberAS || s.Members[0].AS != 65010 {
		t.Errorf("member 0 = %+v, want AS65010", s.Members[0])
	}
	if s.Members[1].Kind != MemberSet || s.Members[1].Set.Canonical() != "AS-DOWNSTREAM" {
		t.Errorf("member 1 = %+v, want set AS-DOWNSTREAM", s.Members[1])
	}
}

func TestDecodeRouteSetPrefixRange(t *testing.T) {
	o := parse(`route-set: RS-EXAMPLE
members:   192.0.2.0/24^+
members:   AS65001
source:    RIPE
`)
	obj, diags := Decode(o)
	if len(diags) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", diags)
	}
	s := obj.(RouteSet)
	if len(s.Members) != 2 {
		t.Fatalf("Members = %v", s.Members)
	}
	if s.Members[0].Kind != MemberPrefixRange {
		t.Errorf("member 0 kind = %v, want MemberPrefixRange", s.Members[0].Kind)
	}
}

// A prefix-range in an as-set is the wrong shape: kept best-effort, one Warning.
func TestWrongClassMemberWarns(t *testing.T) {
	o := parse("as-set: AS-FOO\nmembers: 192.0.2.0/24^+\n")
	obj, diags := Decode(o)
	s := obj.(AsSet)
	if len(s.Members) != 1 || s.Members[0].Kind != MemberPrefixRange {
		t.Errorf("member not kept: %v", s.Members)
	}
	if len(diags) != 1 || diags[0].Severity != ast.Warning {
		t.Errorf("diags = %+v, want one warning", diags)
	}
}

// Per-attribute resilience: a malformed origin: must not stop mnt-by: decoding,
// and yields exactly one diagnostic on the bad line.
func TestPerAttributeResilience(t *testing.T) {
	o := parse("route: 192.0.2.0/24\norigin: NOTANASN\nmnt-by: MAINT-X\n")
	obj, diags := Decode(o)
	r := obj.(Route)
	if len(r.MntBy) != 1 || r.MntBy[0] != "MAINT-X" {
		t.Errorf("MntBy = %v, want [MAINT-X]", r.MntBy)
	}
	if len(diags) != 1 || diags[0].Severity != ast.Error || diags[0].Rule != "object/route-origin" {
		t.Errorf("diags = %+v, want one route-origin error", diags)
	}
}

func TestUnknownClassGeneric(t *testing.T) {
	o := parse("inet-rtr: rtr.example.net\nlocal-as: AS65001\n")
	obj, diags := Decode(o)
	if len(diags) != 0 {
		t.Errorf("unexpected diagnostics: %+v", diags)
	}
	if _, ok := obj.(Generic); !ok {
		t.Errorf("Decode = %T, want Generic", obj)
	}
	if obj.Class() != "inet-rtr" {
		t.Errorf("Class = %q", obj.Class())
	}
}

// TestRawRoundTrip: the typed layer never disturbs the lossless round-trip.
func TestRawRoundTrip(t *testing.T) {
	dir := filepath.Join("..", "testdata", "corpus")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".txt") || e.Name() == "dump-multi.txt" {
			continue
		}
		src, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		obj, _ := Decode(parse(string(src)))
		if got := obj.Raw().String(); got != string(src) {
			t.Errorf("%s: Raw().String() not byte-identical", e.Name())
		}
	}
}
