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

func TestDecodeAutNum(t *testing.T) {
	o := parse(`aut-num: AS65001
as-name: EXAMPLE-AS
import:  from AS64500 accept ANY
export:  to AS64500 announce AS65001
admin-c: EX1-RIPE
mnt-by:  MAINT-EXAMPLE
source:  RIPE
`)
	obj, diags := Decode(o)
	if len(diags) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", diags)
	}
	a, ok := obj.(AutNum)
	if !ok {
		t.Fatalf("Decode = %T, want AutNum", obj)
	}
	if a.AS != 65001 {
		t.Errorf("AS = %v, want 65001", a.AS)
	}
	if a.AsName != "EXAMPLE-AS" {
		t.Errorf("AsName = %q", a.AsName)
	}
	if len(a.Imports) != 1 {
		t.Errorf("Imports = %d, want 1", len(a.Imports))
	}
	if len(a.Exports) != 1 {
		t.Errorf("Exports = %d, want 1", len(a.Exports))
	}
}

func TestDecodeAutNumMpImport(t *testing.T) {
	o := parse(`aut-num: AS65001
as-name: EXAMPLE-AS
import:    from AS64500 accept ANY
mp-import: afi ipv6.unicast from AS64500 accept ANY
mp-export: afi ipv6.unicast to AS64500 announce AS65001
source:    RIPE
`)
	obj, diags := Decode(o)
	if len(diags) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", diags)
	}
	a := obj.(AutNum)
	if len(a.Imports) != 2 {
		t.Fatalf("Imports = %d, want 2 (import + mp-import)", len(a.Imports))
	}
	// Legacy import: is unscoped; mp-import: carries the afi.
	if len(a.Imports[0].AFIs) != 0 {
		t.Errorf("import[0].AFIs = %v, want unscoped", a.Imports[0].AFIs)
	}
	if len(a.Imports[1].AFIs) != 1 || a.Imports[1].AFIs[0].String() != "ipv6.unicast" {
		t.Errorf("mp-import AFIs = %v, want [ipv6.unicast]", a.Imports[1].AFIs)
	}
	if len(a.Exports) != 1 || len(a.Exports[0].AFIs) != 1 {
		t.Errorf("Exports = %+v, want one afi-scoped mp-export", a.Exports)
	}
}

// A malformed import: must still decode mnt-by:, with the policy diagnostic
// re-based to the precise source location of the offending token.
func TestAutNumPolicyResilience(t *testing.T) {
	src := "aut-num: AS65001\nimport: from @@@ accept ANY\nmnt-by: MAINT-X\n"
	o := parse(src)
	obj, diags := Decode(o)
	a := obj.(AutNum)
	if len(a.MntBy) != 1 || a.MntBy[0] != "MAINT-X" {
		t.Errorf("MntBy = %v, want [MAINT-X]", a.MntBy)
	}
	if len(diags) != 1 || diags[0].Rule != "policy/peering" {
		t.Fatalf("diags = %+v, want one policy/peering", diags)
	}
	// The span must pinpoint the bad "@@@" token, not the whole attribute.
	sp := diags[0].Span
	if sp.StartLine != 2 {
		t.Errorf("StartLine = %d, want 2 (the import line)", sp.StartLine)
	}
	if sp.StartByte >= len(src) || src[sp.StartByte] != '@' {
		t.Errorf("StartByte %d does not point at '@' in source (got %q)", sp.StartByte, safeByte(src, sp.StartByte))
	}
}

// A malformed token on a CONTINUATION line resolves to that physical line, which
// is the payoff of the segment map (whole-attribute spans could not do this).
func TestPolicyDiagnosticOnContinuationLine(t *testing.T) {
	src := "aut-num: AS65001\nimport: from AS1 accept ANY\n        except @@@\nmnt-by: M\n"
	o := parse(src)
	_, diags := Decode(o)
	if len(diags) == 0 {
		t.Fatalf("expected a diagnostic for the malformed continuation")
	}
	d := diags[0]
	if d.Span.StartLine != 3 {
		t.Errorf("StartLine = %d, want 3 (the continuation line)", d.Span.StartLine)
	}
	if d.Span.StartByte >= len(src) || src[d.Span.StartByte] != '@' {
		t.Errorf("StartByte %d does not point at '@' (got %q)", d.Span.StartByte, safeByte(src, d.Span.StartByte))
	}
}

func safeByte(s string, i int) string {
	if i < 0 || i >= len(s) {
		return "<oob>"
	}
	return string(s[i])
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
