package object

import (
	"os"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/ast"
)

// draftFigures returns the objects of each figure in
// testdata/src-members-draft.txt, keyed "figure-N". Figure 4 is a fragment in
// the draft; the file wraps it in an as-set of ours.
func draftFigures(t *testing.T) map[string][]*ast.Object {
	t.Helper()
	b, err := os.ReadFile("testdata/src-members-draft.txt")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]*ast.Object{}
	for _, block := range strings.Split(string(b), "=== ")[1:] {
		name, body, _ := strings.Cut(block, "\n")
		for _, text := range strings.Split(strings.TrimSpace(body), "\n\n") {
			out[name] = append(out[name], parse(text+"\n"))
		}
	}
	return out
}

func rulesOf(diags []ast.Diagnostic) map[string]int {
	m := map[string]int{}
	for _, d := range diags {
		m[d.Rule]++
	}
	return m
}

func TestDraftFigure2DecodesClean(t *testing.T) {
	obj, diags := Decode(draftFigures(t)["figure-2"][0])
	if len(diags) != 0 {
		t.Fatalf("figure 2 diagnostics: %+v", diags)
	}
	rs := obj.(RouteSet)
	if len(rs.SrcMembers) != 3 || rs.SrcMembers[1].Ref().String() != "RIPE::RS-OTHER" {
		t.Errorf("figure 2 SrcMembers = %+v", rs.SrcMembers)
	}
}

func TestDraftFigure3IsUnlistedTwice(t *testing.T) {
	obj, diags := Decode(draftFigures(t)["figure-3"][0])
	r := rulesOf(diags)
	if r["object/route-set-src-members-unlisted"] != 2 || len(diags) != 2 {
		t.Fatalf("figure 3 diagnostics = %+v; want exactly two unlisted warnings", diags)
	}
	for _, d := range diags {
		if d.Severity != ast.Warning {
			t.Errorf("%s is %v, want Warning", d.Rule, d.Severity)
		}
		if !strings.Contains(d.Message, "RS-SRCMBRONLY") && !strings.Contains(d.Message, "2001:db8::/32") {
			t.Errorf("unexpected unlisted item: %s", d.Message)
		}
	}
	if n := len(obj.(RouteSet).SrcMembers); n != 4 { // unlisted members are kept: the resolver follows them
		t.Errorf("figure 3 kept %d SrcMembers, want 4", n)
	}
}

func TestDraftFigure4IsAConflict(t *testing.T) {
	obj, diags := Decode(draftFigures(t)["figure-4"][0])
	if rulesOf(diags)["object/as-set-src-members-conflict"] != 2 {
		t.Fatalf("figure 4 diagnostics = %+v; want a conflict error at each of the two items", diags)
	}
	if n := len(obj.(AsSet).SrcMembers); n != 0 {
		t.Errorf("figure 4 kept %d SrcMembers; both conflicting entries must be dropped", n)
	}
}

func TestSrcMembersDiagnostics(t *testing.T) {
	for _, tc := range []struct{ name, src, rule string }{
		{"unscoped set", "as-set: AS-X\nmembers: AS-Y\nsrc-members: AS-Y\n", "object/as-set-src-members"},
		{"operator on ASN", "route-set: RS-X\nmembers: AS1^24\nsrc-members: AS1^24\n", "object/route-set-src-members"},
		{"prefix in as-set", "as-set: AS-X\nsrc-members: 192.0.2.0/24\n", "object/as-set-src-members"},
	} {
		_, diags := Decode(parse(tc.src))
		if rulesOf(diags)[tc.rule] != 1 {
			t.Errorf("%s: diagnostics = %+v; want one %s", tc.name, diags, tc.rule)
		}
	}
}

func TestSrcMembersSameRegistryTwiceIsKeptOnce(t *testing.T) {
	obj, diags := Decode(parse("as-set: AS-X\nmembers: AS-Y\nsrc-members: RIPE::AS-Y, ripe::as-y\n"))
	if len(diags) != 0 {
		t.Fatalf("diagnostics: %+v", diags)
	}
	if n := len(obj.(AsSet).SrcMembers); n != 1 {
		t.Errorf("kept %d, want 1", n)
	}
}

func TestSrcMembersKeyIgnoresOperatorOnASN(t *testing.T) {
	// members: AS1^24 lists AS1 (spec §5.2), so src-members: AS1 is not unlisted.
	_, diags := Decode(parse("route-set: RS-X\nmembers: AS1^24\nsrc-members: AS1\n"))
	if len(diags) != 0 {
		t.Errorf("diagnostics: %+v", diags)
	}
}

func TestWithSrcMembers(t *testing.T) {
	p := WithSrcMembers(RIPE)
	if p.Name() != "RIPE+src-members" {
		t.Errorf("Name = %q", p.Name())
	}
	for _, class := range []string{"as-set", "route-set"} {
		spec, _ := p.Class(class)
		if a, ok := spec.Attrs["src-members"]; !ok || a.Required || a.Single {
			t.Errorf("%s src-members spec = %+v, %v; want optional, multi-valued", class, a, ok)
		}
		orig, _ := RIPE.Class(class)
		if _, ok := orig.Attrs["src-members"]; ok {
			t.Errorf("WithSrcMembers changed RIPE's own %s table", class)
		}
	}
	o := parse("as-set: AS-X\nmembers: AS-Y\nsrc-members: RIPE::AS-Y\ntech-c: X-RIPE\nadmin-c: X-RIPE\nmnt-by: M\nsource: RIPE\n")
	if r := rulesOf(RIPE.Validate(o)); r["dict/unknown-attr"] != 1 {
		t.Errorf("RIPE did not flag src-members: %v", r)
	}
	if r := rulesOf(p.Validate(o)); r["dict/unknown-attr"] != 0 {
		t.Errorf("RIPE+src-members flagged src-members: %v", r)
	}
}
