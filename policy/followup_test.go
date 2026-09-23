package policy

import (
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/ast"
)

// A Unicode space (NTTCOM, RADB and TC hold U+00A0 in policies) separates
// tokens as an ASCII space does, as IRRd reads it; the value gets one Warning.
func TestUnicodeSpaces(t *testing.T) {
	ascii, ds := ParseImport("from AS4690 accept AS4690")
	if len(ds) != 0 {
		t.Fatal(diagRules(ds))
	}
	for _, sp := range []string{"\u00a0", "\u00a0\u00a0", "\u3000", "\u2028", "\u202f", "\v", "\f"} {
		in := "from AS4690" + sp + "accept AS4690"
		imp, ds := ParseImport(in)
		if imp.String() != ascii.String() {
			t.Errorf("%q parses as %q, want %q", in, imp.String(), ascii.String())
		}
		if len(ds) != 1 || ds[0].Rule != "policy/unicode-space" || ds[0].Severity != ast.Warning ||
			ds[0].Span.StartByte != len("from AS4690") {
			t.Errorf("%q: diagnostics %+v, want one policy/unicode-space Warning at byte %d", in, ds, len("from AS4690"))
		}
	}
	// Zero-width characters are not whitespace, in Go or in IRRd's Python.
	if _, ds := ParseImport("from AS4690\u200baccept AS4690"); !hasError(ds) {
		t.Errorf("a zero-width space was read as whitespace: %v", diagRules(ds))
	}
	// Only the first occurrence is reported.
	if _, ds := ParseImport("from\u00a0AS1\u00a0accept\u00a0ANY"); len(ds) != 1 {
		t.Errorf("diagnostics %v, want one Warning for the value", diagRules(ds))
	}
}

// At the end of a value a message names the end, never an empty token.
func TestEndOfValueMessages(t *testing.T) {
	for _, c := range []struct {
		parse func(string) []ast.Diagnostic
		in    string
	}{
		{func(s string) []ast.Diagnostic { _, d := ParseFilter(s); return d }, "ANY AND"},
		{func(s string) []ast.Diagnostic { _, d := ParseImport(s); return d }, "from AS1 accept ANY AND"},
		{func(s string) []ast.Diagnostic { _, d := ParseImport(s); return d }, "from AS1 accept {192.0.2.0/24"},
		{func(s string) []ast.Diagnostic { _, d := ParsePeering(s); return d }, "<><"},
		{func(s string) []ast.Diagnostic { _, d := ParseFilter(s); return d }, "<AS1{>"},
		{func(s string) []ast.Diagnostic { _, d := ParseRPAttribute(s); return d }, "0 \v"},
	} {
		ds := c.parse(c.in)
		if len(ds) == 0 {
			t.Fatalf("%q: no diagnostics", c.in)
		}
		for _, d := range ds {
			if strings.Contains(d.Message, `""`) {
				t.Errorf("%q: message %q names an empty token", c.in, d.Message)
			}
		}
	}
	_, ds := ParseFilter("ANY AND")
	if len(ds) == 0 || !strings.Contains(ds[0].Message, "end of value") {
		t.Errorf("ANY AND: diagnostics %v, want one naming the end of value", ds)
	}
}

// EXCEPT joins policies; a filter term after it gets a hint towards AND NOT.
func TestExceptBeforeFilterHint(t *testing.T) {
	for _, c := range []struct {
		in    string
		parse func(string) []ast.Diagnostic
	}{
		{"from AS1 accept ANY except FLTR-BOGONS", func(s string) []ast.Diagnostic { _, d := ParseImport(s); return d }},
		{"to AS1 announce AS1 except FLTR-BOGONS", func(s string) []ast.Diagnostic { _, d := ParseExport(s); return d }},
		{"AS6777 from AS1 accept ANY except FLTR-BOGONS", func(s string) []ast.Diagnostic { _, d := ParseImportVia(s); return d }},
	} {
		ds := c.parse(c.in)
		if len(ds) == 0 || ds[0].Rule != "policy/expect-peering" || ds[0].Severity != ast.Error ||
			!strings.Contains(ds[0].Message, "EXCEPT joins two policies") || !strings.Contains(ds[0].Message, `"AND NOT FLTR-BOGONS"`) {
			t.Errorf("%q: diagnostics %+v, want a policy/expect-peering Error with the AND NOT hint", c.in, ds)
		}
	}
	// A well-formed EXCEPT is untouched, and a missing from elsewhere gets no hint.
	if _, ds := ParseImport("from AS1 accept ANY except from AS2 accept AS2"); len(ds) != 0 {
		t.Errorf("valid EXCEPT: diagnostics %v", diagRules(ds))
	}
	if _, ds := ParseImport("accept ANY"); len(ds) == 0 || strings.Contains(ds[0].Message, "EXCEPT") {
		t.Errorf("missing from without EXCEPT: diagnostics %+v", ds)
	}
}

func hasError(ds []ast.Diagnostic) bool {
	for _, d := range ds {
		if d.Severity == ast.Error {
			return true
		}
	}
	return false
}
