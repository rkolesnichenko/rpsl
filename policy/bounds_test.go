package policy

import (
	"runtime"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/ast"
)

// allocs reports the bytes f allocates.
func allocs(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// A value full of errors reports a bounded number of them and stops: a 16 MiB
// "{;;;…}" used to produce one diagnostic per ';' (about 6.5 GB of heap).
func TestPolicyDiagnosticsAreCapped(t *testing.T) {
	in := "from AS1 accept {" + strings.Repeat(";", 500_000) + "}"
	var diags []ast.Diagnostic
	a := allocs(func() { _, diags = ParseImport(in) })
	if len(diags) != maxDiagnostics+1 || diags[len(diags)-1].Rule != "policy/too-many-errors" {
		t.Fatalf("%d diagnostics, last %q; want %d then policy/too-many-errors",
			len(diags), diags[len(diags)-1].Rule, maxDiagnostics)
	}
	if a > 64<<20 {
		t.Errorf("allocated %d MB, want under 64 MB", a>>20)
	}
}

// A value with more tokens than any real policy is refused up front, before the
// token list for it is built.
func TestPolicyTokenCap(t *testing.T) {
	for name, in := range map[string]string{
		"filter": "from AS1 accept " + strings.Repeat("AS1 ", maxTokens+1),
		"regexp": "from AS1 accept <" + strings.Repeat("AS1 ", maxTokens+1) + ">",
	} {
		var diags []ast.Diagnostic
		a := allocs(func() { _, diags = ParseImport(in) })
		if len(diags) != 1 || diags[0].Rule != "policy/too-long" {
			t.Errorf("%s: diagnostics %v, want one policy/too-long", name, diagRules(diags))
		}
		if a > 128<<20 {
			t.Errorf("%s: allocated %d MB, want under 128 MB", name, a>>20)
		}
	}
}

// Long AND/OR chains are one node, so a consumer that walks the tree
// recursively cannot overflow its stack on a long, valid filter.
func TestLongFilterChainsAreFlat(t *testing.T) {
	const n = 200_000
	or, diags := ParseFilter(strings.TrimSpace(strings.Repeat("AS1 ", n)))
	if f, ok := or.(FilterOr); len(diags) != 0 || !ok || len(f.Terms) != n {
		t.Fatalf("implicit OR of %d terms = %T, %v", n, or, diagRules(diags))
	}
	and, diags := ParseFilter("AS1" + strings.Repeat(" AND AS1", n-1))
	if f, ok := and.(FilterAnd); len(diags) != 0 || !ok || len(f.Terms) != n {
		t.Fatalf("AND of %d terms = %T, %v", n, and, diagRules(diags))
	}
}

// Chains that do build nested nodes — AS-expressions and AS-path quantifiers —
// count toward the nesting cap, so their trees stay shallow too.
func TestNestedChainsCountTowardDepth(t *testing.T) {
	for name, in := range map[string]string{
		"as-or":      "from AS1" + strings.Repeat(" OR AS2", 5000) + " accept ANY",
		"as-and":     "from AS1" + strings.Repeat(" AND AS2", 5000) + " accept ANY",
		"quantifier": "from AS1 accept <AS1" + strings.Repeat("*", 5000) + ">",
	} {
		_, diags := ParseImport(in)
		if len(diags) == 0 || (diags[0].Rule != "policy/nesting" && diags[0].Rule != "policy/as-path-regexp") {
			t.Errorf("%s: diagnostics %v, want a nesting error", name, diagRules(diags))
		}
	}
	// Real data nests AS-expressions at most 16 deep.
	if _, diags := ParseImport("from AS1" + strings.Repeat(" OR AS2", 50) + " accept ANY"); len(diags) != 0 {
		t.Errorf("a 50-term AS-expression: %v", diagRules(diags))
	}
}
