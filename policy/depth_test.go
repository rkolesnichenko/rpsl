package policy

import (
	"strings"
	"testing"
)

// Deeply nested hostile input must be diagnosed, never overflow the stack. The
// recursion-depth guard caps descent at maxParseDepth and records a diagnostic
// instead of recursing per level. (Per the CLAUDE.md "must never panic" bar.)
func TestPolicyDeepNestingNoPanic(t *testing.T) {
	const depth = 20000 // far beyond maxParseDepth (1000)
	cases := map[string]string{
		"nested parens": "from AS1 accept " + strings.Repeat("(", depth) + "ANY" + strings.Repeat(")", depth),
		"nested not":    "from AS1 accept " + strings.Repeat("not ", depth) + "ANY",
		"nested braces": strings.Repeat("{", depth) + "from AS1 accept ANY" + strings.Repeat("}", depth),
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			_, diags := ParseImport(s) // must return; a panic fails the test
			if len(diags) == 0 {
				t.Errorf("expected nesting diagnostics for %s, got none", name)
			}
		})
	}
}

func TestASPathRegexpDeepNestingNoPanic(t *testing.T) {
	body := strings.Repeat("(", 20000) + "AS1" + strings.Repeat(")", 20000)
	if _, err := ParseASPathRegexp(body); err == nil {
		t.Error("expected an error on deeply nested AS-path regexp, got nil")
	}
}
