package policy

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/ast"
)

// Every policy example in RFC 2622, 2650 and 4012 parses as the RFCs mean it:
// without a diagnostic, or with exactly the rules its line expects.
func TestRFCExamples(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "rfc-examples.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	parsers := map[string]func(string) []ast.Diagnostic{
		"import":     func(v string) []ast.Diagnostic { _, d := ParseImport(v); return d },
		"export":     func(v string) []ast.Diagnostic { _, d := ParseExport(v); return d },
		"default":    func(v string) []ast.Diagnostic { _, d := ParseDefault(v); return d },
		"mp-import":  func(v string) []ast.Diagnostic { _, d := ParseMPImport(v); return d },
		"mp-export":  func(v string) []ast.Diagnostic { _, d := ParseMPExport(v); return d },
		"mp-default": func(v string) []ast.Diagnostic { _, d := ParseMPDefault(v); return d },
		"filter":     func(v string) []ast.Diagnostic { _, d := ParseFilter(v); return d },
		"mp-filter":  func(v string) []ast.Diagnostic { _, d := ParseFilter(v); return d },
		"peering":    func(v string) []ast.Diagnostic { _, d := ParsePeering(v); return d },
		"mp-peering": func(v string) []ast.Diagnostic { _, d := ParsePeering(v); return d },
	}
	where, n := "", 0
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") {
			where = strings.TrimSpace(strings.TrimPrefix(line, "#"))
			continue
		}
		if line == "" {
			continue
		}
		example, expect, _ := strings.Cut(line, " ## expect:")
		attr, value, _ := strings.Cut(example, ":")
		parse := parsers[attr]
		if parse == nil {
			t.Fatalf("%s: no parser for %q", where, attr)
		}
		n++
		want := strings.Fields(expect)
		if got := diagRules(parse(strings.TrimSpace(value))); strings.Join(got, " ") != strings.Join(want, " ") {
			t.Errorf("%s: %s\n  diagnostics %v, want %v", where, example, got, want)
		}
	}
	if n < 100 {
		t.Errorf("only %d examples read", n)
	}
}
