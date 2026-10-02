package consist

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestLintRulesAreDocumented holds docs/diagnostics.md's lint/ list to the
// rules Lint reports and their severities. The doc is in the root module,
// outside the resolve module's zip: outside a checkout of the repository
// the test skips (release.sh tests the published module).
func TestLintRulesAreDocumented(t *testing.T) {
	if _, err := os.Stat("../../go.work"); err != nil {
		t.Skip("not running inside the rpsl repository checkout (../../go.work not found); docs/diagnostics.md lives outside resolve's own module")
	}
	b, err := os.ReadFile("../../docs/diagnostics.md")
	if err != nil {
		t.Fatal(err)
	}
	documented := map[string]string{}
	for _, m := range regexp.MustCompile("(?m)^- \\*\\*`(lint/[a-z-]+)`\\*\\* \\((Info|Warning|Error)\\)").FindAllStringSubmatch(string(b), -1) {
		documented[m[1]] = m[2]
	}
	for _, r := range Rules() {
		sev, ok := documented[r]
		switch {
		case !ok:
			t.Errorf("%s is not documented in docs/diagnostics.md", r)
		case !strings.EqualFold(sev, ruleSeverity[r].String()):
			t.Errorf("%s is documented as %s; Lint reports it as %s", r, sev, ruleSeverity[r])
		}
		delete(documented, r)
	}
	for r := range documented {
		t.Errorf("docs/diagnostics.md documents %s, which Lint does not report", r)
	}
}
