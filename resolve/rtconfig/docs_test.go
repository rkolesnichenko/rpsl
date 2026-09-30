package rtconfig_test

import (
	"os"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/resolve/rtconfig"
)

// capabilityTable renders Capabilities() as docs/rpslconf.md holds it.
func capabilityTable() string {
	var b strings.Builder
	b.WriteString("| Feature |")
	for _, v := range rtconfig.Vendors() {
		b.WriteString(" " + v.String() + " |")
	}
	b.WriteString(" Refused with |\n|---|")
	for range rtconfig.Vendors() {
		b.WriteString("---|")
	}
	b.WriteString("---|\n")
	for _, c := range rtconfig.Capabilities() {
		b.WriteString("| " + string(c.Feature) + " |")
		for _, v := range rtconfig.Vendors() {
			mark := " no |"
			for _, w := range c.Vendors {
				if w == v {
					mark = " yes |"
				}
			}
			b.WriteString(mark)
		}
		b.WriteString(" `" + c.Cause + "` |\n")
	}
	return b.String()
}

func TestRpslconfDocs(t *testing.T) {
	raw, err := os.ReadFile("../../docs/rpslconf.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	for _, c := range rtconfig.Causes() {
		if !strings.Contains(doc, "`"+c+"`") {
			t.Errorf("docs/rpslconf.md does not document the cause %q", c)
		}
	}
	for _, w := range peval.Whys() {
		if !strings.Contains(doc, "`"+w+"`") {
			t.Errorf("docs/rpslconf.md does not document the reason %q", w)
		}
	}
	const open, close = "<!-- capabilities -->\n", "<!-- /capabilities -->"
	i, j := strings.Index(doc, open), strings.Index(doc, close)
	if i < 0 || j < i {
		t.Fatalf("docs/rpslconf.md has no %q … %q block", open, close)
	}
	if got, want := doc[i+len(open):j], capabilityTable(); got != want {
		t.Errorf("docs/rpslconf.md's capability table is not the code's; it should read:\n%s", want)
	}
}
