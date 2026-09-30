package peval

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every reason peval gives is one of the Why constants: none is spelled out
// anywhere but in their declaration, and no Why is built from a literal.
func TestWhyValuesAreConstants(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var src strings.Builder
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		src.Write(b)
	}
	for _, w := range Whys() {
		if n := strings.Count(src.String(), `"`+w+`"`); n != 1 {
			t.Errorf("%q is spelled out %d times; once, in its constant, is right", w, n)
		}
	}
	if m := regexp.MustCompile(`(Why:|why :?=)\s*"`).FindString(src.String()); m != "" {
		t.Errorf("a reason built from a literal: %q", m)
	}
}
