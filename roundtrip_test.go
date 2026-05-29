package rpsl

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/lexer"
)

const corpusDir = "testdata/corpus"

func corpusFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(corpusDir)
	if err != nil {
		t.Fatalf("read corpus dir: %v", err)
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".txt") {
			files = append(files, filepath.Join(corpusDir, e.Name()))
		}
	}
	if len(files) == 0 {
		t.Fatal("no corpus fixtures found")
	}
	return files
}

// TestRoundTrip is the lossless guard: ParseObject(src).String() must reproduce
// every corpus fixture byte-for-byte.
func TestRoundTrip(t *testing.T) {
	for _, f := range corpusFiles(t) {
		f := f
		t.Run(filepath.Base(f), func(t *testing.T) {
			src, err := os.ReadFile(f)
			if err != nil {
				t.Fatalf("read %s: %v", f, err)
			}
			obj, _ := ParseObject(string(src))
			if got := obj.String(); got != string(src) {
				t.Errorf("round trip not byte-identical for %s\n got %q\nwant %q", f, got, src)
			}
		})
	}
}

// TestLexerPartitionCorpus verifies the foundational partition invariant on whole
// corpus files (including the multi-object dump).
func TestLexerPartitionCorpus(t *testing.T) {
	for _, f := range corpusFiles(t) {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		var b strings.Builder
		for _, tk := range lexer.Tokenize(string(src)) {
			b.WriteString(tk.Raw)
		}
		if b.String() != string(src) {
			t.Errorf("partition broken for %s", f)
		}
	}
}

func TestParseStream(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(corpusDir, "dump-multi.txt"))
	if err != nil {
		t.Fatalf("read dump-multi: %v", err)
	}
	var classes []string
	for obj, diags := range Parse(strings.NewReader(string(src))) {
		if len(diags) != 0 {
			t.Errorf("unexpected diagnostics: %+v", diags)
		}
		classes = append(classes, obj.Class())
	}
	if len(classes) != 2 || classes[0] != "route" || classes[1] != "route6" {
		t.Errorf("stream classes = %v, want [route route6]", classes)
	}
}

func TestMalformedDiagnostic(t *testing.T) {
	_, diags := ParseObject("route: 192.0.2.0/24\nthis line has no colon\n")
	if len(diags) != 1 || diags[0].Rule != "lexer/malformed-line" {
		t.Errorf("diags = %+v, want one malformed-line diagnostic", diags)
	}
}
