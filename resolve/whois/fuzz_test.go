package whois

import (
	"bytes"
	"testing"
)

// lines splits b after each newline; a last line without one is a line too.
func lines(b []byte) [][]byte {
	out := bytes.SplitAfter(b, []byte("\n"))
	if len(out) > 0 && len(out[len(out)-1]) == 0 {
		out = out[:len(out)-1]
	}
	return out
}

// FuzzScanResponse holds scanResponse to its contract: every line that starts
// with '%' becomes an empty line, every other line is kept as it is, so the
// response never grows and no server comment reaches the RPSL parser.
func FuzzScanResponse(f *testing.F) {
	for _, s := range []string{"% comment\nas-set: AS-X\n", "%ERROR:201: denied\n", "%% ERROR: nope", "as-set: AS-X\nmembers: AS1\n", "", "\n%\n%%\n"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		orig := append([]byte(nil), data...)
		out, _ := scanResponse(data)
		if len(out) > len(orig) {
			t.Fatalf("scanResponse grew %d bytes to %d", len(orig), len(out))
		}
		in, got := lines(orig), lines(out)
		if len(in) != len(got) {
			t.Fatalf("scanResponse(%q) = %q: %d lines, want %d", orig, out, len(got), len(in))
		}
		for i, l := range in {
			want := l
			if l[0] == '%' {
				want = []byte("\n")
			}
			if !bytes.Equal(got[i], want) {
				t.Fatalf("scanResponse(%q) line %d = %q, want %q", orig, i, got[i], want)
			}
		}
	})
}
