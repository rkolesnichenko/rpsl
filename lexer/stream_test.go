package lexer

import (
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// totalAlloc reports the bytes allocated while running f. TotalAlloc is
// cumulative and unaffected by GC, so it measures algorithmic cost
// deterministically (unlike wall time).
func totalAlloc(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// A long folded attribute must tokenize in linear time: doubling the input may
// roughly double the bytes allocated, not quadruple them. (Re-concatenating Raw
// for every continuation line allocated ~1.7 GB for 40k lines.)
func TestContinuationFoldingIsLinear(t *testing.T) {
	cost := func(n int) uint64 {
		src := "remarks: x\n" + strings.Repeat("+\n", n)
		var toks []Token
		alloc := totalAlloc(func() { toks = Tokenize(src) })
		if len(toks) != 1 || toks[0].Raw != src {
			t.Fatalf("got %d tokens, want one attribute holding the whole input", len(toks))
		}
		return alloc
	}
	small, large := cost(20000), cost(40000)
	if ratio := float64(large) / float64(small); ratio > 3 {
		t.Errorf("allocation grew %.1fx when the input doubled (%d -> %d bytes); want ~2x (linear)", ratio, small, large)
	}
}

// TokenizeAt positions tokens as if src began at the given line and byte of a
// larger stream: every span and segment shifts, and nothing else changes.
func TestTokenizeAtShiftsPositions(t *testing.T) {
	src := "# c\na: 1\n\nb: x # y\n  z\n+\n"
	base, shifted := Tokenize(src), TokenizeAt(src, 10, 100)
	if len(base) != len(shifted) {
		t.Fatalf("token counts differ: %d vs %d", len(base), len(shifted))
	}
	for i := range base {
		want := base[i]
		want.Span.StartLine += 9
		want.Span.EndLine += 9
		want.Span.StartByte += 100
		want.Span.EndByte += 100
		want.Segments = append([]Segment(nil), base[i].Segments...)
		for j := range want.Segments {
			want.Segments[j].SrcLine += 9
			want.Segments[j].SrcByte += 100
		}
		if !reflect.DeepEqual(shifted[i], want) {
			t.Errorf("token %d:\n got %+v\nwant %+v", i, shifted[i], want)
		}
	}
}

// A carriage return at the very end of input terminates the line; it is not
// part of the value.
func TestTrailingCarriageReturnAtEOF(t *testing.T) {
	toks := Tokenize("a: 1\r")
	if len(toks) != 1 || toks[0].Value != "1" || toks[0].Raw != "a: 1\r" {
		t.Errorf("tokens = %+v, want one attribute with Value %q and Raw %q", toks, "1", "a: 1\r")
	}
}
