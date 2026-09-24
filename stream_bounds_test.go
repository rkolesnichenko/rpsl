package rpsl

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// peakHeap runs f while sampling the heap, returning the highest HeapAlloc seen
// (live data plus garbage not yet collected) and the bytes f allocated.
func peakHeap(f func()) (peak, total uint64) {
	var before runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	var max atomic.Uint64
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			if m.HeapAlloc > max.Load() {
				max.Store(m.HeapAlloc)
			}
			select {
			case <-stop:
				return
			case <-time.After(2 * time.Millisecond):
			}
		}
	}()
	f()
	close(stop)
	<-done
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	return max.Load() - min(max.Load(), before.HeapAlloc), after.TotalAlloc - before.TotalAlloc
}

// With default options, no input can make the parser hold much memory: the
// worst case, an object at both caps, peaks around 140 MB. Lines used to be
// uncapped and cost ~1 KB each: 4 MiB of blank lines allocated 4 GB.
func TestStreamMemoryIsBoundedByDefault(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates hostile 16 MiB inputs")
	}
	const size = 16 << 20
	lines := DefaultMaxObjectLines - 1 // just under the line cap: parsed, not skipped
	cases := map[string]string{
		// Past the caps: discarded as they stream.
		"blank lines":            strings.Repeat("\n", size) + "as-set: AS-X\n",
		"attribute lines":        "as-set: AS-X\n" + strings.Repeat("a:\n", size/3),
		"malformed lines":        strings.Repeat("x\n", size/2) + "as-set: AS-X\n",
		"malformed in an object": "as-set: AS-X\n" + strings.Repeat("x\n", size/2),
		"continuation lines":     "remarks: x\n" + strings.Repeat("+\n", size/2),
		"one long line":          "remarks: " + strings.Repeat("x", size+1) + "\n\nas-set: AS-X\n",
		// At the caps: the worst an object can cost.
		"blank lines at cap":      strings.Repeat("\n", lines) + "as-set: AS-X\n",
		"attributes at cap":       "as-set: AS-X\n" + strings.Repeat("a:\n", lines),
		"malformed at cap":        "as-set: AS-X\n" + strings.Repeat("x\n", lines),
		"continuations at cap":    "remarks: x\n" + strings.Repeat("+\n", lines),
		"long line at cap":        "remarks: " + strings.Repeat("x", size-100) + "\n",
		"long folded line at cap": "remarks: x\n" + strings.Repeat(" "+strings.Repeat("x", 62)+"\n", size/64-2),
	}
	for name, in := range cases {
		start := time.Now()
		peak, total := peakHeap(func() {
			for range Parse(strings.NewReader(in)) {
			}
		})
		t.Logf("%-24s peak heap %4d MB, allocated %5d MB, %v", name, peak>>20, total>>20, time.Since(start).Round(time.Millisecond))
		if peak > 192<<20 {
			t.Errorf("%s: peak heap %d MB, want under 192 MB", name, peak>>20)
		}
		if total > 384<<20 {
			t.Errorf("%s: allocated %d MB, want under 384 MB", name, total>>20)
		}
	}
}

func TestStreamDefaults(t *testing.T) {
	if DefaultMaxObjectBytes != 16<<20 || DefaultMaxObjectLines != 1<<18 {
		t.Errorf("defaults = %d bytes, %d lines; want 16 MiB, 262144", DefaultMaxObjectBytes, DefaultMaxObjectLines)
	}
	if got := (ParseOptions{}).maxObjectLines(); got != DefaultMaxObjectLines {
		t.Errorf("zero ParseOptions line cap = %d, want DefaultMaxObjectLines", got)
	}
	if got := (ParseOptions{MaxObjectLines: -1}).maxObjectLines(); got >= 0 {
		t.Errorf("negative MaxObjectLines = %d, want unlimited (< 0)", got)
	}
}

// MaxObjectLines caps an object's lines, and separately the trivia before it,
// exactly as MaxObjectBytes caps their bytes.
func TestMaxObjectLines(t *testing.T) {
	opts := ParseOptions{MaxObjectLines: 3}
	_, classes, diags := streamAll(strings.NewReader("a: 1\nb: 2\nc: 3\nd: 4\n\nroute: X\n"), opts)
	if !reflect.DeepEqual(classes, []string{"", "route"}) || countRule(diags, "rpsl/object-too-large") != 1 {
		t.Errorf("long object: classes %q, diags %+v; want it skipped, then route", classes, diags)
	}
	_, classes, diags = streamAll(strings.NewReader("\n#\n\n#\nroute: X\n"), opts)
	if !reflect.DeepEqual(classes, []string{"route"}) || countRule(diags, "rpsl/trivia-too-large") != 1 {
		t.Errorf("long trivia: classes %q, diags %+v; want route with one trivia-too-large", classes, diags)
	}
	_, classes, diags = streamAll(strings.NewReader("a: 1\nb: 2\nc: 3\n\n\n\nroute: X\n"), opts)
	if !reflect.DeepEqual(classes, []string{"a", "route"}) || len(diags[0])+len(diags[1]) != 0 {
		t.Errorf("at the cap: classes %q, diags %+v; want a and route, clean", classes, diags)
	}
}

// Lexer diagnostics per object are capped, with one summary for the rest.
func TestLexerDiagnosticsAreCapped(t *testing.T) {
	in := "as-set: AS-X\n" + strings.Repeat("x\n", 500)
	_, _, diags := streamAll(strings.NewReader(in), ParseOptions{})
	ds := diags[0]
	if len(ds) != maxLexerDiagnostics+1 || ds[len(ds)-1].Rule != "lexer/too-many-errors" ||
		!strings.Contains(ds[len(ds)-1].Message, "400 more") {
		t.Errorf("%d diagnostics, last %+v; want %d then one lexer/too-many-errors for 400 more",
			len(ds), ds[len(ds)-1], maxLexerDiagnostics)
	}
}

// An over-long line outside an object discards only that line: it used to be
// taken for an oversized object, which also skipped the object after it. A
// long whitespace-only line still separates objects.
func TestLongLineOutsideAnObject(t *testing.T) {
	opts := ParseOptions{MaxObjectBytes: 30}
	in := "a: 1\n\n# lead\n#" + strings.Repeat("x", 50) + "\nr: 1\no: 2\n\nc: 3\n"
	objs, classes, diags := streamAll(strings.NewReader(in), opts)
	if !reflect.DeepEqual(classes, []string{"a", "r", "c"}) || countRule(diags, "rpsl/trivia-too-large") != 1 ||
		!strings.Contains(objs[1], "# lead\n") {
		t.Errorf("long comment: classes %q, objects %q, diags %+v; want a, r (keeping # lead), c", classes, objs, diags)
	}
	in = "a: 1\n" + strings.Repeat(" ", 50) + "\nroute: X\n\nc: 3\n"
	_, classes, diags = streamAll(strings.NewReader(in), opts)
	if !reflect.DeepEqual(classes, []string{"a", "route", "c"}) || countRule(diags, "rpsl/trivia-too-large") != 1 {
		t.Errorf("long blank line: classes %q, diags %+v; want a, route, c", classes, diags)
	}
	in = "a: 1\n\ndescr: " + strings.Repeat("x", 50) + "\nmore: 2\n\nc: 3\n"
	_, classes, diags = streamAll(strings.NewReader(in), opts)
	if !reflect.DeepEqual(classes, []string{"a", "", "c"}) || countRule(diags, "rpsl/object-too-large") != 1 {
		t.Errorf("long first attribute: classes %q, diags %+v; want a, the skipped object, c", classes, diags)
	}
}

// Ranging over Parse again after a break continues with the next object, like a
// bufio.Scanner, so a caller can consume a dump in pieces without losing data.
// Once the input is exhausted, further ranges yield nothing.
func TestParseIteratorResumes(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 5000; i++ {
		fmt.Fprintf(&b, "as-set: AS-X%d\ndescr: object number %d\n\n", i, i)
	}
	b.WriteString("# trailing comment\n")
	in := b.String()
	seq := Parse(strings.NewReader(in))
	var got strings.Builder
	n := 0
	for piece := 1; n < 5000; piece++ {
		taken := 0
		for obj, diags := range seq {
			if len(diags) != 0 {
				t.Fatalf("object %d: %+v", n, diags)
			}
			if want := fmt.Sprintf("AS-X%d", n); obj.Key() != want {
				t.Fatalf("object %d has key %q, want %q", n, obj.Key(), want)
			}
			got.WriteString(obj.String())
			n++
			if taken++; taken == piece%7+1 {
				break
			}
		}
	}
	for obj := range seq {
		got.WriteString(obj.String())
		n++
	}
	if n != 5000 || got.String() != in {
		t.Errorf("%d objects, lossless %v; want 5000, true", n, got.String() == in)
	}
	for range seq {
		t.Fatal("an exhausted stream yielded again")
	}
}

// The stream and the lexer classify lines by one set of rules, so an object the
// stream yields is exactly one object to the lexer: re-parsing its text never
// reports rpsl/multiple-objects and gives the same attributes. A bare '\r' used
// to be blank to the stream and content to the lexer, which let a line such as
// "\rmnt-by: …" end up inside the following object.
func TestStreamAgreesWithLexer(t *testing.T) {
	for _, in := range []string{
		"a: 1\n\n\rmnt-by: EVIL-MNT\nroute: 192.0.2.0/24\norigin: AS1\n",
		"a: 1\n\n\rb: 2\n\nc: 3\n",
		"a: 1\n \r \nb: 2\n",
		"a: 1\r\r\nb: 2\r\r\n\r\r\nc: 3\n",
		"a: 1\n\r\n\rb: 2\n",
		"a: 1\n\n\r\nb: 2\r",
	} {
		var got []string
		for obj, diags := range Parse(strings.NewReader(in)) {
			got = append(got, obj.Class())
			reparsed, rd := ParseObject(obj.String())
			if countRule([][]Diagnostic{rd}, "rpsl/multiple-objects") != 0 {
				t.Errorf("%q: streamed object %q holds more than one object (%+v)", in, obj.String(), diags)
			}
			if !reflect.DeepEqual(reparsed.Attributes(), obj.Attributes()) && len(reparsed.Attributes()) != len(obj.Attributes()) {
				t.Errorf("%q: object %q re-parses differently", in, obj.String())
			}
		}
		t.Logf("%q -> classes %q", in, got)
	}
}

// A line discarded for its length leaves every later position where it was in
// the stream (found by FuzzParseStream: they moved up by the discarded line).
func TestDiscardedLineKeepsPositions(t *testing.T) {
	long := "#" + strings.Repeat("x", 40) + "\n"
	for _, src := range []string{
		"\n" + long + "ab: 1\n",                 // trivia before and after the discarded line
		"a: 1\n\n# c\n" + long + "# d\nab: 1\n", // the same, after an object
		"a: 1\n\n" + long + "# trailing\n",      // trailing trivia owned by the last object
	} {
		var got []string
		for o, ds := range ParseWith(strings.NewReader(src), ParseOptions{MaxObjectBytes: 20}) {
			for _, a := range o.Attributes() {
				if want := strings.Index(src, a.Raw); a.Span.StartByte != want ||
					a.Span.StartLine != 1+strings.Count(src[:want], "\n") {
					t.Errorf("%q: %s at line %d byte %d, want line %d byte %d", src, a.Name, a.Span.StartLine,
						a.Span.StartByte, 1+strings.Count(src[:want], "\n"), want)
				}
			}
			for _, d := range ds {
				got = append(got, d.Rule)
			}
		}
		if len(got) != 1 || got[0] != "rpsl/trivia-too-large" {
			t.Errorf("%q: diagnostics %v, want one rpsl/trivia-too-large", src, got)
		}
	}
}

// An over-long line is classified by the whole line, not its first bytes: one
// whose ':' comes after 4 KiB still starts an object, which is then too large
// (found by FuzzParseStream: it was taken for a trivia line).
func TestOverLongAttributeLineStartsAnObject(t *testing.T) {
	src := strings.Repeat("x", 5000) + ": v\nb: 2\n\nc: 3\n"
	var rules, classes []string
	for o, ds := range ParseWith(strings.NewReader(src), ParseOptions{MaxObjectBytes: 100}) {
		classes = append(classes, o.Class())
		for _, d := range ds {
			rules = append(rules, d.Rule)
		}
	}
	if !reflect.DeepEqual(rules, []string{"rpsl/object-too-large"}) || !reflect.DeepEqual(classes, []string{"", "c"}) {
		t.Errorf("classes %q, diagnostics %v; want the first object skipped as too large, then c", classes, rules)
	}
}

// TestTriviaWarningsBounded pins the diagnostics for a run of over-long lines
// outside any object: one Warning for the first and one summary for the rest,
// rather than one per line, which let a small cap grow memory with the input.
func TestTriviaWarningsBounded(t *testing.T) {
	const n = 20000
	src := strings.Repeat("#"+strings.Repeat("x", 200)+"\n", n) + "a: 1\n"
	var objs int
	var diags []Diagnostic
	for o, d := range ParseWith(strings.NewReader(src), ParseOptions{MaxObjectBytes: 100}) {
		if len(o.Attributes()) > 0 {
			objs++
		}
		diags = append(diags, d...)
	}
	if objs != 1 {
		t.Fatalf("got %d objects, want 1", objs)
	}
	if len(diags) != 2 || countRule([][]Diagnostic{diags}, "rpsl/trivia-too-large") != 2 {
		t.Fatalf("got %d diagnostics, want the first discarded line and one summary: %v", len(diags), firstN(diags, 3))
	}
	if want := fmt.Sprintf("%d more", n-1); !strings.Contains(diags[1].Message, want) {
		t.Errorf("summary %q does not say %q", diags[1].Message, want)
	}
}

func firstN(d []Diagnostic, n int) []Diagnostic {
	if len(d) > n {
		return d[:n]
	}
	return d
}
