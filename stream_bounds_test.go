package rpsl

import (
	"fmt"
	"io"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl/ast"
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
// uncapped and cost ~1 KB each: 4 MiB of blank lines allocated 4 GB. Reading
// lines as Windows-1252, which can triple them, keeps the bound.
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
		// Read as Windows-1252, 0x80 is three bytes and 0xE9 two.
		"tripled line under cap":     "remarks: " + strings.Repeat("\x80", size-100) + "\n\nas-set: AS-X\n",
		"doubled line at cap":        "remarks: " + strings.Repeat("\xe9", (size-100)/2) + "\n",
		"doubled folded line at cap": "remarks: x\n" + strings.Repeat(" "+strings.Repeat("\xe9", 31)+"\n", size/64-2),
	}
	for name, in := range cases {
		for _, opts := range []ParseOptions{{}, {NonUTF8AsWindows1252: true}} {
			name := name
			if opts.NonUTF8AsWindows1252 {
				name += " (1252)"
			}
			start := time.Now()
			peak, total := peakHeap(func() {
				for range ParseWith(strings.NewReader(in), opts) {
				}
			})
			t.Logf("%-38s peak heap %4d MB, allocated %5d MB, %v", name, peak>>20, total>>20, time.Since(start).Round(time.Millisecond))
			if peak > 192<<20 {
				t.Errorf("%s: peak heap %d MB, want under 192 MB", name, peak>>20)
			}
			if total > 384<<20 {
				t.Errorf("%s: allocated %d MB, want under 384 MB", name, total>>20)
			}
		}
	}
}

// A line within MaxObjectBytes as read but over it as Windows-1252 is
// discarded without being transcoded: reading it so costs no more than
// reading its bytes, which keeps it.
func TestWindows1252LineOverCapIsNotBuilt(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates a hostile 16 MiB input")
	}
	in := "remarks: " + strings.Repeat("\x80", DefaultMaxObjectBytes-100) + "\n" // 48 MiB as UTF-8
	cost := func(opts ParseOptions) uint64 {
		_, total := peakHeap(func() {
			for range ParseWith(strings.NewReader(in), opts) {
			}
		})
		return total
	}
	if on, off := cost(ParseOptions{NonUTF8AsWindows1252: true}), cost(ParseOptions{}); on > off {
		t.Errorf("read as Windows-1252, the line allocated %d MB; as bytes, kept, %d MB", on>>20, off>>20)
	}
}

// A plain object costs a few allocations, however many attributes it has:
// its text, its chunk, tokens and segments, the object and its attributes;
// and one more for a lead of two trivia lines, joined.
func TestStreamAllocationsPerObject(t *testing.T) {
	obj := "inetnum: 192.0.2.0 - 192.0.2.255\nnetname: EXAMPLE\ndescr: one\ncountry: NL\n" +
		"admin-c: A1-RIPE\ntech-c: A1-RIPE\nstatus: ASSIGNED PA\nmnt-by: MNT\nsource: RIPE\n"
	for _, c := range []struct {
		sep  string
		most float64
	}{{"\n", 8}, {"\r\n", 8}, {"\n# next\n", 9}} {
		in := strings.Repeat(obj+c.sep, 100)
		n := testing.AllocsPerRun(20, func() {
			for range Parse(strings.NewReader(in)) {
			}
		})
		if per := n / 100; per > c.most {
			t.Errorf("objects apart by %q: %.2f allocations per object, want at most %v", c.sep, per, c.most)
		}
	}
}

// The parser holds the same memory at the end of a long stream as early on:
// nothing it keeps grows with the objects it has yielded.
func TestStreamStateDoesNotGrow(t *testing.T) {
	if testing.Short() {
		t.Skip("parses 500,000 objects")
	}
	const n = 500000
	in := strings.Repeat("a:\n\n", n)
	heap := func() int64 {
		var m runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&m)
		return int64(m.HeapAlloc)
	}
	var early, late int64
	i := 0
	for range Parse(strings.NewReader(in)) {
		switch i++; i {
		case 1000:
			early = heap()
		case n:
			late = heap()
		}
	}
	if late-early > 1<<20 {
		t.Errorf("the heap grew %d bytes between the 1,000th object and the %dth", late-early, n)
	}
}

// retained reports the heap that what keep returns holds after a collection.
func retained(keep func() any) int64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	kept := keep()
	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(kept)
	return int64(after.HeapAlloc) - int64(before.HeapAlloc)
}

// What an object keeps once parsed is about its text: a long run of trivia
// before or in it costs no more than its bytes when the object is kept, and
// nothing much when only an attribute's Segments or Value is.
func TestStreamRetention(t *testing.T) {
	for name, c := range map[string]struct{ in, trivia string }{
		"blank lines before it":      {"x: 0\n" + strings.Repeat("\n", 200000) + "a: 1\n", strings.Repeat("\n", 200000)},
		"comment lines in it":        {"a: 1\n" + strings.Repeat("#\n", 100000) + "b: 2\n", strings.Repeat("#\n", 100000)},
		"one long comment before it": {"x: 0\n\n# " + strings.Repeat("x", 4<<20) + "\na: 1\n", "\n# " + strings.Repeat("x", 4<<20) + "\n"},
	} {
		for what, keep := range map[string]func(*ast.Object) any{
			"the object": func(o *ast.Object) any { return o },
			"Segments":   func(o *ast.Object) any { a, _ := o.GetFirst("a"); return a.Segments },
			"Value":      func(o *ast.Object) any { a, _ := o.GetFirst("a"); return a.Value },
		} {
			in := c.in
			most := int64(len(c.trivia)) + 1<<20 // the trivia itself, kept by the object, and slack
			if what != "the object" {
				most = 1 << 20
			}
			n := retained(func() any {
				var kept []any
				for o := range Parse(strings.NewReader(in)) {
					if o.Class() == "a" {
						kept = append(kept, keep(o))
					}
				}
				return kept
			})
			if n > most {
				t.Errorf("%s, %s kept: %d bytes held, want at most %d", name, what, n, most)
			}
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

// streamSummary renders what a stream yields: each kept object's class and the
// rules of every diagnostic, in order.
func streamSummary(src string, opts ParseOptions) string {
	var out []string
	for o, ds := range ParseWith(strings.NewReader(src), opts) {
		if c := o.Class(); c != "" {
			out = append(out, c)
		}
		for _, d := range ds {
			out = append(out, d.Rule)
		}
	}
	return strings.Join(out, " ")
}

// A carriage return at the end of a 64 KiB read of an over-long line is part
// of the line, not its end: the line is not blank, so it does not end the
// object, and the stream reads it as the lexer does — as it reads the same
// line with the carriage return anywhere else.
func TestLongLineCRAtChunkBoundary(t *testing.T) {
	const chunk = 64 << 10
	opts := ParseOptions{MaxObjectBytes: 1000}
	for _, c := range []struct{ name, tail string }{
		{"a lone CR", "\r" + strings.Repeat(" ", 10) + "\n"},
		{"CR CR LF", "\r\r\n"},
	} {
		boundary := "a: 1\n" + strings.Repeat(" ", chunk-1) + c.tail + "b: 2\n"
		control := "a: 1\n" + strings.Repeat(" ", 100) + c.tail + strings.Repeat(" ", chunk-101) + "b: 2\n"
		got, want := streamSummary(boundary, opts), streamSummary(control, opts)
		if got != want {
			t.Errorf("%s at the chunk boundary: %q; elsewhere: %q", c.name, got, want)
		}
	}
	// A CRLF split across the boundary still ends a blank line.
	src := "a: 1\n" + strings.Repeat(" ", chunk-1) + "\r\nb: 2\n"
	if got, want := streamSummary(src, opts), "a b rpsl/trivia-too-large"; got != want {
		t.Errorf("a blank line ending CR|LF across the boundary: %q, want the objects apart: %q", got, want)
	}
}

// An over-long line is described by all of it from its first byte, however
// the 64 KiB reads split it: the part kept before the cap was passed counts,
// and a later read is not the line's start.
func TestLongLineDescribedWhole(t *testing.T) {
	const chunk = 64 << 10
	for _, c := range []struct {
		name, src string
		opts      ParseOptions
		want      string
	}{
		// Past a cap of one and a half reads: the '#' was in the part kept.
		{"a comment holding a ':'", "a: 1\n\n# " + strings.Repeat("x", 2*chunk) + ": y\nb: 2\n",
			ParseOptions{MaxObjectBytes: chunk + chunk/2}, "a b rpsl/trivia-too-large"},
		// The second read starts with a space, inside the line.
		{"an attribute", "a: 1\n\n" + strings.Repeat("x", chunk) + " : y\n\nb: 2\n",
			ParseOptions{MaxObjectBytes: 1000}, "a rpsl/object-too-large b"},
		// The part kept ends in a '\r' the next read shows is inside the line,
		// which is so not blank and does not end the object.
		{"a carriage return ending the part kept", "a: 1\n" + strings.Repeat(" ", chunk-1) + "\r\r\nb: 2\n",
			ParseOptions{MaxObjectBytes: chunk}, "rpsl/object-too-large"},
	} {
		if got := streamSummary(c.src, c.opts); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// A finished object is yielded as soon as the next object begins: nothing
// after that can join it, so a consumer on a live connection need not wait for
// the next object to end too.
func TestObjectYieldedAtNextAttribute(t *testing.T) {
	pr, pw := io.Pipe()
	gotA := make(chan struct{})
	go func() {
		_, _ = pw.Write([]byte("a: 1\n\nb: 2\n"))
		select {
		case <-gotA:
		case <-time.After(5 * time.Second):
		}
		_, _ = pw.Write([]byte("\n"))
		pw.Close()
	}()
	start := time.Now()
	var classes []string
	for o := range Parse(pr) {
		classes = append(classes, o.Class())
		if o.Class() == "a" {
			if d := time.Since(start); d > 2*time.Second {
				t.Errorf("object a was yielded after %v, once the writer gave up waiting", d)
			}
			close(gotA)
		}
	}
	if strings.Join(classes, " ") != "a b" {
		t.Errorf("objects %v, want a b", classes)
	}
}

// Ranging over the iterator from inside its own loop is a programming error;
// it used to end the outer loop early without a word.
func TestNestedRangePanics(t *testing.T) {
	seq := Parse(strings.NewReader("a: 1\n\nb: 2\n\nc: 3\n"))
	defer func() {
		if r := recover(); r == nil || !strings.Contains(fmt.Sprint(r), "already") {
			t.Errorf("a nested range recovered %v, want a panic saying the iterator is already running", r)
		}
	}()
	for range seq {
		for range seq {
			break
		}
	}
}
