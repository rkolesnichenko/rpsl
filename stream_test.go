package rpsl

import (
	"errors"
	"io"
	"os"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/object"
)

// streamAll collects every yielded object and diagnostic.
func streamAll(r io.Reader, opts ParseOptions) (objs []string, classes []string, diags [][]Diagnostic) {
	for obj, ds := range ParseWith(r, opts) {
		objs = append(objs, obj.String())
		classes = append(classes, obj.Class())
		diags = append(diags, ds)
	}
	return
}

// Principle #1 for streams: concatenating every yielded object's String()
// reproduces the input byte for byte.
func TestStreamRoundTrip(t *testing.T) {
	inputs := []string{
		"a: 1\n\n\nb: 2\n\n# trailer\n",
		"# header\n\na: 1\n\nb: 2\n",
		"a: 1\r\n\r\nb: 2\r\n",
		"a: 1\n\nb: 2", // no final newline
		"junk line\n\na: 1\n",
		"a: 1\n \t\nb: 2\n", // a whitespace-only line separates objects
		"# only a comment\n",
		"\n\n",
		"",
	}
	for _, f := range corpusFiles(t) {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		inputs = append(inputs, string(src))
	}
	for _, in := range inputs {
		objs, _, _ := streamAll(strings.NewReader(in), ParseOptions{})
		if got := strings.Join(objs, ""); got != in {
			t.Errorf("stream round trip of %q:\n got %q (objects %q)", in, got, objs)
		}
	}
}

// Trivia belongs to the object after it; trailing trivia to the last object; a
// stream with no attributes at all is one object with an empty class.
func TestStreamTriviaOwnership(t *testing.T) {
	cases := []struct {
		in      string
		objs    []string
		classes []string
	}{
		{"a: 1\n\n\nb: 2\n\n# trailer\n", []string{"a: 1\n", "\n\nb: 2\n\n# trailer\n"}, []string{"a", "b"}},
		{"# header\n\na: 1\n", []string{"# header\n\na: 1\n"}, []string{"a"}},
		{"# only a comment\n", []string{"# only a comment\n"}, []string{""}},
		{"", nil, nil},
	}
	for _, c := range cases {
		objs, classes, _ := streamAll(strings.NewReader(c.in), ParseOptions{})
		if !reflect.DeepEqual(objs, c.objs) || !reflect.DeepEqual(classes, c.classes) {
			t.Errorf("%q: objects %q classes %q, want %q %q", c.in, objs, classes, c.objs, c.classes)
		}
	}
}

type failingReader struct{ err error }

func (f failingReader) Read([]byte) (int, error) { return 0, f.err }

// A read error is reported on the object in progress (or an empty object), never
// passed off as a clean end of input.
func TestStreamReadError(t *testing.T) {
	boom := errors.New("gzip: invalid checksum")
	rules := func(ds []Diagnostic) []string {
		var out []string
		for _, d := range ds {
			out = append(out, d.Rule)
		}
		return out
	}
	cases := []struct {
		name    string
		data    string
		classes []string
		last    []string // rules on the final object
	}{
		{"mid-object", "route: 192.0.2.0/24\norigin: AS1\n\nroute: 198.51.100.0/24\norigin: AS2\n",
			[]string{"route", "route"}, []string{"rpsl/read-error"}},
		{"between objects", "route: 192.0.2.0/24\norigin: AS1\n\n", []string{"route", ""}, []string{"rpsl/read-error"}},
		{"before any data", "", []string{""}, []string{"rpsl/read-error"}},
	}
	for _, c := range cases {
		r := io.MultiReader(strings.NewReader(c.data), failingReader{boom})
		_, classes, diags := streamAll(r, ParseOptions{})
		if !reflect.DeepEqual(classes, c.classes) {
			t.Errorf("%s: classes = %q, want %q", c.name, classes, c.classes)
			continue
		}
		last := diags[len(diags)-1]
		if !reflect.DeepEqual(rules(last), c.last) || !strings.Contains(last[0].Message, "invalid checksum") {
			t.Errorf("%s: last object diagnostics = %+v, want one rpsl/read-error naming the cause", c.name, last)
		}
		for _, ds := range diags[:len(diags)-1] {
			if len(ds) != 0 {
				t.Errorf("%s: an earlier, complete object has diagnostics %+v", c.name, ds)
			}
		}
	}
}

func allocDuring(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func countRule(diags [][]Diagnostic, rule string) (n int) {
	for _, ds := range diags {
		for _, d := range ds {
			if d.Rule == rule {
				n++
			}
		}
	}
	return n
}

// MaxObjectBytes bounds memory for hostile input: runs of blank lines and a
// single over-long line are discarded as they stream, not held.
func TestStreamMemoryIsBounded(t *testing.T) {
	const limit = 10 << 20
	blanks := strings.Repeat("\n", 40<<20)
	var diags [][]Diagnostic
	if a := allocDuring(func() {
		_, _, diags = streamAll(strings.NewReader(blanks), ParseOptions{MaxObjectBytes: 1000})
	}); a > limit {
		t.Errorf("40 MiB of blank lines allocated %d bytes; want < %d", a, limit)
	}
	if n := countRule(diags, "rpsl/trivia-too-large"); n != 1 {
		t.Errorf("rpsl/trivia-too-large reported %d times, want once", n)
	}

	longLine := "route: 192.0.2.0/24\ndescr: " + strings.Repeat("x", 50<<20) + "\n\nroute: 198.51.100.0/24\n"
	var classes []string
	if a := allocDuring(func() {
		_, classes, diags = streamAll(strings.NewReader(longLine), ParseOptions{MaxObjectBytes: 1000})
	}); a > limit {
		t.Errorf("a 50 MiB line allocated %d bytes; want < %d", a, limit)
	}
	if countRule(diags, "rpsl/object-too-large") != 1 || classes[len(classes)-1] != "route" {
		t.Errorf("classes %q, diags %+v: want one object-too-large, then the next route", classes, diags)
	}
}

// Blank lines before an object do not count against that object's cap.
func TestStreamLeadingTriviaNotChargedToObject(t *testing.T) {
	route := "route: 192.0.2.0/24\norigin: AS1\n"
	_, classes, diags := streamAll(strings.NewReader("a: 1\n\n\n\n\n"+route), ParseOptions{MaxObjectBytes: int64(len(route))})
	if !reflect.DeepEqual(classes, []string{"a", "route"}) || countRule(diags, "rpsl/object-too-large") != 0 {
		t.Errorf("classes %q diags %+v; want [a route] with no object-too-large", classes, diags)
	}
}

func TestDefaultMaxObjectBytes(t *testing.T) {
	if got := (ParseOptions{}).maxObjectBytes(); got != DefaultMaxObjectBytes {
		t.Errorf("zero ParseOptions cap = %d, want DefaultMaxObjectBytes (%d)", got, DefaultMaxObjectBytes)
	}
	if got := (ParseOptions{MaxObjectBytes: -1}).maxObjectBytes(); got >= 0 {
		t.Errorf("negative MaxObjectBytes = %d, want unlimited (< 0)", got)
	}
}

// Positions in streamed objects point into the stream, including those of
// diagnostics produced later by Decode.
func TestStreamPositions(t *testing.T) {
	src := "a: 1\n\nroute: 192.0.2.0/24\norigin: NOTANAS\nbadline\n"
	var objs []Diagnostic
	var decoded []Diagnostic
	for obj, ds := range Parse(strings.NewReader(src)) {
		if obj.Class() != "route" {
			continue
		}
		objs = ds
		_, decoded = object.Decode(obj)
		if a, _ := obj.GetFirst("origin"); a.Span.StartLine != 4 || a.Span.StartByte != strings.Index(src, "origin") {
			t.Errorf("origin span = %+v, want stream line 4, byte %d", a.Span, strings.Index(src, "origin"))
		}
	}
	if len(objs) != 1 || objs[0].Span.StartLine != 5 || objs[0].Span.StartByte != strings.Index(src, "badline") {
		t.Errorf("malformed-line diagnostic = %+v, want stream line 5, byte %d", objs, strings.Index(src, "badline"))
	}
	if len(decoded) != 1 || decoded[0].Span.StartLine != 4 {
		t.Errorf("decode diagnostics = %+v, want one at stream line 4", decoded)
	}
}

func TestParseObjectDiagnostics(t *testing.T) {
	rules := func(text string) []string {
		_, ds := ParseObject(text)
		var out []string
		for _, d := range ds {
			out = append(out, d.Rule)
		}
		return out
	}
	cases := []struct {
		in   string
		want []string
	}{
		{"a: 1\n\nb: 2\n", []string{"rpsl/multiple-objects"}},
		{"a: 1\n\n\n", nil},
		{"# c\n\na: 1\n", nil},
		{": value\nfoo bar: x\n\ufeffroute: y\nok-name_2: z\n",
			[]string{"lexer/invalid-attribute-name", "lexer/invalid-attribute-name", "lexer/invalid-attribute-name"}},
	}
	for _, c := range cases {
		if got := rules(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("ParseObject(%q) rules = %v, want %v", c.in, got, c.want)
		}
	}
}
