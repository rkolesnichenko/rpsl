package rpsl

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

var cp1252 = ParseOptions{NonUTF8AsWindows1252: true}

// A line that is not UTF-8 is read as Windows-1252, each line on its own; a
// UTF-8 line, and every line without the option, is kept as it is.
func TestWindows1252Lines(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"descr: Caf\xe9\n", "descr: Café\n"},
		{"descr: Café\n", "descr: Café\n"},
		{"descr: Caf\xe9\ndescr: Café\n", "descr: Café\ndescr: Café\n"},              // one object, both kinds
		{"city: Lujan \x96 J\xe1uregui\n", "city: Lujan – Jáuregui\n"},               // 0x96 is an en dash, not U+0096
		{"descr: \x80 \x8a \x9f \xa0\xff\n", "descr: € Š Ÿ  ÿ\n"},                    // the table's ends; 0xA0-0xFF are Latin-1
		{"descr: \x81\x8d\x8f\x90\x9d\n", "descr: \u0081\u008d\u008f\u0090\u009d\n"}, // undefined in Windows-1252: the C1 controls
		{"descr: Caf\xe9\n  Café\n+ \xe9\n", "descr: Café\n  Café\n+ é\n"},           // continuation lines decided alone
		{"descr: caf\xc3\n", "descr: cafÃ\n"},                                        // a sequence cut short at the line's end
		{"descr: \xe2\x80\r\n", "descr: â€\r\n"},                                     // the terminator is kept
		{"# Caf\xe9\n\ndescr: x\n", "# Café\n\ndescr: x\n"},                          // trivia too
		{"descr: Caf\xe9", "descr: Café"},                                            // no final newline
	} {
		objs, _, _ := streamAll(strings.NewReader(c.in), cp1252)
		if got := strings.Join(objs, ""); got != c.want {
			t.Errorf("%q: read as %q, want %q", c.in, got, c.want)
		}
		objs, _, _ = streamAll(strings.NewReader(c.in), ParseOptions{})
		if got := strings.Join(objs, ""); got != c.in {
			t.Errorf("%q without the option: read as %q", c.in, got)
		}
	}
}

// A UTF-8 line longer than the line reader's buffer, with a character split
// across two of its reads, is UTF-8: the line is judged whole.
func TestWindows1252LongUTF8Line(t *testing.T) {
	for _, pad := range []int{65536 - 8, 65536 - 9, 65536 - 10} {
		in := "descr: " + strings.Repeat("a", pad) + "é€\n"
		objs, _, diags := streamAll(strings.NewReader(in), cp1252)
		if len(objs) != 1 || objs[0] != in || len(diags[0]) != 0 {
			t.Errorf("pad %d: a UTF-8 line was changed or diagnosed: %v", pad, diags)
		}
	}
}

// Each object carries one Warning for the lines read as Windows-1252, its
// trivia's and trailing trivia's included, on the first of them.
func TestWindows1252Warning(t *testing.T) {
	type warned struct {
		line int
		msg  string
	}
	for _, c := range []struct {
		in   string
		want []warned // per object: zero for none
	}{
		{"a: 1\n\nb: \xe9\nc: \xe9\n+ \xe9\n\nd: 2\n", []warned{{}, {3, "3 lines are not UTF-8"}, {}}},
		{"# \xe9\na: 1\n", []warned{{1, "1 line is not UTF-8"}}},
		{"a: 1\n\n# \xe9\n\nb: 2\n", []warned{{}, {3, "1 line is not UTF-8"}}}, // trivia goes to the next object
		{"a: 1\n\n# \xe9\n", []warned{{3, "1 line is not UTF-8"}}},             // trailing trivia to the last
		{"# \xe9\n", []warned{{1, "1 line is not UTF-8"}}},                     // no attributes at all
		{"a: \xe9\n\n# \xe9\n", []warned{{1, "2 lines are not UTF-8"}}},        // the object's and its trailing trivia's: one Warning
		{"a: é\n", []warned{{}}},
	} {
		_, _, diags := streamAll(strings.NewReader(c.in), cp1252)
		if len(diags) != len(c.want) {
			t.Fatalf("%q: %d objects, want %d", c.in, len(diags), len(c.want))
		}
		for i, ds := range diags {
			var got []Diagnostic
			for _, d := range ds {
				if d.Rule == "rpsl/not-utf8" {
					got = append(got, d)
				}
			}
			switch w := c.want[i]; {
			case w.line == 0 && len(got) != 0:
				t.Errorf("%q object %d: %v, want no rpsl/not-utf8", c.in, i, got)
			case w.line != 0 && (len(got) != 1 || got[0].Severity != Warning || got[0].Span.StartLine != w.line || !strings.HasPrefix(got[0].Message, w.msg)):
				t.Errorf("%q object %d: %v, want one Warning at line %d: %q…", c.in, i, got, w.line, w.msg)
			}
		}
	}
}

// Positions index the text as read: line numbers are the input's, and byte
// offsets count each line as transcoded, as the objects hold it, the Warning's
// too.
func TestWindows1252Positions(t *testing.T) {
	in := "descr: Caf\xe9 \x96\n\nroute: 192.0.2.0/24\norigin: AS1\ndescr: \xe9\n"
	held := "descr: Café –\n\nroute: 192.0.2.0/24\norigin: AS1\ndescr: é\n"
	for obj, diags := range ParseWith(strings.NewReader(in), cp1252) {
		if obj.Class() != "route" {
			continue
		}
		if a, _ := obj.GetFirst("origin"); a.Span.StartLine != 4 || a.Span.StartByte != strings.Index(held, "origin") {
			t.Errorf("origin span = %+v, want line 4, byte %d", a.Span, strings.Index(held, "origin"))
		}
		if len(diags) != 1 || diags[0].Span.StartLine != 5 || diags[0].Span.StartByte != strings.LastIndex(held, "descr") {
			t.Errorf("route diagnostics = %v, want one at line 5, byte %d", diags, strings.LastIndex(held, "descr"))
		}
	}
}

// The corpus's Latin-1 fixture reads as the text it means, with one Warning
// for its four Latin-1 lines, at the first; its UTF-8 line is kept.
func TestWindows1252Corpus(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(corpusDir, "latin1-lacnic.txt"))
	if err != nil {
		t.Fatal(err)
	}
	want := strings.NewReplacer("\xe9", "é", "\xed", "í", "\xe1", "á", "\x96", "–").Replace(string(src))
	objs, _, diags := streamAll(strings.NewReader(string(src)), cp1252)
	if len(objs) != 1 || objs[0] != want || !strings.Contains(want, "Pequeña") {
		t.Fatalf("read as %q, want %q", objs, want)
	}
	var warned []Diagnostic
	for _, d := range diags[0] {
		if d.Rule == "rpsl/not-utf8" {
			warned = append(warned, d)
		}
	}
	if len(warned) != 1 || warned[0].Span.StartLine != 6 || !strings.HasPrefix(warned[0].Message, "4 lines are not UTF-8") {
		t.Errorf("not-utf8 diagnostics = %v, want one at line 6 counting 4", warned)
	}
}

// The caps count bytes as held: a line within MaxObjectBytes as read but over
// it transcoded makes its object too large.
func TestWindows1252Caps(t *testing.T) {
	in := "a: " + strings.Repeat("\xe9", 10) + "\n" // 14 bytes, 24 as UTF-8
	for _, c := range []struct {
		cap  int64
		rule string
	}{{24, ""}, {23, "rpsl/object-too-large"}} {
		objs, _, diags := streamAll(strings.NewReader(in), ParseOptions{NonUTF8AsWindows1252: true, MaxObjectBytes: c.cap})
		var rules []string
		for _, d := range diags[0] {
			rules = append(rules, d.Rule)
		}
		switch {
		case c.rule == "" && (objs[0] != "a: éééééééééé\n" || len(rules) != 1 || rules[0] != "rpsl/not-utf8"):
			t.Errorf("cap %d: %q %v, want the line kept and one rpsl/not-utf8", c.cap, objs[0], rules)
		case c.rule != "" && (objs[0] != "" || len(rules) != 1 || rules[0] != c.rule):
			t.Errorf("cap %d: %q %v, want an empty object and %s alone", c.cap, objs[0], rules, c.rule)
		}
	}
	// Lines dropped with their object or trivia run are not counted, toward
	// it or toward the next object.
	for _, c := range []struct {
		in    string
		rules [][]string // per object
	}{
		{"a: " + strings.Repeat("\xe9", 30) + "\n\nb: 1\n", [][]string{{"rpsl/object-too-large"}, nil}},
		{"# \xe9\na: \xe9\nb: 2222222222222\n\nc: 1\n", [][]string{{"rpsl/object-too-large"}, nil}},
		{"# \xe9\n# xxxxxxxx\n# x\na: 1\n", [][]string{{"rpsl/trivia-too-large"}}}, // the run over the cap: all of it goes
		// An over-long line goes alone: the trivia before it is held, and counted.
		{"# \xe9\n# xxxxxxxxxxxxxxx\na: 1\n", [][]string{{"rpsl/trivia-too-large", "rpsl/not-utf8"}}},
	} {
		_, _, diags := streamAll(strings.NewReader(c.in), ParseOptions{NonUTF8AsWindows1252: true, MaxObjectBytes: 16})
		var got [][]string
		for _, ds := range diags {
			var rules []string
			for _, d := range ds {
				rules = append(rules, d.Rule)
			}
			got = append(got, rules)
		}
		if !reflect.DeepEqual(got, c.rules) {
			t.Errorf("%q: %v, want %v", c.in, got, c.rules)
		}
	}
}

// Read as Windows-1252, any input is UTF-8, and reading that again changes
// nothing.
func TestWindows1252Idempotent(t *testing.T) {
	var all strings.Builder
	for b := 0; b < 256; b++ {
		all.WriteString("a: ")
		all.WriteByte(byte(b))
		all.WriteString("\n")
	}
	for _, in := range []string{all.String(), "a: \xf0\x9f\x98\n", "a: \xed\xa0\x80\n", "a: \xc0\xaf\n"} {
		objs, _, _ := streamAll(strings.NewReader(in), cp1252)
		once := strings.Join(objs, "")
		if !utf8.ValidString(once) {
			t.Errorf("%q read as %q, not UTF-8", in, once)
		}
		objs, _, _ = streamAll(strings.NewReader(once), cp1252)
		if twice := strings.Join(objs, ""); twice != once {
			t.Errorf("%q: read again as %q, was %q", in, twice, once)
		}
	}
}
