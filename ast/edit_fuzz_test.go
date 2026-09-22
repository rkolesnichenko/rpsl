package ast

import (
	"errors"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/lexer"
)

// FuzzEdit: Append and Set on any object either refuse (and change nothing) or
// produce text that parses back to exactly the edit asked for: the new values,
// in the right place, with every other attribute's bytes untouched (bar a line
// ending added to the last) and no new malformed lines.
func FuzzEdit(f *testing.F) {
	for _, c := range []struct {
		src, name, value string
		op               uint8
	}{
		{"route: 192.0.2.0/24\norigin: AS1\n", "descr", "a\nb", 0},
		{"route: 192.0.2.0/24\r\ndescr: x\r\ndescr: y\r\n", "descr", "z", 1},
		{"# only a comment\n  orphan\n", "a", "1", 0},
		{"  orphan\n", "a", "1", 0},
		{"a: 1\n+\n b\n# c\n", "A", "\n\n x \t\n", 2},
		{"a:1", "b", "", 1},
		{"", "x", "y", 3},
	} {
		f.Add(c.src, c.name, c.value, c.op)
	}
	f.Fuzz(func(t *testing.T, src, name, value string, op uint8) {
		o := New(lexer.Tokenize(src))
		before, beforeText := o.Attributes(), o.String()
		var values []string
		var err error
		switch op % 4 {
		case 0:
			err = o.Append(name, value)
			values = []string{value}
		case 1:
			values = []string{value}
		case 2:
			values = []string{value, value + "\n2"}
		case 3:
			values = nil
		}
		if op%4 != 0 {
			err = o.Set(name, values...)
		}
		if err != nil {
			if !errors.Is(err, ErrInvalidAttribute) || o.String() != beforeText {
				t.Fatalf("refused edit: err %v, and the object changed to %q", err, o.String())
			}
			return
		}
		canon := lexer.CanonicalName(name)
		var want []Attribute
		switch {
		case op%4 == 0:
			want = append(before, Attribute{Name: canon, Value: normalize(value)})
		default:
			placed := false
			for _, a := range before {
				if a.Name != canon {
					want = append(want, a)
					continue
				}
				if !placed {
					for _, v := range values {
						want = append(want, Attribute{Name: canon, Value: normalize(v)})
					}
					placed = true
				}
			}
			if !placed {
				for _, v := range values {
					want = append(want, Attribute{Name: canon, Value: normalize(v)})
				}
			}
		}
		text := o.String()
		toks := lexer.Tokenize(text)
		got := New(toks).Attributes()
		if len(got) != len(want) {
			t.Fatalf("edit of %q gives %q: %d attributes, want %d", src, text, len(got), len(want))
		}
		for i := range want {
			if got[i].Name != want[i].Name || got[i].Value != want[i].Value {
				t.Fatalf("edit of %q gives %q: attribute %d is %s=%q, want %s=%q", src, text, i,
					got[i].Name, got[i].Value, want[i].Name, want[i].Value)
			}
			// An untouched attribute keeps its bytes; the last may gain a line
			// ending, so what is appended starts on a line of its own.
			rest, kept := strings.CutPrefix(got[i].Raw, want[i].Raw)
			if want[i].Raw != "" && (!kept || rest != "" && rest != "\n" && rest != "\r\n") {
				t.Fatalf("edit of %q changed untouched attribute %d from %q to %q", src, i, want[i].Raw, got[i].Raw)
			}
		}
		if malformed(toks) != malformed(lexer.Tokenize(beforeText)) {
			t.Fatalf("edit of %q gives %q, with %d malformed lines, not %d", src, text, malformed(toks), malformed(lexer.Tokenize(beforeText)))
		}
	})
}

// normalize is what a value reads back as: every line trimmed of spaces and
// tabs, as RPSL folds them.
func normalize(v string) string {
	lines := strings.Split(v, "\n")
	for i, l := range lines {
		lines[i] = strings.Trim(l, " \t")
	}
	return strings.Join(lines, "\n")
}

func malformed(toks []lexer.Token) int {
	n := 0
	for _, tk := range toks {
		if tk.Kind == lexer.KindMalformed {
			n++
		}
	}
	return n
}

// FuzzFormat: formatting is the one sanctioned departure from losslessness, so
// it must change nothing that has meaning. Whatever the input, the zero options
// reproduce the source byte for byte, and any options leave every attribute's
// name and parsed Value untouched once the result is re-parsed.
func FuzzFormat(f *testing.F) {
	for _, src := range []string{
		"route: 192.0.2.0/24\norigin: AS1\n",
		"Route:\t192.0.2.0/24   \r\nORIGIN:AS1\r\n",
		"descr: one\n two\n+\n three\n",
		"a:\n# comment\n\n  orphan\n",
		"a:1", "", "  ", ":", "a::b\n", "#\n",
	} {
		f.Add(src, 17, true)
	}
	f.Fuzz(func(t *testing.T, src string, align int, lower bool) {
		o := New(lexer.Tokenize(src))
		if got := o.Format(FormatOptions{}); got != o.String() {
			t.Fatalf("Format(zero) = %q, want String() = %q", got, o.String())
		}
		if align < -1<<20 || align > 1<<20 {
			return // a silly column would only allocate, not inform
		}
		out := o.Format(FormatOptions{Align: align, LowerNames: lower})
		again := New(lexer.Tokenize(out))
		before, after := o.Attributes(), again.Attributes()
		if len(before) != len(after) {
			t.Fatalf("Format(%q) changed the attribute count %d -> %d\n%q",
				src, len(before), len(after), out)
		}
		for i := range before {
			if before[i].Name != after[i].Name {
				t.Fatalf("Format(%q) renamed attribute %d: %q -> %q",
					src, i, before[i].Name, after[i].Name)
			}
			if before[i].Value != after[i].Value {
				t.Fatalf("Format(%q) changed value %d: %q -> %q\n%q",
					src, i, before[i].Value, after[i].Value, out)
			}
		}
	})
}
