package ast

import (
	"strings"
	"testing"
	"unicode"
)

// FuzzAttributeList: List never panics, its offsets stay in bounds and in
// order, each item equals its trimmed slice of Value and lies within one line,
// the non-empty items are Value split at commas and line breaks, an empty item
// is never next to a line break between content, and without line breaks the items account
// for every comma in Value.
func FuzzAttributeList(f *testing.F) {
	for _, s := range []string{"AS1, AS2", "a,,b,", " , ", "AS1\n AS2", "", "AS1,\n\n,AS2", " \n , \n"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, v string) {
		items := Attribute{Value: v}.List()
		if strings.TrimSpace(v) == "" {
			if items != nil {
				t.Fatalf("List(%q) = %+v, want nil for a blank value", v, items)
			}
			return
		}
		// Without line breaks, commas alone separate items.
		if !strings.Contains(v, "\n") && len(items) != strings.Count(v, ",")+1 {
			t.Fatalf("List(%q) has %d items, want %d", v, len(items), strings.Count(v, ",")+1)
		}
		// The non-empty items are the value split at commas and line breaks.
		var want, got []string
		for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == '\n' }) {
			if f = strings.TrimSpace(f); f != "" {
				want = append(want, f)
			}
		}
		prev := 0
		for _, it := range items {
			if it.Start < prev || it.End < it.Start || it.End > len(v) {
				t.Fatalf("List(%q): item %+v out of bounds/order", v, it)
			}
			if v[it.Start:it.End] != it.Value || strings.TrimSpace(it.Value) != it.Value {
				t.Fatalf("List(%q): item %+v is not a trimmed slice of Value", v, it)
			}
			if strings.Contains(it.Value, "\n") {
				t.Fatalf("List(%q): item %+v spans a line break", v, it)
			}
			// An empty item lies between commas (or a comma and an end of the
			// value), never next to a line break that has content on both sides.
			if it.Value == "" {
				l := strings.TrimRightFunc(v[:it.Start], unicode.IsSpace)
				r := strings.TrimLeftFunc(v[it.End:], unicode.IsSpace)
				if l != "" && r != "" && strings.Contains(v[len(l):it.Start]+v[it.End:len(v)-len(r)], "\n") {
					t.Fatalf("List(%q): empty item %+v next to a line break", v, it)
				}
			} else {
				got = append(got, it.Value)
			}
			prev = it.End
		}
		if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
			t.Fatalf("List(%q) items %q, want %q", v, got, want)
		}
	})
}
