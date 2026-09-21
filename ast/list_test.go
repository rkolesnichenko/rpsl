package ast

import (
	"reflect"
	"testing"
)

func TestAttributeList(t *testing.T) {
	cases := []struct {
		src  string
		want []ListItem
	}{
		{"members: AS1, AS2,AS3\n", []ListItem{{"AS1", 0, 3}, {"AS2", 5, 8}, {"AS3", 9, 12}}},
		{"members: AS1\n", []ListItem{{"AS1", 0, 3}}},
		// Empty items (",," and a trailing comma) are reported, not dropped, so
		// the decoder can diagnose them.
		{"members: AS1,,AS2,\n", []ListItem{{"AS1", 0, 3}, {"", 4, 4}, {"AS2", 5, 8}, {"", 9, 9}}},
		// Whitespace is not a separator: RFC 2622 §2 lists are comma-separated.
		{"members: AS1 AS2\n", []ListItem{{"AS1 AS2", 0, 7}}},
		{"members:    \n", nil},
	}
	for _, c := range cases {
		a, _ := parse(c.src).GetFirst("members")
		got := a.List()
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%q: List() = %+v, want %+v", c.src, got, c.want)
			continue
		}
		for _, it := range got {
			if a.Value[it.Start:it.End] != it.Value {
				t.Errorf("%q: item %q does not match Value[%d:%d] = %q",
					c.src, it.Value, it.Start, it.End, a.Value[it.Start:it.End])
			}
		}
	}
}

// A list folded across continuation lines (with a comment in between) splits
// into the right items, and each item's span points at its own source line.
func TestAttributeListFolded(t *testing.T) {
	src := "as-set: AS-X\nmembers: AS1, # first\n  AS2,\n+\n\tAS-Y\n"
	a, _ := parse(src).GetFirst("members")
	got := a.List()
	var vals []string
	for _, it := range got {
		vals = append(vals, it.Value)
	}
	if !reflect.DeepEqual(vals, []string{"AS1", "AS2", "AS-Y"}) {
		t.Fatalf("List() values = %q, want [AS1 AS2 AS-Y]", vals)
	}
	for i, want := range []struct{ line, col int }{{2, 10}, {3, 3}, {5, 2}} {
		sp := a.SpanAt(got[i].Start, got[i].End)
		if sp.StartLine != want.line || sp.StartCol != want.col {
			t.Errorf("item %q span starts at %d:%d, want %d:%d",
				got[i].Value, sp.StartLine, sp.StartCol, want.line, want.col)
		}
	}
}
