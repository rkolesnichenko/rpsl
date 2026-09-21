package ast

import (
	"strings"
	"testing"
)

// FuzzAttributeList: List never panics, its offsets stay in bounds and in
// order, each item equals its trimmed slice of Value, and the items account
// for every comma in Value.
func FuzzAttributeList(f *testing.F) {
	for _, s := range []string{"AS1, AS2", "a,,b,", " , ", "AS1\n AS2", ""} {
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
		if len(items) != strings.Count(v, ",")+1 {
			t.Fatalf("List(%q) has %d items, want %d", v, len(items), strings.Count(v, ",")+1)
		}
		prev := 0
		for _, it := range items {
			if it.Start < prev || it.End < it.Start || it.End > len(v) {
				t.Fatalf("List(%q): item %+v out of bounds/order", v, it)
			}
			if v[it.Start:it.End] != it.Value || strings.TrimSpace(it.Value) != it.Value {
				t.Fatalf("List(%q): item %+v is not a trimmed slice of Value", v, it)
			}
			prev = it.End
		}
	})
}
