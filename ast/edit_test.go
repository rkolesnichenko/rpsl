package ast

import (
	"errors"
	"runtime"
	"testing"
)

func TestSetReplacesInPlace(t *testing.T) {
	cases := []struct {
		name, src string
		attr      string
		values    []string
		want      string
	}{
		{"keeps position and alignment; drops later duplicates, keeping their trivia",
			"route:   192.0.2.0/24\ndescr:   old one\norigin:  AS1\n# note\ndescr:   old two\nsource:  RIPE\n",
			"descr", []string{"new"},
			"route:   192.0.2.0/24\ndescr:   new\norigin:  AS1\n# note\nsource:  RIPE\n"},
		{"the class attribute stays first",
			"route:   192.0.2.0/24\norigin:  AS1\n",
			"route", []string{"10.0.0.0/8"},
			"route:   10.0.0.0/8\norigin:  AS1\n"},
		{"several values land at the first position",
			"route: 1\ndescr: old\nsource: X\n",
			"descr", []string{"a", "b"},
			"route: 1\ndescr: a\ndescr: b\nsource: X\n"},
		{"no values removes every occurrence",
			"route: 1\n# about descr\ndescr: old\nsource: X\n",
			"descr", nil,
			"route: 1\n# about descr\nsource: X\n"},
		{"absent attributes are appended",
			"route: 1\nsource: X\n",
			"mnt-by", []string{"M"},
			"route: 1\nsource: X\nmnt-by: M\n"},
		{"CRLF objects stay CRLF",
			"route: 1\r\ndescr: old\r\nsource: X\r\n",
			"descr", []string{"new"},
			"route: 1\r\ndescr: new\r\nsource: X\r\n"},
	}
	for _, c := range cases {
		o := parse(c.src)
		if err := o.Set(c.attr, c.values...); err != nil {
			t.Fatalf("%s: Set: %v", c.name, err)
		}
		if got := o.String(); got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, got, c.want)
		}
		if got := parse(o.String()).String(); got != o.String() {
			t.Errorf("%s: edited object does not round-trip", c.name)
		}
	}
	o := parse("route:   192.0.2.0/24\norigin:  AS1\n")
	_ = o.Set("route", "10.0.0.0/8")
	if o.Class() != "route" || o.Key() != "10.0.0.0/8" {
		t.Errorf("after Set(route): Class %q Key %q", o.Class(), o.Key())
	}
}

// A newline in a value becomes RPSL continuation lines, so re-parsing yields the
// same Value; an empty inner line uses the '+' continuation marker.
func TestAppendFoldsMultiLineValues(t *testing.T) {
	o := parse("route: 1\n")
	if err := o.Append("remarks", "line1\nline2\n\nline4"); err != nil {
		t.Fatal(err)
	}
	want := "route: 1\nremarks: line1\n         line2\n+\n         line4\n"
	if o.String() != want {
		t.Errorf("got %q\nwant %q", o.String(), want)
	}
	a, _ := parse(o.String()).GetFirst("remarks")
	if a.Value != "line1\nline2\n\nline4" {
		t.Errorf("re-parsed Value = %q, want the appended value", a.Value)
	}
}

// Names and values that RPSL cannot represent are rejected, leaving the object
// unchanged (they used to be written out and silently mangled on re-parse).
func TestAppendRejectsUnrepresentable(t *testing.T) {
	for _, c := range []struct{ name, value string }{
		{"", "v"}, {"bad name", "v"}, {"x:y", "v"}, {"1abc", "v"}, {"a#b", "v"}, {"\ufeffroute", "v"},
		{"descr", "a # b"}, {"descr", "a\rb"}, {"descr", "a\x00b"},
	} {
		o := parse("route: 1\n")
		err := o.Append(c.name, c.value)
		if !errors.Is(err, ErrInvalidAttribute) {
			t.Errorf("Append(%q, %q) err = %v, want ErrInvalidAttribute", c.name, c.value, err)
		}
		if o.String() != "route: 1\n" {
			t.Errorf("Append(%q, %q) changed the object to %q", c.name, c.value, o.String())
		}
		if err := o.Set(c.name, c.value); !errors.Is(err, ErrInvalidAttribute) {
			t.Errorf("Set(%q, %q) err = %v, want ErrInvalidAttribute", c.name, c.value, err)
		}
	}
}

// Building an object attribute by attribute is linear, not quadratic.
func TestAppendIsLinear(t *testing.T) {
	cost := func(n int) uint64 {
		var before, after runtime.MemStats
		o := parse("route: 1\n")
		runtime.ReadMemStats(&before)
		for i := 0; i < n; i++ {
			if err := o.Append("remarks", "x"); err != nil {
				t.Fatal(err)
			}
		}
		runtime.ReadMemStats(&after)
		return after.TotalAlloc - before.TotalAlloc
	}
	small, large := cost(10000), cost(20000)
	if ratio := float64(large) / float64(small); ratio > 3 {
		t.Errorf("allocation grew %.1fx when appends doubled (%d -> %d bytes); want ~2x", ratio, small, large)
	}
}
