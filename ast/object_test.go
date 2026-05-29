package ast

import (
	"testing"

	"github.com/rkolesnichenko/rpsl/lexer"
)

func parse(src string) *Object {
	return New(lexer.Tokenize(src))
}

func TestRoundTripExact(t *testing.T) {
	inputs := []string{
		"aut-num: AS1\nmnt-by: M\nsource: RIPE\n",
		"# leading comment\nroute: 192.0.2.0/24\norigin: AS1\n",
		"remarks: a\n+\n b\nmembers: AS1\n",
		"person: P\nnic-hdl: X\nsource: RIPE", // no trailing newline
		"a: 1\n\n# between\nb: 2\n",            // interleaved trivia
	}
	for _, in := range inputs {
		if got := parse(in).String(); got != in {
			t.Errorf("round trip broke:\n in: %q\nout: %q", in, got)
		}
	}
}

func TestAccessors(t *testing.T) {
	o := parse("as-set: AS-FOO\nmembers: AS1\nmembers: AS2\nsource: RIPE\n")
	if o.Class() != "as-set" {
		t.Errorf("Class = %q, want as-set", o.Class())
	}
	if o.Key() != "AS-FOO" {
		t.Errorf("Key = %q, want AS-FOO", o.Key())
	}
	if !o.Has("members") || o.Has("origin") {
		t.Errorf("Has wrong: members=%v origin=%v", o.Has("members"), o.Has("origin"))
	}
	first, ok := o.GetFirst("MEMBERS") // case-insensitive
	if !ok || first.Value != "AS1" {
		t.Errorf("GetFirst members = %q (%v), want AS1", first.Value, ok)
	}
	all := o.GetAll("members")
	if len(all) != 2 || all[0].Value != "AS1" || all[1].Value != "AS2" {
		t.Errorf("GetAll members = %+v, want [AS1 AS2] in order", all)
	}
}

func TestInlineComment(t *testing.T) {
	o := parse("origin: AS1 # the origin\n")
	a, _ := o.GetFirst("origin")
	if a.Comment != "the origin" {
		t.Errorf("Comment = %q, want %q", a.Comment, "the origin")
	}
}

func TestAppend(t *testing.T) {
	o := parse("route: 192.0.2.0/24\norigin: AS1\n")
	o.Append("mnt-by", "MAINT-X")
	if !o.Has("mnt-by") {
		t.Fatal("Append did not add mnt-by")
	}
	want := "route: 192.0.2.0/24\norigin: AS1\nmnt-by: MAINT-X\n"
	if o.String() != want {
		t.Errorf("after Append:\n got %q\nwant %q", o.String(), want)
	}
}

func TestAppendNoTrailingNewline(t *testing.T) {
	o := parse("route: 192.0.2.0/24\norigin: AS1") // no trailing newline
	o.Append("source", "RIPE")
	want := "route: 192.0.2.0/24\norigin: AS1\nsource: RIPE\n"
	if o.String() != want {
		t.Errorf("got %q, want %q", o.String(), want)
	}
}

func TestSet(t *testing.T) {
	o := parse("route: 192.0.2.0/24\norigin: AS1\norigin: AS2\nsource: RIPE\n")
	o.Set("origin", "AS999")
	all := o.GetAll("origin")
	if len(all) != 1 || all[0].Value != "AS999" {
		t.Errorf("Set origin = %+v, want single AS999", all)
	}
	if !o.Has("route") || !o.Has("source") {
		t.Error("Set clobbered unrelated attributes")
	}
}
