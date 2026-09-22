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
		"a: 1\n\n# between\nb: 2\n",           // interleaved trivia
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
	if err := o.Append("mnt-by", "MAINT-X"); err != nil {
		t.Fatal(err)
	}
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
	if err := o.Append("source", "RIPE"); err != nil {
		t.Fatal(err)
	}
	want := "route: 192.0.2.0/24\norigin: AS1\nsource: RIPE\n"
	if o.String() != want {
		t.Errorf("got %q, want %q", o.String(), want)
	}
}

func TestSet(t *testing.T) {
	o := parse("route: 192.0.2.0/24\norigin: AS1\norigin: AS2\nsource: RIPE\n")
	if err := o.Set("origin", "AS999"); err != nil {
		t.Fatal(err)
	}
	all := o.GetAll("origin")
	if len(all) != 1 || all[0].Value != "AS999" {
		t.Errorf("Set origin = %+v, want single AS999", all)
	}
	if !o.Has("route") || !o.Has("source") {
		t.Error("Set clobbered unrelated attributes")
	}
}

// A nil *Object reads as an empty one, so objects that carry no source text
// (Raw() == nil) never panic their readers.
func TestNilObjectReads(t *testing.T) {
	var o *Object
	if o.Class() != "" || o.Key() != "" || o.Has("x") || len(o.GetAll("x")) != 0 ||
		len(o.Attributes()) != 0 || o.String() != "" {
		t.Error("nil *Object is not empty")
	}
	if _, ok := o.GetFirst("x"); ok {
		t.Error("nil *Object GetFirst found something")
	}
}

// Lookups and edits canonicalize names alike, so what Append adds GetAll finds.
func TestNameLookupMatchesEdits(t *testing.T) {
	o := New(nil)
	if err := o.Append(" Descr\t", "x"); err != nil {
		t.Fatal(err)
	}
	if got := o.GetAll(" DESCR "); len(got) != 1 || got[0].Value != "x" {
		t.Errorf("GetAll after Append = %+v", got)
	}
}

func TestDiagnosticString(t *testing.T) {
	d := Diagnostic{Severity: Error, Message: "bad line", Rule: "lexer/malformed-line",
		Span: lexer.Span{StartLine: 4, StartCol: 14}}
	if got, want := d.String(), "4:14: error lexer/malformed-line: bad line"; got != want {
		t.Errorf("String = %q, want %q", got, want)
	}
	if Info.String() != "info" || Warning.String() != "warning" || Error.String() != "error" || Severity(9).String() != "severity(9)" {
		t.Error("Severity.String")
	}
}
