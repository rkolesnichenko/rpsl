package ast

import (
	"errors"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/lexer"
)

func TestBuilder(t *testing.T) {
	o, err := NewBuilder("route", "192.0.2.0/24").
		Add("origin", "AS65001").
		AddAll("mnt-by", "MNT-A", "MNT-B").
		Add("source", "RIPE").
		Build()
	if err != nil {
		t.Fatal(err)
	}
	want := "route: 192.0.2.0/24\norigin: AS65001\nmnt-by: MNT-A\nmnt-by: MNT-B\nsource: RIPE\n"
	if got := o.String(); got != want {
		t.Errorf("String() =\n%q\nwant\n%q", got, want)
	}
	if o.Class() != "route" || o.Key() != "192.0.2.0/24" {
		t.Errorf("Class/Key = %q/%q", o.Class(), o.Key())
	}
	// What was built re-parses to exactly the attributes that went in.
	again := New(lexer.Tokenize(o.String()))
	if again.String() != o.String() {
		t.Errorf("re-parse changed the text")
	}
	got := attrPairs(again)
	wantPairs := []string{"route=192.0.2.0/24", "origin=AS65001", "mnt-by=MNT-A", "mnt-by=MNT-B", "source=RIPE"}
	if strings.Join(got, " ") != strings.Join(wantPairs, " ") {
		t.Errorf("re-parsed attributes = %v, want %v", got, wantPairs)
	}
}

// A multi-line value becomes continuation lines and survives the round trip.
func TestBuilderMultiLineValue(t *testing.T) {
	o, err := NewBuilder("person", "Example Person").
		Add("address", "One Street\nSome Town\nRIPE Land").
		Add("nic-hdl", "EX1-RIPE").
		Build()
	if err != nil {
		t.Fatal(err)
	}
	again := New(lexer.Tokenize(o.String()))
	a, ok := again.GetFirst("address")
	if !ok {
		t.Fatal("address was lost")
	}
	if a.Value != "One Street\nSome Town\nRIPE Land" {
		t.Errorf("address Value = %q", a.Value)
	}
	if again.String() != o.String() {
		t.Error("re-parse changed the text")
	}
}

// AddAll with no values adds nothing, and Build reports the first bad input.
func TestBuilderErrors(t *testing.T) {
	o, err := NewBuilder("route", "192.0.2.0/24").AddAll("mnt-by").Build()
	if err != nil {
		t.Fatal(err)
	}
	if len(o.Attributes()) != 1 {
		t.Errorf("AddAll with no values added %d attributes", len(o.Attributes())-1)
	}
	for _, c := range []struct{ name, value string }{
		{"1bad", "x"},
		{"ok", "has # a comment"},
		{"", "x"},
	} {
		b := NewBuilder("route", "192.0.2.0/24").Add(c.name, c.value).Add("source", "RIPE")
		got, err := b.Build()
		if err == nil {
			t.Errorf("Add(%q, %q) was accepted: %q", c.name, c.value, got.String())
			continue
		}
		if !errors.Is(err, ErrInvalidAttribute) {
			t.Errorf("Add(%q, %q) error = %v, want ErrInvalidAttribute", c.name, c.value, err)
		}
		if got != nil {
			t.Errorf("Build returned an object alongside an error")
		}
		if b.String() != "" {
			t.Errorf("String() on a failed builder = %q", b.String())
		}
	}
}

func TestFormat(t *testing.T) {
	src := "Route:   192.0.2.0/24   \n" +
		"ORIGIN:AS65001\n" +
		"descr: one\n" +
		"       two\n" +
		"remarks:\n" +
		"# a comment\n" +
		"source:        RIPE\n"
	o := New(lexer.Tokenize(src))

	// The zero options change nothing at all.
	if got := o.Format(FormatOptions{}); got != src {
		t.Errorf("Format(zero) =\n%q\nwant\n%q", got, src)
	}

	got := o.Format(FormatOptions{Align: 17, LowerNames: true})
	want := "route:          192.0.2.0/24\n" +
		"origin:         AS65001\n" +
		"descr:          one\n" +
		"       two\n" +
		"remarks:\n" +
		"# a comment\n" +
		"source:         RIPE\n"
	if got != want {
		t.Errorf("Format =\n%q\nwant\n%q", got, want)
	}

	// Formatting changes no parsed value, and the result re-parses to the same
	// attributes — that is what makes this normalization safe to opt into.
	again := New(lexer.Tokenize(got))
	if a, b := attrPairs(o), attrPairs(again); strings.Join(a, "|") != strings.Join(b, "|") {
		t.Errorf("Format changed the attributes:\n%v\n%v", a, b)
	}
}

// Format keeps CRLF line endings and a missing final newline.
func TestFormatLineEndings(t *testing.T) {
	src := "route:\t192.0.2.0/24\r\norigin: AS1\r\n"
	o := New(lexer.Tokenize(src))
	got := o.Format(FormatOptions{Align: 17})
	want := "route:          192.0.2.0/24\r\norigin:         AS1\r\n"
	if got != want {
		t.Errorf("Format =\n%q\nwant\n%q", got, want)
	}
	o = New(lexer.Tokenize("route: 192.0.2.0/24"))
	if got := o.Format(FormatOptions{Align: 17}); got != "route:          192.0.2.0/24" {
		t.Errorf("Format without a final newline = %q", got)
	}
	// A name longer than the column keeps a single space.
	o = New(lexer.Tokenize("a-very-long-attribute-name: v\n"))
	if got := o.Format(FormatOptions{Align: 10}); got != "a-very-long-attribute-name: v\n" {
		t.Errorf("Format of an over-long name = %q", got)
	}
	// A nil object formats to "".
	var nilObj *Object
	if got := nilObj.Format(FormatOptions{Align: 17}); got != "" {
		t.Errorf("nil Format = %q", got)
	}
}

// attrPairs renders an object's attributes as "name=value" for comparison.
func attrPairs(o *Object) []string {
	var out []string
	for _, a := range o.Attributes() {
		out = append(out, a.Name+"="+a.Value)
	}
	return out
}

// With Align zero, Format leaves the separator as written, as its doc says;
// only the name's case and the line's trailing blanks change.
func TestFormatAlignZeroKeepsSeparator(t *testing.T) {
	o := New(lexer.Tokenize("Descr:\t\tfoo  \nRemarks:   bar\n"))
	if got, want := o.Format(FormatOptions{LowerNames: true}), "descr:\t\tfoo\nremarks:   bar\n"; got != want {
		t.Errorf("Format(LowerNames) = %q, want %q", got, want)
	}
	if got, want := o.Format(FormatOptions{Align: 17}), "Descr:          foo\nRemarks:        bar\n"; got != want {
		t.Errorf("Format(Align 17) = %q, want %q", got, want)
	}
}
