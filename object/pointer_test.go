package object

import (
	"reflect"
	"testing"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/lexer"
)

// TestDecodeReturnsPointers: every class any profile knows decodes to a
// non-nil pointer of its own class, and an unknown class to *Generic, so a
// type switch over object.Object meets one form only.
func TestDecodeReturnsPointers(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range []Profile{RIPE, IRRd, ARIN, RFCStrict} {
		for _, class := range p.Classes() {
			if seen[class] {
				continue
			}
			seen[class] = true
			o, _ := Decode(ast.New(lexer.Tokenize(class + ": X\nsource: RIPE\n")))
			if v := reflect.ValueOf(o); v.Kind() != reflect.Pointer || v.IsNil() {
				t.Errorf("Decode(%s) = %T, want a non-nil pointer", class, o)
				continue
			}
			if o.Class() != class {
				t.Errorf("Decode(%s).Class() = %q", class, o.Class())
			}
		}
	}
	if o, _ := Decode(ast.New(lexer.Tokenize("no-such-class: X\n"))); reflect.TypeOf(o) != reflect.TypeOf(&Generic{}) {
		t.Errorf("unknown class decodes to %T, want *object.Generic", o)
	}
}
