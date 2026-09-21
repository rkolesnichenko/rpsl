// Package rpsl is the top-level façade over the RPSL lexer, generic object
// model, typed decoding, and class/attribute validation. It exposes lossless
// parsing of single objects, a lazy streaming parser for multi-object dumps,
// typed Decode, and profile-based Validate.
package rpsl

import (
	"fmt"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/lexer"
	"github.com/rkolesnichenko/rpsl/object"
)

// Object is a typed RPSL object (AutNum, Route, AsSet, …) produced by Decode.
// It is re-exported from the object package so consumers need only this façade.
type Object = object.Object

// Profile is a class/attribute dictionary used by Validate. The built-in
// profiles are RIPE and RFCStrict.
type Profile = object.Profile

// RIPE and RFCStrict are the built-in validation profiles (design §10): RIPE
// mirrors IRRd/RIPE reality (extra attributes, legacy changed:), RFCStrict
// admits only RFC 2622/2650/4012 attributes.
var (
	RIPE      = object.RIPE
	RFCStrict = object.RFCStrict
)

// Diagnostic and Severity live in the ast module so lower layers (object decoding)
// can emit them without importing this façade. They are re-exported here for
// convenience.
type (
	Diagnostic = ast.Diagnostic
	Severity   = ast.Severity
)

const (
	Info    = ast.Info
	Warning = ast.Warning
	Error   = ast.Error
)

// ParseObject parses exactly one object, returning the object plus any
// diagnostics. The returned object round-trips: obj.String() == text. Positions
// are relative to text. Text holding more than one object still parses and
// round-trips as one, with a Warning ("rpsl/multiple-objects"); use Parse for
// dumps.
func ParseObject(text string) (*ast.Object, []Diagnostic) {
	return parseObjectAt(text, 1, 0)
}

// parseObjectAt parses text that begins at the given line and byte of a stream.
func parseObjectAt(text string, line, byteOffset int) (*ast.Object, []Diagnostic) {
	toks := lexer.TokenizeAt(text, line, byteOffset)
	return ast.New(toks), diagnose(toks)
}

// Decode upgrades a generic object to its typed form (AutNum, Route, AsSet, …),
// returning best-effort diagnostics. Unknown classes degrade to a generic
// object. Decoding never fails a whole object; use Validate for schema checks.
func Decode(o *ast.Object) (Object, []Diagnostic) {
	return object.Decode(o)
}

// Validate checks an object against a dictionary profile, reporting unknown
// attributes, missing required attributes, and cardinality violations. It is
// separate from Decode so parsing stays resilient and validation stays opt-in.
func Validate(o *ast.Object, p Profile) []Diagnostic {
	return p.Validate(o)
}

// diagnose reports what the lexer surfaced: malformed lines, attribute names
// RPSL does not allow, and a second object inside what should be one.
func diagnose(toks []lexer.Token) []Diagnostic {
	var ds []Diagnostic
	seenAttr, blankAfterAttr, warned := false, false, false
	for _, t := range toks {
		switch t.Kind {
		case lexer.KindMalformed:
			ds = append(ds, ast.Diagnostic{
				Severity: ast.Error,
				Message:  "line is not a valid attribute, continuation, comment, or blank",
				Span:     t.Span,
				Rule:     "lexer/malformed-line",
			})
		case lexer.KindBlank:
			blankAfterAttr = seenAttr
		case lexer.KindAttribute:
			if !validAttrName(t.Name) {
				ds = append(ds, ast.Diagnostic{
					Severity: ast.Error,
					Message:  fmt.Sprintf("invalid attribute name %q", t.Name),
					Span:     t.Span,
					Rule:     "lexer/invalid-attribute-name",
				})
			}
			if blankAfterAttr && !warned {
				warned = true
				ds = append(ds, ast.Diagnostic{
					Severity: ast.Warning,
					Message:  "text holds more than one object; use Parse for multi-object input",
					Span:     t.Span,
					Rule:     "rpsl/multiple-objects",
				})
			}
			seenAttr = true
		}
	}
	return ds
}

// validAttrName reports whether a (lower-cased) attribute name is well formed:
// a letter followed by letters, digits, '-' or '_'.
func validAttrName(n string) bool {
	if n == "" || n[0] < 'a' || n[0] > 'z' {
		return false
	}
	for i := 1; i < len(n); i++ {
		if c := n[i]; !('a' <= c && c <= 'z') && !('0' <= c && c <= '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}
