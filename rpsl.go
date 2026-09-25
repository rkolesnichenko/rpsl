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
// profiles are RIPE, IRRd, ARIN and RFCStrict.
type Profile = object.Profile

// The built-in validation profiles (design §10): RIPE is the RIPE Database's
// templates, IRRd is IRRd 4's class tables — what RADB and the IRRs it mirrors
// accept — ARIN is ARIN's IRR as it serves its objects (IRRd's tables for
// ARIN's five classes, with the created: ARIN adds), and RFCStrict admits only
// the attributes of RFC 2622, 2725, 2726 and 4012.
var (
	RIPE      = object.RIPE
	IRRd      = object.IRRd
	ARIN      = object.ARIN
	RFCStrict = object.RFCStrict
)

// Diagnostic and Severity live in the ast module so lower layers (object decoding)
// can emit them without importing this façade. They are re-exported here for
// convenience.
type (
	Diagnostic = ast.Diagnostic
	Severity   = ast.Severity
)

// The severities, re-exported from ast.
const (
	Info    = ast.Info
	Warning = ast.Warning
	Error   = ast.Error
)

// ParseObject parses exactly one object, returning the object plus any
// diagnostics. The returned object round-trips: obj.String() == text. Positions
// are relative to text. Text holding more than one object still parses and
// round-trips as one, with a Warning ("rpsl/multiple-objects"); use Parse for
// dumps. ParseObject applies no size caps — text is already in memory, and
// parsing it costs a few hundred bytes per line — so for untrusted input of
// unknown size, stream it through ParseWith instead.
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

// maxLexerDiagnostics caps the per-line lexer diagnostics (malformed lines,
// invalid attribute names) reported for one object; the rest are counted in one
// "lexer/too-many-errors" diagnostic, so hostile input cannot turn every line
// into a retained Diagnostic.
const maxLexerDiagnostics = 100

// diagnose reports what the lexer surfaced: malformed lines, attribute names
// RPSL does not allow, and a second object inside what should be one.
func diagnose(toks []lexer.Token) []Diagnostic {
	var ds []Diagnostic
	lineDiags, extra := 0, 0
	var firstExtra lexer.Span
	perLine := func(d Diagnostic) {
		if lineDiags++; lineDiags <= maxLexerDiagnostics {
			ds = append(ds, d)
			return
		}
		if extra++; extra == 1 {
			firstExtra = d.Span
		}
	}
	seenAttr, blankAfterAttr, warned := false, false, false
	for _, t := range toks {
		switch t.Kind {
		case lexer.KindMalformed:
			perLine(ast.Diagnostic{
				Severity: ast.Error,
				Message:  "line is not a valid attribute, continuation, comment, or blank",
				Span:     t.Span,
				Rule:     "lexer/malformed-line",
			})
		case lexer.KindBlank:
			blankAfterAttr = seenAttr
		case lexer.KindAttribute:
			if !validAttrName(t.Name) {
				perLine(ast.Diagnostic{
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
	if extra > 0 {
		ds = append(ds, ast.Diagnostic{
			Severity: ast.Error,
			Message:  fmt.Sprintf("%d more malformed lines or invalid attribute names not reported", extra),
			Span:     firstExtra,
			Rule:     "lexer/too-many-errors",
		})
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

// Builder composes a new object attribute by attribute, the write-side
// counterpart of parsing. It is re-exported from ast for the same reason
// Diagnostic is: a consumer that only builds and parses objects needs one
// import.
type Builder = ast.Builder

// NewBuilder starts an object of the given class, carrying key.
func NewBuilder(class, key string) *Builder { return ast.NewBuilder(class, key) }

// FormatOptions controls the opt-in normalization of ast.Object.Format: the
// column values are aligned at, and whether attribute names are lower-cased.
// The zero value changes nothing.
type FormatOptions = ast.FormatOptions
