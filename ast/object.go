// Package ast is the generic, lossless RPSL object model. An Object is an
// ordered list of attributes that can represent any RPSL class, including ones
// the typed layer does not know about. String reproduces the source byte-for-byte.
package ast

import (
	"errors"
	"fmt"
	"strings"

	"github.com/rkolesnichenko/rpsl/lexer"
)

// Attribute is one "name: value" unit. Raw holds the exact source bytes for the
// attribute (including continuation lines and the trailing terminator); Value is
// the comment-stripped, continuation-joined logical value.
type Attribute struct {
	Name    string // canonical lowercase
	Value   string // logical value
	Raw     string // exact source bytes
	Comment string // inline comment on the name line (after '#'), if any
	Span    lexer.Span

	// Segments maps Value offsets back to source positions (see lexer.Segment),
	// enabling precise sub-spans within a folded value.
	Segments []lexer.Segment

	// lead holds the raw bytes of any comment/blank/malformed lines that
	// immediately precede this attribute, so String stays byte-exact.
	lead string
}

// SpanAt returns a precise source span for the half-open value range
// [valStart, valEnd), translated through the segment map. It falls back to the
// whole-attribute Span when no segment map is present.
func (a Attribute) SpanAt(valStart, valEnd int) lexer.Span {
	if len(a.Segments) == 0 {
		return a.Span
	}
	t := lexer.Token{Span: a.Span, Segments: a.Segments}
	sl, sc, sb := t.SourceAt(valStart)
	el, ec, eb := t.SourceAt(valEnd)
	return lexer.Span{StartLine: sl, StartCol: sc, StartByte: sb, EndLine: el, EndCol: ec, EndByte: eb}
}

// Object is an ordered collection of attributes. Order is significant in RPSL
// (e.g. import: precedence), so attributes are stored as a slice, never a map.
type Object struct {
	attrs []Attribute
	trail string // trivia after the last attribute (within object scope)
}

// New builds an Object from a token stream (typically one object's worth).
// Non-attribute tokens are retained as round-trip trivia attached to the
// following attribute, or as trailing trivia if none follows.
func New(toks []lexer.Token) *Object {
	o := &Object{}
	var lead strings.Builder
	for _, t := range toks {
		if t.Kind != lexer.KindAttribute {
			lead.WriteString(t.Raw)
			continue
		}
		o.attrs = append(o.attrs, Attribute{
			Name:     t.Name,
			Value:    t.Value,
			Raw:      t.Raw,
			Comment:  inlineComment(t.Raw),
			Span:     t.Span,
			Segments: t.Segments,
			lead:     lead.String(),
		})
		lead.Reset()
	}
	o.trail = lead.String()
	return o
}

// Class reports the object's class: the name of its first attribute.
func (o *Object) Class() string {
	if len(o.attrs) == 0 {
		return ""
	}
	return o.attrs[0].Name
}

// Key reports the primary-key value: the value of the class-defining first attribute.
func (o *Object) Key() string {
	if len(o.attrs) == 0 {
		return ""
	}
	return o.attrs[0].Value
}

// GetFirst returns the first attribute with the given name (case-insensitive).
func (o *Object) GetFirst(name string) (Attribute, bool) {
	name = strings.ToLower(name)
	for _, a := range o.attrs {
		if a.Name == name {
			return a, true
		}
	}
	return Attribute{}, false
}

// GetAll returns every attribute with the given name, in document order.
func (o *Object) GetAll(name string) []Attribute {
	name = strings.ToLower(name)
	var out []Attribute
	for _, a := range o.attrs {
		if a.Name == name {
			out = append(out, a)
		}
	}
	return out
}

// Has reports whether the object contains an attribute with the given name.
func (o *Object) Has(name string) bool {
	_, ok := o.GetFirst(name)
	return ok
}

// Attributes returns the object's attributes in document order. The result is a
// copy, so mutating the slice does not affect the object (validation and other
// consumers iterate it read-only).
func (o *Object) Attributes() []Attribute {
	return append([]Attribute(nil), o.attrs...)
}

// String re-serializes the object byte-for-byte with the source it was parsed from.
func (o *Object) String() string {
	var b strings.Builder
	for _, a := range o.attrs {
		b.WriteString(a.lead)
		b.WriteString(a.Raw)
	}
	b.WriteString(o.trail)
	return b.String()
}

// ErrInvalidAttribute is wrapped by the errors Append and Set return for a name
// or value that RPSL cannot represent.
var ErrInvalidAttribute = errors.New("ast: invalid attribute")

// Append adds an attribute after the existing ones, serialized as
// "name: value" in the object's line-ending style. A value containing
// newlines is written as continuation lines (a '+' line for an empty one), so
// re-parsing yields the same Value; surrounding whitespace on each line is not
// significant in RPSL and is trimmed. The name must match [A-Za-z][A-Za-z0-9_-]*
// and the value may not contain '#' (it would start a comment) or control
// characters other than tab and newline; otherwise Append returns an error
// wrapping ErrInvalidAttribute and leaves the object unchanged.
func (o *Object) Append(name, value string) error {
	name, err := checkAttr(name, value)
	if err != nil {
		return err
	}
	o.ensureTrailingNewline()
	o.attrs = append(o.attrs, newAttr(name, value, name+": ", o.lineEnding()))
	return nil
}

// Set replaces every attribute named name with one attribute per value, written
// where the first of them was — keeping that line's "name:" alignment and line
// ending — or appended if there was none. Later occurrences are removed; the
// comments and blank lines before them are kept, carried to the next
// attribute. With no values, every occurrence is removed. Invalid names or
// values return an error wrapping ErrInvalidAttribute (see Append) and leave the
// object unchanged.
func (o *Object) Set(name string, values ...string) error {
	name, err := checkAttr(name, "")
	if err != nil {
		return err
	}
	for _, v := range values {
		if _, err := checkAttr(name, v); err != nil {
			return err
		}
	}
	var kept []Attribute
	var carry string
	found := false
	for _, a := range o.attrs {
		if a.Name != name {
			a.lead = carry + a.lead
			carry = ""
			kept = append(kept, a)
			continue
		}
		carry += a.lead
		if found {
			continue
		}
		found = true
		prefix, term := a.namePrefix(), lineTerm(a.Raw)
		for _, v := range values {
			na := newAttr(name, v, prefix, term)
			na.lead, carry = carry, ""
			kept = append(kept, na)
		}
	}
	o.attrs = kept
	o.trail = carry + o.trail
	if !found {
		for _, v := range values {
			o.ensureTrailingNewline()
			o.attrs = append(o.attrs, newAttr(name, v, name+": ", o.lineEnding()))
		}
	}
	return nil
}

// checkAttr lower-cases and validates an attribute name and value.
func checkAttr(name, value string) (string, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || !isLetter(name[0]) {
		return "", fmt.Errorf("%w: name %q", ErrInvalidAttribute, name)
	}
	for i := 0; i < len(name); i++ {
		if c := name[i]; !isLetter(c) && !('0' <= c && c <= '9') && c != '-' && c != '_' {
			return "", fmt.Errorf("%w: name %q", ErrInvalidAttribute, name)
		}
	}
	for i := 0; i < len(value); i++ {
		if c := value[i]; c == '#' || c == 0x7f || (c < 0x20 && c != '\t' && c != '\n') {
			return "", fmt.Errorf("%w: value %q for %s", ErrInvalidAttribute, value, name)
		}
	}
	return name, nil
}

func isLetter(c byte) bool { return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' }

// newAttr serializes a (validated) value after prefix, folding newlines into
// continuation lines indented under the value.
func newAttr(name, value, prefix, term string) Attribute {
	lines := strings.Split(value, "\n")
	var raw strings.Builder
	for i, l := range lines {
		lines[i] = strings.Trim(l, " \t")
		switch {
		case i == 0:
			raw.WriteString(prefix + lines[i])
		case lines[i] == "":
			raw.WriteString("+")
		default:
			raw.WriteString(strings.Repeat(" ", len(prefix)) + lines[i])
		}
		raw.WriteString(term)
	}
	return Attribute{Name: name, Value: strings.Join(lines, "\n"), Raw: raw.String()}
}

// namePrefix returns the attribute's name line up to where its value starts
// ("descr:   "), so a replacement keeps the original alignment.
func (a Attribute) namePrefix() string {
	line := a.Raw
	if nl := strings.IndexAny(line, "\r\n"); nl >= 0 {
		line = line[:nl]
	}
	prefix := a.Name + ": "
	if len(a.Segments) > 0 && a.Segments[0].SrcCol-1 <= len(line) {
		prefix = line[:a.Segments[0].SrcCol-1]
	}
	if !strings.HasSuffix(prefix, " ") && !strings.HasSuffix(prefix, "\t") {
		prefix += " "
	}
	return prefix
}

// lineTerm reports the line ending of raw's first line ("\n" if it has none).
func lineTerm(raw string) string {
	if nl := strings.IndexByte(raw, '\n'); nl > 0 && raw[nl-1] == '\r' {
		return "\r\n"
	}
	return "\n"
}

// lineEnding is the object's line-ending style, taken from its first attribute.
func (o *Object) lineEnding() string {
	if len(o.attrs) > 0 {
		return lineTerm(o.attrs[0].Raw)
	}
	return "\n"
}

// ensureTrailingNewline guarantees the serialization ends with a newline so a
// freshly appended attribute starts on its own line. It inspects only the last
// piece written, so repeated Appends stay linear.
func (o *Object) ensureTrailingNewline() {
	switch n := len(o.attrs); {
	case o.trail != "":
		if !strings.HasSuffix(o.trail, "\n") {
			o.trail += o.lineEnding()
		}
	case n > 0:
		if !strings.HasSuffix(o.attrs[n-1].Raw, "\n") {
			o.attrs[n-1].Raw += o.lineEnding()
		}
	}
}

// inlineComment extracts the comment (after '#') on an attribute's name line.
func inlineComment(raw string) string {
	first := raw
	if nl := strings.IndexByte(first, '\n'); nl >= 0 {
		first = first[:nl]
	}
	first = strings.TrimSuffix(first, "\r")
	if h := strings.IndexByte(first, '#'); h >= 0 {
		return strings.TrimSpace(first[h+1:])
	}
	return ""
}
