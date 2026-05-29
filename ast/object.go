// Package ast is the generic, lossless RPSL object model. An Object is an
// ordered list of attributes that can represent any RPSL class, including ones
// the typed layer does not know about. String reproduces the source byte-for-byte.
package ast

import (
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

	// lead holds the raw bytes of any comment/blank/malformed lines that
	// immediately precede this attribute, so String stays byte-exact.
	lead string
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
			Name:    t.Name,
			Value:   t.Value,
			Raw:     t.Raw,
			Comment: inlineComment(t.Raw),
			Span:    t.Span,
			lead:    lead.String(),
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

// Append adds a new attribute with a canonical serialization.
func (o *Object) Append(name, value string) {
	name = strings.ToLower(strings.TrimSpace(name))
	o.ensureTrailingNewline()
	o.attrs = append(o.attrs, Attribute{
		Name:  name,
		Value: value,
		Raw:   name + ": " + value + "\n",
	})
}

// Set replaces every attribute named name with one new attribute per value
// (appending if none existed). Trivia preceding removed attributes is preserved.
func (o *Object) Set(name string, values ...string) {
	name = strings.ToLower(strings.TrimSpace(name))
	var kept []Attribute
	var carry string
	for _, a := range o.attrs {
		if a.Name == name {
			carry += a.lead
			continue
		}
		a.lead = carry + a.lead
		carry = ""
		kept = append(kept, a)
	}
	o.attrs = kept
	o.trail = carry + o.trail
	for _, v := range values {
		o.Append(name, v)
	}
}

// ensureTrailingNewline guarantees the current serialization ends with a newline
// so a freshly appended attribute starts on its own line.
func (o *Object) ensureTrailingNewline() {
	s := o.String()
	if s == "" || strings.HasSuffix(s, "\n") {
		return
	}
	if o.trail != "" {
		o.trail += "\n"
	} else if n := len(o.attrs); n > 0 {
		o.attrs[n-1].Raw += "\n"
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
