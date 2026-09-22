package ast

import "strings"

// Building an object from scratch, for a consumer that composes RPSL rather
// than only reading it — preparing an update to submit to a registry, say.
// Parsing gives back exactly what came in; Builder is the other direction.

// Builder composes an Object attribute by attribute. It is the write-side
// counterpart of parsing: the result is an ordinary Object, so it serializes
// with String and re-parses to the same attributes.
//
// The first attribute is the class and its key, so NewBuilder takes them. The
// methods chain, and the first invalid name or value is held until Build
// reports it.
type Builder struct {
	o   *Object
	err error
}

// NewBuilder starts an object of the given class, whose first attribute is the
// class name carrying key.
func NewBuilder(class, key string) *Builder {
	b := &Builder{o: New(nil)}
	return b.Add(class, key)
}

// Add appends one attribute. A value containing newlines becomes continuation
// lines, as Append describes.
func (b *Builder) Add(name, value string) *Builder {
	if b.err != nil {
		return b
	}
	b.err = b.o.Append(name, value)
	return b
}

// AddAll appends one attribute per value, in order. No values adds nothing.
func (b *Builder) AddAll(name string, values ...string) *Builder {
	for _, v := range values {
		b.Add(name, v)
	}
	return b
}

// Build returns the object. It reports the first invalid name or value passed
// to Add or AddAll, wrapping ErrInvalidAttribute; the object is then nil.
func (b *Builder) Build() (*Object, error) {
	if b.err != nil {
		return nil, b.err
	}
	return b.o, nil
}

// String returns the object built so far, or "" if a value was rejected. It is
// a convenience for the common case where the input is known to be valid;
// Build is the form that reports the problem.
func (b *Builder) String() string {
	if b.err != nil {
		return ""
	}
	return b.o.String()
}

// FormatOptions controls Format. The zero value changes nothing.
type FormatOptions struct {
	// Align is the column the values are padded to, 1-based, counting the
	// attribute name and its colon. RIPE writes 17. Zero leaves the separator
	// as written; a name too long for the column keeps a single space.
	Align int
	// LowerNames writes each attribute name lower-case, which is how RIPE
	// stores them and how this library compares them.
	LowerNames bool
}

// Format re-serializes the object with the given normalization. It is the one
// opt-in departure from the lossless round-trip: the zero FormatOptions
// reproduces String exactly, and anything else changes only each attribute's
// first line — its name, the space after the colon, and trailing blanks on that
// line. Values, continuation lines, comments and blank lines are untouched, so
// every attribute's parsed Value survives unchanged.
func (o *Object) Format(opts FormatOptions) string {
	if o == nil {
		return ""
	}
	var b strings.Builder
	for _, a := range o.attrs {
		b.WriteString(a.lead)
		b.WriteString(formatAttr(a, opts))
	}
	b.WriteString(o.trail)
	return b.String()
}

// lowerASCII lower-cases the ASCII letters of s and leaves every other byte
// alone. An attribute name is ASCII; strings.ToLower would replace an invalid
// UTF-8 byte with U+FFFD and so rename the attribute.
func lowerASCII(s string) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'A' <= c && c <= 'Z' {
			if b == nil {
				b = []byte(s)
			}
			b[i] = c + 'a' - 'A'
		}
	}
	if b == nil {
		return s
	}
	return string(b)
}

// hasControl reports whether s holds a control byte other than tab.
func hasControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 && c != '\t' {
			return true
		}
	}
	return false
}

// formatAttr rewrites the name and separator on an attribute's first line.
func formatAttr(a Attribute, opts FormatOptions) string {
	if opts.Align <= 0 && !opts.LowerNames {
		return a.Raw
	}
	first, rest := a.Raw, ""
	if nl := strings.IndexByte(first, '\n'); nl >= 0 {
		first, rest = first[:nl], first[nl:]
	}
	cr := ""
	if strings.HasSuffix(first, "\r") {
		first, cr = first[:len(first)-1], "\r"
	}
	colon := strings.IndexByte(first, ':')
	if colon < 0 {
		return a.Raw // not an attribute line after all; leave it alone
	}
	name := first[:colon]
	value := strings.TrimRight(strings.TrimLeft(first[colon+1:], " \t"), " \t")
	if hasControl(name) || hasControl(value) {
		// A stray control byte — a lone carriage return, say — can shift where
		// the value ends once the line is rewritten. Leave such a line alone
		// rather than risk changing what it means.
		return a.Raw
	}
	if opts.LowerNames {
		name = lowerASCII(name)
	}
	if value == "" {
		return name + ":" + cr + rest
	}
	// Align is 1-based and counts the name plus its colon, so the separator is
	// Align-1 minus those len(name)+1 characters.
	sep := " "
	if n := opts.Align - len(name) - 2; opts.Align > 0 && n > 1 {
		sep = strings.Repeat(" ", n)
	}
	return name + ":" + sep + value + cr + rest
}
