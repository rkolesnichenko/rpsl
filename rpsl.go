// Package rpsl is the top-level façade over the RPSL lexer and generic object
// model. Milestone 1 exposes lossless parsing of single objects and a lazy
// streaming parser for multi-object dumps.
package rpsl

import (
	"bufio"
	"io"
	"iter"
	"strings"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/lexer"
)

// Severity ranks a Diagnostic.
type Severity uint8

const (
	Info Severity = iota
	Warning
	Error
)

// Diagnostic reports a problem found while parsing. Parsing is resilient:
// diagnostics are returned alongside a best-effort result, never via panic.
type Diagnostic struct {
	Severity Severity
	Message  string
	Span     lexer.Span
	Rule     string // machine-filterable identifier, e.g. "lexer/malformed-line"
}

// ParseObject parses exactly one object, returning the object plus any
// diagnostics. The returned object round-trips: obj.String() == text.
func ParseObject(text string) (*ast.Object, []Diagnostic) {
	toks := lexer.Tokenize(text)
	return ast.New(toks), diagnose(toks)
}

// Parse lazily parses a stream of blank-line-separated objects (IRR dumps,
// whois output). It yields one object at a time, holding only the current
// object in memory, so multi-gigabyte dumps stream rather than load wholesale.
func Parse(r io.Reader) iter.Seq2[*ast.Object, []Diagnostic] {
	return func(yield func(*ast.Object, []Diagnostic) bool) {
		br := bufio.NewReader(r)
		var buf strings.Builder
		hasAttr := false

		emit := func() bool {
			if buf.Len() == 0 {
				return true
			}
			obj, d := ParseObject(buf.String())
			buf.Reset()
			hasAttr = false
			return yield(obj, d)
		}

		for {
			line, err := br.ReadString('\n')
			if len(line) > 0 {
				switch {
				case isBlankLine(line):
					if hasAttr {
						if !emit() {
							return
						}
						// the separating blank is consumed, not attached
					} else {
						buf.WriteString(line) // leading trivia for the next object
					}
				default:
					buf.WriteString(line)
					if isAttrStart(line) {
						hasAttr = true
					}
				}
			}
			if err != nil {
				break
			}
		}
		emit()
	}
}

// diagnose reports malformed lines surfaced by the lexer.
func diagnose(toks []lexer.Token) []Diagnostic {
	var ds []Diagnostic
	for _, t := range toks {
		if t.Kind == lexer.KindMalformed {
			ds = append(ds, Diagnostic{
				Severity: Error,
				Message:  "line is not a valid attribute, continuation, comment, or blank",
				Span:     t.Span,
				Rule:     "lexer/malformed-line",
			})
		}
	}
	return ds
}

func isBlankLine(line string) bool {
	return strings.Trim(strings.TrimRight(line, "\r\n"), " \t") == ""
}

func isAttrStart(line string) bool {
	s := strings.TrimRight(line, "\r\n")
	if s == "" {
		return false
	}
	switch s[0] {
	case ' ', '\t', '+', '#':
		return false
	}
	if h := strings.IndexByte(s, '#'); h >= 0 {
		s = s[:h]
	}
	return strings.IndexByte(s, ':') >= 0
}
