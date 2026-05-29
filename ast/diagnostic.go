package ast

import "github.com/rkolesnichenko/rpsl/lexer"

// Severity ranks a Diagnostic.
type Severity uint8

const (
	Info Severity = iota
	Warning
	Error
)

// Diagnostic reports a problem found while parsing or decoding. Parsing is
// resilient: diagnostics are returned alongside a best-effort result, never via
// panic. Rule is a machine-filterable identifier, e.g. "lexer/malformed-line".
type Diagnostic struct {
	Severity Severity
	Message  string
	Span     lexer.Span
	Rule     string
}
