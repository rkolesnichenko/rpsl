package ast

import (
	"fmt"

	"github.com/rkolesnichenko/rpsl/lexer"
)

// Severity ranks a Diagnostic. Info is advisory (e.g. a lint-style nudge),
// Warning means the object decoded but a value was suspect, Error means a value
// or line could not be interpreted at all. Severity orders Info < Warning <
// Error so callers can filter on (d.Severity >= ast.Warning); for finer
// dispatch see Diagnostic.Rule, which is the stable machine-filterable handle.
type Severity uint8

// The severities, in increasing order.
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

// String returns "info", "warning" or "error".
func (s Severity) String() string {
	switch s {
	case Info:
		return "info"
	case Warning:
		return "warning"
	case Error:
		return "error"
	}
	return fmt.Sprintf("severity(%d)", uint8(s))
}

// String formats d as "line:col: severity rule: message".
func (d Diagnostic) String() string {
	return fmt.Sprintf("%d:%d: %s %s: %s", d.Span.StartLine, d.Span.StartCol, d.Severity, d.Rule, d.Message)
}
