package ast

import (
	"strings"
	"unicode"
)

// ListItem is one element of a list-valued attribute such as members:,
// mnt-by:, or member-of: (RFC 2622 §2). Start and End are byte offsets into
// Attribute.Value, so Attribute.SpanAt(it.Start, it.End) locates the item in
// the source even across folded continuation lines.
type ListItem struct {
	Value      string // trimmed of surrounding whitespace; "" for an empty item
	Start, End int    // half-open range of Value within Attribute.Value
}

// List splits the attribute's value into trimmed items in document order.
// Items are separated by commas (RFC 2622 §2) and by line breaks: IRRd joins
// the lines of a value with commas, so "members: AS1" continued by a line "AS2"
// lists two members, not one. Whitespace within a line does not separate
// items; it is left in the item for the caller to reject.
//
// Empty items between commas (",," or a comma at either end of the value) are
// kept with Value "" so callers can diagnose them. An empty item next to a line
// break — "AS1," ending a line, a "+" blank line between lines — is not an
// item, as in IRRd. Only a line break with content on both sides separates:
// blank lines at either end of the value mean nothing, so "AS1," followed by a
// "+" line lists what "AS1," does. An all-blank value yields nil.
func (a Attribute) List() []ListItem {
	v := a.Value
	if strings.TrimSpace(v) == "" {
		return nil
	}
	first := len(v) - len(strings.TrimLeftFunc(v, unicode.IsSpace))
	last := len(strings.TrimRightFunc(v, unicode.IsSpace))
	var out []ListItem
	start, afterBreak := 0, false
	for {
		end := start
		for end < len(v) && v[end] != ',' && (v[end] != '\n' || end < first || end >= last) {
			end++
		}
		atBreak := end < len(v) && v[end] == '\n'
		if it := trimItem(v, start, end); it.Value != "" || !(afterBreak || atBreak) {
			out = append(out, it)
		}
		if end == len(v) {
			return out
		}
		start, afterBreak = end+1, atBreak
	}
}

// trimItem narrows v[start:end] to exclude surrounding whitespace, using the
// same definition as strings.TrimSpace (so List's blank check agrees with it).
func trimItem(v string, start, end int) ListItem {
	s := v[start:end]
	l := strings.TrimLeftFunc(s, unicode.IsSpace)
	start += len(s) - len(l)
	end = start + len(strings.TrimRightFunc(l, unicode.IsSpace))
	return ListItem{Value: v[start:end], Start: start, End: end}
}
