package ast

import (
	"strings"
	"unicode"
)

// ListItem is one comma-separated element of a list-valued attribute such as
// members:, mnt-by:, or member-of: (RFC 2622 §2). Start and End are byte offsets
// into Attribute.Value, so Attribute.SpanAt(it.Start, it.End) locates the item
// in the source even across folded continuation lines.
type ListItem struct {
	Value      string // trimmed of surrounding whitespace; "" for an empty item
	Start, End int    // half-open range of Value within Attribute.Value
}

// List splits the attribute's value on ',' into trimmed items in document
// order. Empty items (from ",," or a trailing comma) are kept with Value "" so
// callers can diagnose them; an all-blank value yields nil. Only commas
// separate items — whitespace inside an item is left for the caller to reject.
func (a Attribute) List() []ListItem {
	if strings.TrimSpace(a.Value) == "" {
		return nil
	}
	var out []ListItem
	start := 0
	for {
		end := strings.IndexByte(a.Value[start:], ',')
		if end < 0 {
			end = len(a.Value)
		} else {
			end += start
		}
		out = append(out, trimItem(a.Value, start, end))
		if end == len(a.Value) {
			return out
		}
		start = end + 1
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
