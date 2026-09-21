// Package lexer is a hand-written, line-oriented scanner for RPSL text.
//
// Its defining property is that Tokenize is a *total partition* of the input:
// every byte of the source belongs to exactly one token's Raw field, in order.
// Therefore concatenating every token's Raw reproduces the source byte-for-byte,
// which is the foundation of the library's lossless round-trip guarantee.
package lexer

import "strings"

// Kind classifies a token.
type Kind uint8

const (
	// KindAttribute is a folded "name: value" unit: the name line plus any
	// continuation lines that follow it.
	KindAttribute Kind = iota
	// KindBlank is an empty or whitespace-only line — an object-separator candidate.
	KindBlank
	// KindComment is a standalone full-line comment (first byte is '#').
	KindComment
	// KindMalformed is a non-continuation, non-blank line with no ':' — its bytes
	// are still preserved so round-trip holds, but it should be diagnosed.
	KindMalformed
)

// Span locates a token in the source. Lines and columns are 1-based and columns
// count bytes, not characters; EndCol is exclusive and excludes the line
// terminator. Byte offsets are a half-open [StartByte, EndByte) range into the
// source and include the terminator.
type Span struct {
	StartLine, StartCol int
	EndLine, EndCol     int
	StartByte, EndByte  int
}

// Segment maps a contiguous range of an attribute's logical Value back to its
// source location. A folded value is a join of one segment per physical line
// (the name line plus each continuation); within a segment, value bytes map 1:1
// to source bytes, so a value offset translates to source by linear offset from
// the segment start. ValStart/ValEnd are a half-open range into Token.Value.
type Segment struct {
	ValStart, ValEnd int // range within Token.Value
	SrcLine, SrcCol  int // 1-based source position of the segment's first byte
	SrcByte          int // source byte offset of the segment's first byte
}

// Token is a single lexical unit. Raw holds the exact original bytes (including
// continuation lines, inline comments, and the trailing line terminator); Value
// holds the comment-stripped, continuation-joined logical value for attributes.
// Segments maps Value offsets back to source positions (attributes only).
type Token struct {
	Kind     Kind
	Name     string // canonical lowercased attribute name; "" for non-attribute kinds
	Value    string // logical value for attributes; "" for non-attribute kinds
	Raw      string // exact source bytes for this token
	Span     Span
	Segments []Segment
}

// SourceAt maps a byte offset within this token's Value to a source position
// (1-based line/col and a byte offset into the source). Offsets on the join
// newline between segments resolve to the end of the preceding segment. When no
// segment map is present it falls back to the token's start.
func (t Token) SourceAt(valOffset int) (line, col, byteoff int) {
	if len(t.Segments) == 0 {
		return t.Span.StartLine, t.Span.StartCol, t.Span.StartByte
	}
	if valOffset < 0 {
		valOffset = 0
	}
	for _, s := range t.Segments {
		if valOffset <= s.ValEnd {
			d := valOffset - s.ValStart
			if d < 0 {
				d = 0
			}
			return s.SrcLine, s.SrcCol + d, s.SrcByte + d
		}
	}
	last := t.Segments[len(t.Segments)-1]
	d := last.ValEnd - last.ValStart
	return last.SrcLine, last.SrcCol + d, last.SrcByte + d
}

// physLine is one physical source line with its terminator preserved.
type physLine struct {
	text  string // content without the line terminator
	term  string // "\n", "\r\n", "\r" or "" at end of input
	start int    // byte offset of the line start
	line  int    // 1-based line number
}

// Tokenize partitions src into a gap-free, in-order sequence of tokens such that
// the concatenation of every token's Raw equals src exactly. It never panics and
// runs in time linear in len(src). Positions are relative to src (line 1, byte 0).
func Tokenize(src string) []Token { return TokenizeAt(src, 1, 0) }

// TokenizeAt is Tokenize for a src that begins at the given 1-based line and
// byte offset of a larger stream (at the start of a line): every Span and
// Segment position is reported in stream coordinates. Raw and Value are
// unaffected.
func TokenizeAt(src string, line, byteOffset int) []Token {
	var toks []Token
	var cur *Token    // attribute being folded, or nil
	var curStart int  // src offset where cur begins
	var segs []string // logical value segments for cur
	var valOff int    // running offset within the joined value for the next segment
	lineBase := line - 1

	flush := func() {
		if cur != nil {
			cur.Raw = src[curStart : cur.Span.EndByte-byteOffset] // a slice: no copying per line
			cur.Value = strings.Join(segs, "\n")
			toks = append(toks, *cur)
			cur, segs, valOff = nil, nil, 0
		}
	}

	for _, pl := range scanLines(src) {
		endByte := pl.start + len(pl.text) + len(pl.term)
		kind, isCont := classify(pl.text, cur != nil)

		if isCont {
			cur.Span.EndLine = lineBase + pl.line
			cur.Span.EndCol = len(pl.text) + 1
			cur.Span.EndByte = byteOffset + endByte
			val, off := contValue(pl.text)
			segs = append(segs, val)
			cur.Segments = append(cur.Segments, Segment{
				ValStart: valOff, ValEnd: valOff + len(val),
				SrcLine: lineBase + pl.line, SrcCol: off + 1, SrcByte: byteOffset + pl.start + off,
			})
			valOff += len(val) + 1 // +1 for the join newline
			continue
		}

		flush()
		span := Span{
			StartLine: lineBase + pl.line, StartCol: 1,
			EndLine: lineBase + pl.line, EndCol: len(pl.text) + 1,
			StartByte: byteOffset + pl.start, EndByte: byteOffset + endByte,
		}
		switch kind {
		case KindAttribute:
			name, val, off := splitAttr(pl.text)
			cur = &Token{Kind: KindAttribute, Name: name, Span: span}
			curStart = pl.start
			segs = []string{val}
			cur.Segments = []Segment{{
				ValStart: 0, ValEnd: len(val),
				SrcLine: lineBase + pl.line, SrcCol: off + 1, SrcByte: byteOffset + pl.start + off,
			}}
			valOff = len(val) + 1
		default:
			toks = append(toks, Token{Kind: kind, Raw: src[pl.start:endByte], Span: span})
		}
	}
	flush()
	return toks
}

// scanLines splits src into physical lines, preserving each line's terminator so
// the bytes can be reassembled exactly. A "\r" at the very end of input (with no
// "\n" after it) is treated as that line's terminator.
func scanLines(src string) []physLine {
	var lines []physLine
	i, lineNo := 0, 1
	for i < len(src) {
		start := i
		j := i
		for j < len(src) && src[j] != '\n' {
			j++
		}
		var text, term string
		switch {
		case j < len(src): // hit a '\n'
			if j > start && src[j-1] == '\r' {
				text, term = src[start:j-1], "\r\n"
			} else {
				text, term = src[start:j], "\n"
			}
			i = j + 1
		case j > start && src[j-1] == '\r': // end of input after a lone '\r'
			text, term = src[start:j-1], "\r"
			i = j
		default: // end of input, no trailing newline
			text, term = src[start:j], ""
			i = j
		}
		lines = append(lines, physLine{text: text, term: term, start: start, line: lineNo})
		lineNo++
	}
	return lines
}

// classify decides a physical line's kind. isCont is true when the line folds
// into the in-progress attribute (haveCur reports whether one exists).
func classify(text string, haveCur bool) (kind Kind, isCont bool) {
	if strings.Trim(text, " \t") == "" {
		return KindBlank, false
	}
	switch text[0] {
	case ' ', '\t', '+':
		if haveCur {
			return KindAttribute, true
		}
		return KindMalformed, false
	case '#':
		return KindComment, false
	}
	content := text
	if h := strings.IndexByte(content, '#'); h >= 0 {
		content = content[:h]
	}
	if strings.IndexByte(content, ':') >= 0 {
		return KindAttribute, false
	}
	return KindMalformed, false
}

// splitAttr extracts the canonical (lowercased) attribute name, the
// comment-stripped trimmed value, and the byte offset of the value's first
// character within the line.
func splitAttr(text string) (name, value string, valOff int) {
	content := text
	if h := strings.IndexByte(content, '#'); h >= 0 {
		content = content[:h]
	}
	idx := strings.IndexByte(content, ':')
	if idx < 0 {
		v, off := trimPos(content, 0)
		return "", v, off
	}
	name = strings.ToLower(strings.TrimSpace(content[:idx]))
	value, valOff = trimPos(content, idx+1)
	return name, value, valOff
}

// contValue computes the logical value contributed by a continuation line (the
// leading space/tab/'+' marker is dropped, comments are stripped, surrounding
// whitespace trimmed) and the byte offset of its first character within the line.
func contValue(text string) (value string, valOff int) {
	content := text
	if h := strings.IndexByte(content, '#'); h >= 0 {
		content = content[:h]
	}
	if content == "" {
		return "", 0
	}
	if content[0] == '+' {
		return trimPos(content, 1)
	}
	return trimPos(content, 0)
}

// trimPos returns the whitespace-trimmed value of content[from:] together with
// the byte offset (within content, hence within the line) of its first
// non-whitespace character. The trimmed value maps 1:1 to source bytes.
func trimPos(content string, from int) (value string, off int) {
	rest := content[from:]
	trimmedLeft := strings.TrimLeft(rest, " \t")
	off = from + (len(rest) - len(trimmedLeft))
	return strings.TrimRight(trimmedLeft, " \t"), off
}
