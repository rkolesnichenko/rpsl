package rpsl

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"iter"
	"strings"
	"unicode/utf8"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/lexer"
)

// DefaultMaxObjectBytes is the cap on a single object's source applied by Parse
// and by a zero ParseOptions.MaxObjectBytes. The largest object in the RIPE
// database is about 2 MB; the cap exists to bound memory on hostile input.
const DefaultMaxObjectBytes = 16 << 20

// DefaultMaxObjectLines is the cap on a single object's lines applied by Parse
// and by a zero ParseOptions.MaxObjectLines. The longest RIPE object has about
// 20,000 lines. Each line costs a few hundred bytes to parse, so the line cap,
// not the byte cap, bounds memory on input made of many short lines.
const DefaultMaxObjectLines = 1 << 18

// ParseOptions tunes the streaming parser. Its caps bound the memory any input
// can make the parser use: with the defaults, the worst case — an object at
// both caps — peaks at about 150 MB, and at most one object is parsed at a time.
type ParseOptions struct {
	// MaxObjectBytes caps the source of one object, counted from its first
	// attribute line, and — separately — the run of blank, comment and malformed
	// lines before it. Zero means DefaultMaxObjectBytes; a negative value means
	// unlimited. An object over the cap yields a single Error diagnostic
	// ("rpsl/object-too-large") on an empty object and parsing resumes at the
	// next blank line; trivia over the cap is discarded with one Warning
	// ("rpsl/trivia-too-large") on the object that follows. An over-long line is
	// discarded as it streams: inside an object it makes the object too large;
	// outside one only that line is dropped (a whitespace-only one still
	// separates objects).
	MaxObjectBytes int64

	// MaxObjectLines caps the lines of one object, and separately of the trivia
	// before it, like MaxObjectBytes. Zero means DefaultMaxObjectLines; a
	// negative value means unlimited.
	MaxObjectLines int

	// NonUTF8AsWindows1252 reads each line that is not valid UTF-8 as
	// Windows-1252, which has every printable character of the Latin-1
	// (ISO-8859-1) that registries wrote before UTF-8, and keeps it transcoded
	// to UTF-8; a UTF-8 line is kept as it is. Every line is judged on its own,
	// as some dumps mix both (LACNIC's). Bytes 0x80-0x9F, Latin-1's C1
	// controls, are Windows-1252's quotes, dashes and the like (LACNIC writes
	// 0x96 for an en dash); the five it leaves undefined read as the C1
	// controls of the same number. Each object holding such a line — in its
	// trivia too — carries one Warning ("rpsl/not-utf8") counting them, at the
	// first. Objects hold, and String() returns, the text as transcoded: the
	// stream is lossless with respect to it, not to the input's bytes. Line
	// numbers are the input's; byte offsets, and the caps, count the text as
	// transcoded, except that a line over MaxObjectBytes as read, discarded
	// unread, counts as read. ParseObject takes no options: parse one object's
	// text with ParseWith(strings.NewReader(text), …) to read it so.
	NonUTF8AsWindows1252 bool
}

func (o ParseOptions) maxObjectLines() int {
	if o.MaxObjectLines == 0 {
		return DefaultMaxObjectLines
	}
	return o.MaxObjectLines
}

func (o ParseOptions) maxObjectBytes() int64 {
	if o.MaxObjectBytes == 0 {
		return DefaultMaxObjectBytes
	}
	return o.MaxObjectBytes
}

// Parse lazily parses a stream of blank-line-separated objects (IRR dumps,
// whois output), yielding one object at a time; see ParseWith. It applies
// DefaultMaxObjectBytes.
func Parse(r io.Reader) iter.Seq2[*ast.Object, []Diagnostic] {
	return ParseWith(r, ParseOptions{})
}

// ParseWith lazily parses a stream of blank-line-separated objects, holding at
// most one finished object and the one in progress in memory, so multi-gigabyte
// dumps stream rather than load wholesale.
//
// The stream is lossless: each object owns the blank, comment and malformed
// lines that precede its first attribute, and the last object also owns the
// trailing ones, so concatenating every yielded object's String() reproduces the
// input exactly. Input with no attributes at all yields a single object whose
// Class() is "". The only exceptions are those diagnosed: capped objects and
// trivia (see ParseOptions) and a read error.
//
// Positions in yielded objects and diagnostics — including those Decode later
// derives from attribute spans — are relative to the stream, not the object.
//
// A read error other than io.EOF ends the stream: the object in progress (or an
// empty object) is yielded with an Error diagnostic "rpsl/read-error", so a
// truncated or corrupt dump is never mistaken for a complete one.
//
// The iterator reads r once: ranging over it again after a break continues
// with the next object, like a bufio.Scanner, and once r is exhausted further
// ranges yield nothing. It must not be ranged over concurrently, nor again
// from inside its own loop: that panics, since the two loops would share one
// reader and each end the other.
func ParseWith(r io.Reader, opts ParseOptions) iter.Seq2[*ast.Object, []Diagnostic] {
	limit := opts.maxObjectBytes()
	lr := newLineReader(r, limit)
	lr.cp1252 = opts.NonUTF8AsWindows1252
	s := &streamer{lr: lr, limit: limit, maxLines: opts.maxObjectLines()}
	return func(yield func(*ast.Object, []Diagnostic) bool) {
		if s.ranging {
			panic("rpsl: ParseWith iterator ranged over while it is already running")
		}
		s.ranging = true
		defer func() { s.ranging = false }()
		s.yield, s.stopped = yield, false
		s.run()
	}
}

// pos is a stream position: a 1-based line and a 0-based byte offset.
type pos struct{ line, byte int }

func (p pos) span() lexer.Span {
	return lexer.Span{StartLine: p.line, StartCol: 1, EndLine: p.line, EndCol: 1, StartByte: p.byte, EndByte: p.byte}
}

// chunk is a finished object's source awaiting emission; empty chunks carry
// only diagnostics (a skipped object, a read error) and yield an empty object.
// The source comes in parts, each at its own stream position: a discarded line
// leaves a gap between the trivia before and after it.
type chunk struct {
	parts   []part
	diags   []Diagnostic
	empty   bool
	recoded *recoded // lines read as Windows-1252, for one Warning when yielded; nil for none
}

// recoded counts the lines of a chunk read as Windows-1252. It is held apart,
// and only when there are some, to keep a chunk small.
type recoded struct {
	n  int
	at pos // where the first began
}

// part is a run of consecutive source lines starting at at.
type part struct {
	text string
	at   pos
}

// streamer splits the line stream into objects. A finished object is held as
// pending until the next object starts or the input ends, because trailing
// trivia at end of input belongs to it.
type streamer struct {
	lr       *lineReader
	limit    int64
	maxLines int
	yield    func(*ast.Object, []Diagnostic) bool
	stopped  bool // the consumer broke out of the current range
	done     bool // the input is exhausted and finished

	out     []*chunk // finished chunks not yet yielded, in order
	pending *chunk

	lead      []byte // trivia before the next object's first attribute, since the last gap
	leadStart pos
	leadParts []part // trivia before a discarded line
	leadBytes int    // trivia bytes in lead and leadParts, for the cap
	leadLines int
	leadOver  bool   // this trivia run exceeded the cap and was discarded
	obj       []byte // the current object, from its first attribute line
	objLines  int
	objStart  pos
	inObj     bool
	dropping  bool         // skipping an oversized object up to the next blank line
	carry     []Diagnostic // diagnostics for the object that follows
	ranging   bool         // a range over the iterator is in progress
	discards  int          // over-long lines discarded since carry was last taken
	lastDrop  pos          // where the last of them began
	recoded   int          // lines read as Windows-1252 kept since the last take
	recodedAt pos          // where the first of them began
}

// run yields queued chunks, then reads and yields until the input is exhausted
// or the consumer stops; state survives between runs, so a later range resumes.
func (s *streamer) run() {
	s.drain()
	for !s.stopped && !s.done {
		li, err := s.lr.next()
		if len(li.text) > 0 || li.tooLong {
			s.line(li)
		}
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			s.finish(err)
			s.done = true
		}
		s.drain()
	}
}

// drain yields queued chunks until the queue is empty or the consumer stops.
func (s *streamer) drain() {
	n := 0
	for n < len(s.out) && !s.stopped {
		c := s.out[n]
		s.out[n] = nil
		n++
		var obj *ast.Object
		diags := c.diags
		if c.recoded != nil {
			diags = append(diags, c.recodedWarning()...)
		}
		if c.empty {
			obj = &ast.Object{}
		} else {
			var toks []lexer.Token
			if len(c.parts) == 1 { // the usual case: tokens used as they come
				toks = lexer.TokenizeAt(c.parts[0].text, c.parts[0].at.line, c.parts[0].at.byte)
			} else {
				for _, p := range c.parts {
					toks = append(toks, lexer.TokenizeAt(p.text, p.at.line, p.at.byte)...)
				}
			}
			obj = ast.New(toks)
			diags = append(diags, diagnose(toks)...)
		}
		if !s.yield(obj, diags) {
			s.stopped = true
		}
	}
	// What was not yielded stays queued, at the front, for a later range; the
	// array is kept for the chunks to come.
	m := copy(s.out, s.out[n:])
	clear(s.out[m:])
	s.out = s.out[:m]
}

func (s *streamer) line(li lineInfo) {
	switch {
	case li.blank || (!li.tooLong && lexer.IsBlankLine(text(li.text))):
		if s.dropping {
			s.dropping = false // the skipped object ends here
		} else if s.inObj {
			c := s.takeCurrent()
			s.emitPending()
			s.pending = c
		}
		if li.tooLong {
			s.discardLine(li.at)
		} else {
			s.addLead(li.text, li.at)
		}
	case s.dropping:
		// inside an oversized object: discard until the next blank line
	case s.inObj:
		if li.tooLong || s.over(len(s.obj), len(li.text)) || s.overLines(s.objLines+1) {
			s.oversize(s.objStart)
			return
		}
		s.obj = appendDoubling(s.obj, li.text)
		s.objLines++
		s.noteRecoded(li)
	case li.tooLong && li.attr:
		s.oversize(li.at) // an object whose first line alone is too long
	case li.tooLong:
		s.discardLine(li.at) // an over-long comment or malformed line: drop only it
	case lexer.StartsAttribute(text(li.text)):
		// Nothing after this line can join the finished object any more, so it
		// goes now rather than when this object ends.
		s.emitPending()
		s.inObj, s.objStart, s.objLines = true, li.at, 1
		s.obj = append(s.obj[:0], li.text...)
		s.noteRecoded(li)
	default:
		if s.addLead(li.text, li.at) {
			s.noteRecoded(li)
		}
	}
}

// noteRecoded counts a kept line that was read as Windows-1252 toward the
// Warning of the object it goes with.
func (s *streamer) noteRecoded(li lineInfo) {
	if !li.recoded {
		return
	}
	if s.recoded == 0 {
		s.recodedAt = li.at
	}
	s.recoded++
}

// takeRecoded adds the lines read as Windows-1252 since the last take to c,
// which may hold some already (an object, then its trailing trivia), and
// resets the count.
func (s *streamer) takeRecoded(c *chunk) {
	if s.recoded == 0 {
		return
	}
	if c.recoded == nil {
		c.recoded = &recoded{at: s.recodedAt}
	}
	c.recoded.n += s.recoded
	s.recoded = 0
}

// recodedWarning is c's one Warning for the lines it holds that were read as
// Windows-1252, if any.
func (c *chunk) recodedWarning() []Diagnostic {
	if c.recoded == nil {
		return nil
	}
	msg := "1 line is not UTF-8 and was read as Windows-1252"
	if c.recoded.n > 1 {
		msg = fmt.Sprintf("%d lines are not UTF-8 and were read as Windows-1252, the first here", c.recoded.n)
	}
	return []Diagnostic{{Severity: Warning, Message: msg, Span: c.recoded.at.span(), Rule: "rpsl/not-utf8"}}
}

func (s *streamer) over(have, add int) bool { return s.limit >= 0 && int64(have+add) > s.limit }

func (s *streamer) overLines(n int) bool { return s.maxLines >= 0 && n > s.maxLines }

// discardLine reports an over-long line outside any object, whose bytes the
// line reader has already dropped, on the object that follows. The trivia
// buffered so far is set aside as a part, so what follows keeps its position.
func (s *streamer) discardLine(at pos) {
	if len(s.lead) > 0 {
		s.leadParts = append(s.leadParts, part{string(s.lead), s.leadStart})
		s.lead = s.lead[:0]
	}
	// Only the first line of a run gets its own Warning; takeCarry sums up the
	// rest, so a run of any length costs two diagnostics.
	s.lastDrop = at
	if s.discards++; s.discards > 1 {
		return
	}
	s.carry = append(s.carry, Diagnostic{
		Severity: Warning,
		Message:  fmt.Sprintf("a line longer than MaxObjectBytes (%d) outside any object was discarded", s.limit),
		Span:     at.span(),
		Rule:     "rpsl/trivia-too-large",
	})
}

// takeCarry returns the diagnostics for the object that follows, with a
// summary of the over-long lines discardLine did not report one by one, and
// resets them.
func (s *streamer) takeCarry() []Diagnostic {
	d := s.carry
	if s.discards > 1 {
		d = append(d, Diagnostic{
			Severity: Warning,
			Message: fmt.Sprintf("%d more lines longer than MaxObjectBytes (%d) outside any object were discarded",
				s.discards-1, s.limit),
			Span: s.lastDrop.span(),
			Rule: "rpsl/trivia-too-large",
		})
	}
	s.carry, s.discards = nil, 0
	return d
}

// addLead buffers a trivia line for the next object, discarding the whole run
// (with one Warning) once it exceeds the cap. It reports whether it kept b.
func (s *streamer) addLead(b []byte, at pos) bool {
	if s.leadOver {
		return false
	}
	if len(s.lead) == 0 {
		s.leadStart = at
	}
	if s.over(s.leadBytes, len(b)) || s.overLines(s.leadLines+1) {
		s.leadOver = true
		s.lead, s.leadParts, s.leadBytes, s.leadLines = s.lead[:0], nil, 0, 0
		s.recoded = 0 // the trivia counted is gone with the run
		s.carry = append(s.carry, Diagnostic{
			Severity: Warning,
			Message: fmt.Sprintf("blank and comment lines before this object exceed MaxObjectBytes (%d) or MaxObjectLines (%d) and were discarded",
				s.limit, s.maxLines),
			Span: s.leadStart.span(),
			Rule: "rpsl/trivia-too-large",
		})
		return false
	}
	s.lead = appendDoubling(s.lead, b)
	s.leadBytes += len(b)
	s.leadLines++
	return true
}

// takeLead returns the buffered trivia as parts, and resets it.
func (s *streamer) takeLead() []part {
	parts := s.leadParts
	if len(s.lead) > 0 {
		parts = append(parts, part{string(s.lead), s.leadStart})
	}
	s.lead, s.leadParts, s.leadBytes, s.leadLines = s.lead[:0], nil, 0, 0
	return parts
}

// takeCurrent packages the buffered trivia and object as a chunk and resets.
// Trivia that runs straight into the object, as the blank line before one
// does, goes with it as one part, tokenized at once.
func (s *streamer) takeCurrent() *chunk {
	var parts []part
	if len(s.leadParts) == 0 && len(s.lead) > 0 && s.leadStart.byte+len(s.lead) == s.objStart.byte {
		var b strings.Builder
		b.Grow(len(s.lead) + len(s.obj))
		b.Write(s.lead)
		b.Write(s.obj)
		parts = []part{{b.String(), s.leadStart}}
		s.takeLead()
	} else {
		parts = append(s.takeLead(), part{string(s.obj), s.objStart})
	}
	c := &chunk{parts: parts, diags: s.takeCarry()}
	s.takeRecoded(c)
	s.obj, s.objLines = s.obj[:0], 0
	s.leadOver, s.inObj = false, false
	return c
}

func (s *streamer) emitPending() {
	if s.pending == nil {
		return
	}
	c := s.pending
	s.pending = nil
	s.emit(c)
}

// emit queues a finished chunk for yielding.
func (s *streamer) emit(c *chunk) { s.out = append(s.out, c) }

// emitEmpty queues an empty object carrying diags.
func (s *streamer) emitEmpty(diags []Diagnostic) {
	s.out = append(s.out, &chunk{diags: diags, empty: true})
}

// oversize reports the object starting at at as too large and skips it.
func (s *streamer) oversize(at pos) {
	s.emitPending()
	diags := append(s.takeCarry(), Diagnostic{
		Severity: Error,
		Message: fmt.Sprintf("object exceeds MaxObjectBytes (%d) or MaxObjectLines (%d); skipped to the next blank line",
			s.limit, s.maxLines),
		Span: at.span(),
		Rule: "rpsl/object-too-large",
	})
	s.takeLead()
	s.recoded = 0 // the object and its trivia are dropped
	s.obj, s.objLines = s.obj[:0], 0
	s.leadOver, s.inObj = false, false
	s.dropping = true
	s.emitEmpty(diags)
}

// finish emits what remains at end of input (err == nil) or after a read error.
func (s *streamer) finish(err error) {
	var readErr []Diagnostic
	if err != nil {
		readErr = []Diagnostic{{
			Severity: Error,
			Message:  "read error: " + err.Error(),
			Span:     s.lr.pos.span(),
			Rule:     "rpsl/read-error",
		}}
	}
	switch {
	case s.inObj:
		c := s.takeCurrent()
		s.emitPending()
		c.diags = append(c.diags, readErr...)
		s.emit(c)
		return
	case s.dropping:
		s.emitPending()
	case s.pending != nil: // trailing trivia belongs to the last object
		s.pending.parts = append(s.pending.parts, s.takeLead()...)
		s.pending.diags = append(s.pending.diags, s.takeCarry()...)
		s.takeRecoded(s.pending)
		s.emitPending()
	case len(s.lead) > 0 || len(s.leadParts) > 0 || len(s.carry) > 0: // no attributes anywhere
		c := &chunk{parts: s.takeLead(), diags: s.takeCarry()}
		s.takeRecoded(c)
		s.emit(c)
	}
	if readErr != nil {
		s.emitEmpty(readErr)
	}
}

// lineReader reads physical lines, keeping each at most limit bytes long: a
// longer line is consumed but not retained, so it cannot exhaust memory.
type lineReader struct {
	br     *bufio.Reader
	limit  int64
	buf    []byte
	pos    pos    // position of the next line
	cp1252 bool   // read a line that is not UTF-8 as Windows-1252
	out    []byte // the line in buf as Windows-1252, never over limit bytes
}

// lineInfo is one physical line. A line longer than the limit is consumed but
// not kept: it is reported with tooLong, described by its first bytes (enough
// to classify it) and whether it held only whitespace.
type lineInfo struct {
	text    []byte // the line with its terminator; empty when tooLong
	at      pos
	tooLong bool
	blank   bool // tooLong: only spaces, tabs and line terminators
	attr    bool // tooLong: the whole line starts an attribute (lexer.StartsAttribute)
	recoded bool // the line was not UTF-8 and was read as Windows-1252
}

func newLineReader(r io.Reader, limit int64) *lineReader {
	return &lineReader{br: bufio.NewReaderSize(r, 64<<10), limit: limit, pos: pos{line: 1}}
}

// next returns the next line and any read error. The returned slices are only
// valid until the next call.
func (r *lineReader) next() (lineInfo, error) {
	li := lineInfo{at: r.pos}
	r.buf = r.buf[:0]
	n := 0
	d := lineDesc{blank: true} // fed only once the line is over the cap
	for {
		frag, e := r.br.ReadSlice('\n')
		n += len(frag)
		final := e != bufio.ErrBufferFull
		if !li.tooLong && r.limit >= 0 && int64(len(r.buf)+len(frag)) > r.limit {
			li.tooLong = true
			d.add(r.buf, false) // what was kept so far, then the rest as it comes
			r.buf = r.buf[:0]
		}
		if li.tooLong {
			d.add(frag, final)
		} else {
			r.buf = appendDoubling(r.buf, frag)
		}
		if !final {
			continue
		}
		// Judged whole, so a character split between two reads is UTF-8.
		if r.cp1252 && !li.tooLong && !utf8.Valid(r.buf) {
			if n = r.recode(&li); li.tooLong {
				d.add(r.buf, true) // over the cap transcoded: described as read
			}
		}
		r.pos.byte += n
		if e == nil {
			r.pos.line++
		}
		if li.tooLong {
			li.blank, li.attr = d.blank, d.attr.attr
		} else if li.recoded {
			li.text = r.out
		} else {
			li.text = r.buf
		}
		return li, e
	}
}

// recode reads the line in r.buf as Windows-1252 into r.out, marking li
// recoded, or too long if it is over the cap as held, and returns its length.
// The length is measured first: a line over the cap, which may be three times
// its bytes, is not built, and r.out never grows past the cap.
func (r *lineReader) recode(li *lineInfo) int {
	n := windows1252Len(r.buf)
	if r.limit >= 0 && int64(n) > r.limit {
		li.tooLong = true // over the cap as held: discarded, not recoded
		return n
	}
	if n > cap(r.out) {
		r.out = make([]byte, 0, n)
	}
	r.out = appendWindows1252(r.out[:0], r.buf)
	li.recoded = true
	return n
}

// lineDesc describes a line over the cap, which is not kept, from its
// fragments as they are read: whether it is blank and whether it starts an
// attribute. Lines within the cap are kept and need no description.
type lineDesc struct {
	attr   attrScan
	blank  bool // only spaces, tabs and line terminators so far
	heldCR bool // a '\r' ended the previous fragment: a terminator only if "\n" or EOF follows
	seen   int  // bytes described
}

// add describes the next fragment of the line; final marks its last.
func (d *lineDesc) add(frag []byte, final bool) {
	d.attr.scan(frag, d.seen == 0)
	d.seen += len(frag)
	if d.heldCR && !(final && (len(frag) == 0 || len(frag) == 1 && frag[0] == '\n')) {
		d.blank = false // the held '\r' was inside the line, where it is not blank
	}
	body := frag
	if final {
		body = text(frag)
	} else if d.heldCR = len(frag) > 0 && frag[len(frag)-1] == '\r'; d.heldCR {
		body = frag[:len(frag)-1]
	}
	d.blank = d.blank && lexer.IsBlankLine(body)
}

// attrScan decides lexer.StartsAttribute for a line read in fragments, so an
// over-long line is classified by all of it without being kept: the first byte
// may not be a space, tab, '+' or '#', and a ':' must come before any '#'.
type attrScan struct{ decided, attr bool }

func (a *attrScan) scan(frag []byte, first bool) {
	if a.decided || len(frag) == 0 {
		return
	}
	if first {
		switch frag[0] {
		case ' ', '\t', '+', '#':
			a.decided = true
			return
		}
	}
	if i := bytes.IndexAny(frag, ":#"); i >= 0 {
		a.decided, a.attr = true, frag[i] == ':'
	}
}

// appendDoubling is append that doubles a full buffer's capacity. Plain append
// grows large slices by only about 1.25x, so accumulating a 16 MiB object would
// allocate about 5x its size in discarded copies; doubling keeps it under 2x.
func appendDoubling(buf, b []byte) []byte {
	if need := len(buf) + len(b); need > cap(buf) {
		grown := make([]byte, len(buf), max(2*cap(buf), need))
		copy(grown, buf)
		buf = grown
	}
	return append(buf, b...)
}

// text returns a physical line without its terminator: "\n", "\r\n", or the
// "\r" that ends the input, as the lexer strips them.
func text(line []byte) []byte {
	line = bytes.TrimSuffix(line, []byte("\n"))
	return bytes.TrimSuffix(line, []byte("\r"))
}

// windows1252 holds the characters Windows-1252 gives the bytes 0x80-0x9F; the
// five it leaves undefined are the C1 controls of the same number. From 0xA0
// it is Latin-1: each byte is the code point of its value.
var windows1252 = [32]rune{
	'\u20AC', '\u0081', '\u201A', '\u0192', '\u201E', '\u2026', '\u2020', '\u2021',
	'\u02C6', '\u2030', '\u0160', '\u2039', '\u0152', '\u008D', '\u017D', '\u008F',
	'\u0090', '\u2018', '\u2019', '\u201C', '\u201D', '\u2022', '\u2013', '\u2014',
	'\u02DC', '\u2122', '\u0161', '\u203A', '\u0153', '\u009D', '\u017E', '\u0178',
}

// windows1252Len is the length of b read as Windows-1252, in UTF-8.
func windows1252Len(b []byte) int {
	n := 0
	for _, c := range b {
		switch {
		case c < 0x80:
			n++
		case c < 0xA0:
			n += utf8.RuneLen(windows1252[c-0x80])
		default:
			n += 2
		}
	}
	return n
}

// appendWindows1252 appends b, read as Windows-1252, to dst as UTF-8.
func appendWindows1252(dst, b []byte) []byte {
	for _, c := range b {
		switch {
		case c < 0x80:
			dst = append(dst, c)
		case c < 0xA0:
			dst = utf8.AppendRune(dst, windows1252[c-0x80])
		default:
			dst = utf8.AppendRune(dst, rune(c))
		}
	}
	return dst
}
