package rpsl

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"iter"

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
// ranges yield nothing. It must not be ranged over concurrently.
func ParseWith(r io.Reader, opts ParseOptions) iter.Seq2[*ast.Object, []Diagnostic] {
	limit := opts.maxObjectBytes()
	s := &streamer{lr: newLineReader(r, limit), limit: limit, maxLines: opts.maxObjectLines()}
	return func(yield func(*ast.Object, []Diagnostic) bool) {
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
	parts []part
	diags []Diagnostic
	empty bool
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
	for len(s.out) > 0 && !s.stopped {
		c := s.out[0]
		s.out[0], s.out = nil, s.out[1:]
		obj, diags := &ast.Object{}, c.diags
		if !c.empty {
			var toks []lexer.Token
			for _, p := range c.parts {
				toks = append(toks, lexer.TokenizeAt(p.text, p.at.line, p.at.byte)...)
			}
			obj = ast.New(toks)
			diags = append(diags, diagnose(toks)...)
		}
		if !s.yield(obj, diags) {
			s.stopped = true
		}
	}
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
	case li.tooLong && li.attr:
		s.oversize(li.at) // an object whose first line alone is too long
	case li.tooLong:
		s.discardLine(li.at) // an over-long comment or malformed line: drop only it
	case lexer.StartsAttribute(text(li.text)):
		s.inObj, s.objStart, s.objLines = true, li.at, 1
		s.obj = append(s.obj[:0], li.text...)
	default:
		s.addLead(li.text, li.at)
	}
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
	s.carry = append(s.carry, Diagnostic{
		Severity: Warning,
		Message:  fmt.Sprintf("a line longer than MaxObjectBytes (%d) outside any object was discarded", s.limit),
		Span:     at.span(),
		Rule:     "rpsl/trivia-too-large",
	})
}

// addLead buffers a trivia line for the next object, discarding the whole run
// (with one Warning) once it exceeds the cap.
func (s *streamer) addLead(b []byte, at pos) {
	if s.leadOver {
		return
	}
	if len(s.lead) == 0 {
		s.leadStart = at
	}
	if s.over(s.leadBytes, len(b)) || s.overLines(s.leadLines+1) {
		s.leadOver = true
		s.lead, s.leadParts, s.leadBytes, s.leadLines = s.lead[:0], nil, 0, 0
		s.carry = append(s.carry, Diagnostic{
			Severity: Warning,
			Message: fmt.Sprintf("blank and comment lines before this object exceed MaxObjectBytes (%d) or MaxObjectLines (%d) and were discarded",
				s.limit, s.maxLines),
			Span: s.leadStart.span(),
			Rule: "rpsl/trivia-too-large",
		})
		return
	}
	s.lead = appendDoubling(s.lead, b)
	s.leadBytes += len(b)
	s.leadLines++
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
func (s *streamer) takeCurrent() *chunk {
	c := &chunk{parts: append(s.takeLead(), part{string(s.obj), s.objStart}), diags: s.carry}
	s.obj, s.objLines = s.obj[:0], 0
	s.leadOver, s.inObj, s.carry = false, false, nil
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
	diags := append(s.carry, Diagnostic{
		Severity: Error,
		Message: fmt.Sprintf("object exceeds MaxObjectBytes (%d) or MaxObjectLines (%d); skipped to the next blank line",
			s.limit, s.maxLines),
		Span: at.span(),
		Rule: "rpsl/object-too-large",
	})
	s.takeLead()
	s.obj, s.objLines = s.obj[:0], 0
	s.leadOver, s.inObj, s.carry = false, false, nil
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
		s.pending.diags = append(s.pending.diags, s.carry...)
		s.emitPending()
	case len(s.lead) > 0 || len(s.leadParts) > 0 || len(s.carry) > 0: // no attributes anywhere
		s.emit(&chunk{parts: s.takeLead(), diags: s.carry})
	}
	if readErr != nil {
		s.emitEmpty(readErr)
	}
}

// lineReader reads physical lines, keeping each at most limit bytes long: a
// longer line is consumed but not retained, so it cannot exhaust memory.
type lineReader struct {
	br    *bufio.Reader
	limit int64
	buf   []byte
	pos   pos // position of the next line
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
}

func newLineReader(r io.Reader, limit int64) *lineReader {
	return &lineReader{br: bufio.NewReaderSize(r, 64<<10), limit: limit, pos: pos{line: 1}}
}

// next returns the next line and any read error. The returned slices are only
// valid until the next call.
func (r *lineReader) next() (lineInfo, error) {
	li := lineInfo{at: r.pos}
	r.buf = r.buf[:0]
	n, blank := 0, true
	var attr attrScan
	for {
		frag, e := r.br.ReadSlice('\n')
		attr.scan(frag, n == 0)
		n += len(frag)
		blank = blank && lexer.IsBlankLine(text(frag))
		if !li.tooLong {
			if r.limit >= 0 && int64(len(r.buf)+len(frag)) > r.limit {
				li.tooLong = true
				r.buf = r.buf[:0]
			} else {
				r.buf = appendDoubling(r.buf, frag)
			}
		}
		if e == bufio.ErrBufferFull {
			continue
		}
		r.pos.byte += n
		if e == nil {
			r.pos.line++
		}
		if li.tooLong {
			li.blank, li.attr = blank, attr.attr
		} else {
			li.text = r.buf
		}
		return li, e
	}
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
