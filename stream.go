package rpsl

import (
	"bufio"
	"fmt"
	"io"
	"iter"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/lexer"
)

// DefaultMaxObjectBytes is the cap on a single object's source applied by Parse
// and by a zero ParseOptions.MaxObjectBytes. Real RPSL objects are far smaller
// (the largest as-sets are a few MB); the cap exists to bound memory on hostile
// input.
const DefaultMaxObjectBytes = 64 << 20

// ParseOptions tunes the streaming parser.
type ParseOptions struct {
	// MaxObjectBytes caps the source of one object, counted from its first
	// attribute line, and — separately — the run of blank, comment and malformed
	// lines before it. Zero means DefaultMaxObjectBytes; a negative value means
	// unlimited. An object over the cap yields a single Error diagnostic
	// ("rpsl/object-too-large") on an empty object and parsing resumes at the
	// next blank line; trivia over the cap is discarded with one Warning
	// ("rpsl/trivia-too-large") on the object that follows. Over-long lines are
	// discarded as they stream, so memory stays within a small multiple of the cap.
	MaxObjectBytes int64
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
func ParseWith(r io.Reader, opts ParseOptions) iter.Seq2[*ast.Object, []Diagnostic] {
	return func(yield func(*ast.Object, []Diagnostic) bool) {
		limit := opts.maxObjectBytes()
		s := &streamer{lr: newLineReader(r, limit), limit: limit, yield: yield}
		s.run()
	}
}

// pos is a stream position: a 1-based line and a 0-based byte offset.
type pos struct{ line, byte int }

func (p pos) span() lexer.Span {
	return lexer.Span{StartLine: p.line, StartCol: 1, EndLine: p.line, EndCol: 1, StartByte: p.byte, EndByte: p.byte}
}

// chunk is a finished object's source awaiting emission.
type chunk struct {
	text  string
	start pos
	diags []Diagnostic
}

// streamer splits the line stream into objects. A finished object is held as
// pending until the next object starts or the input ends, because trailing
// trivia at end of input belongs to it.
type streamer struct {
	lr      *lineReader
	limit   int64
	yield   func(*ast.Object, []Diagnostic) bool
	stopped bool

	pending *chunk

	lead      []byte // trivia before the next object's first attribute
	leadStart pos
	leadOver  bool   // this trivia run exceeded the cap and was discarded
	obj       []byte // the current object, from its first attribute line
	objStart  pos
	inObj     bool
	dropping  bool         // skipping an oversized object up to the next blank line
	carry     []Diagnostic // diagnostics for the object that follows
}

func (s *streamer) run() {
	for !s.stopped {
		line, at, tooLong, err := s.lr.next()
		if len(line) > 0 || tooLong {
			s.line(line, at, tooLong)
		}
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			s.finish(err)
			return
		}
	}
}

func (s *streamer) line(b []byte, at pos, tooLong bool) {
	switch {
	case !tooLong && isBlank(b):
		if s.dropping {
			s.dropping = false // the skipped object ends here
		} else if s.inObj {
			c := s.takeCurrent()
			s.emitPending()
			s.pending = c
		}
		s.addLead(b, at)
	case s.dropping:
		// inside an oversized object: discard until the next blank line
	case s.inObj:
		if tooLong || s.over(len(s.obj), len(b)) {
			s.oversize(s.objStart)
			return
		}
		s.obj = append(s.obj, b...)
	case tooLong:
		s.oversize(at) // too long to be trivia or to start an object
	case isAttrStart(b):
		s.inObj, s.objStart = true, at
		s.obj = append(s.obj[:0], b...)
	default:
		s.addLead(b, at)
	}
}

func (s *streamer) over(have, add int) bool { return s.limit >= 0 && int64(have+add) > s.limit }

// addLead buffers a trivia line for the next object, discarding the whole run
// (with one Warning) once it exceeds the cap.
func (s *streamer) addLead(b []byte, at pos) {
	if s.leadOver {
		return
	}
	if len(s.lead) == 0 {
		s.leadStart = at
	}
	if s.over(len(s.lead), len(b)) {
		s.leadOver = true
		s.lead = s.lead[:0]
		s.carry = append(s.carry, Diagnostic{
			Severity: Warning,
			Message:  fmt.Sprintf("blank and comment lines before this object exceed MaxObjectBytes (%d) and were discarded", s.limit),
			Span:     s.leadStart.span(),
			Rule:     "rpsl/trivia-too-large",
		})
		return
	}
	s.lead = append(s.lead, b...)
}

// takeCurrent packages the buffered trivia and object as a chunk and resets.
func (s *streamer) takeCurrent() *chunk {
	c := &chunk{start: s.objStart, diags: s.carry}
	if len(s.lead) > 0 {
		c.start = s.leadStart
	}
	buf := make([]byte, 0, len(s.lead)+len(s.obj))
	c.text = string(append(append(buf, s.lead...), s.obj...))
	s.lead, s.obj = s.lead[:0], s.obj[:0]
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

func (s *streamer) emit(c *chunk) {
	if s.stopped {
		return
	}
	obj, diags := parseObjectAt(c.text, c.start.line, c.start.byte)
	if !s.yield(obj, append(c.diags, diags...)) {
		s.stopped = true
	}
}

func (s *streamer) emitEmpty(diags []Diagnostic) {
	if !s.stopped && !s.yield(&ast.Object{}, diags) {
		s.stopped = true
	}
}

// oversize reports the object starting at at as too large and skips it.
func (s *streamer) oversize(at pos) {
	s.emitPending()
	diags := append(s.carry, Diagnostic{
		Severity: Error,
		Message:  fmt.Sprintf("object exceeds MaxObjectBytes (%d); skipped to the next blank line", s.limit),
		Span:     at.span(),
		Rule:     "rpsl/object-too-large",
	})
	s.lead, s.obj = s.lead[:0], s.obj[:0]
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
		s.pending.text += string(s.lead)
		s.pending.diags = append(s.pending.diags, s.carry...)
		s.emitPending()
	case len(s.lead) > 0 || len(s.carry) > 0: // no attributes anywhere
		s.emit(&chunk{text: string(s.lead), start: s.leadStart, diags: s.carry})
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

func newLineReader(r io.Reader, limit int64) *lineReader {
	return &lineReader{br: bufio.NewReaderSize(r, 64<<10), limit: limit, pos: pos{line: 1}}
}

// next returns the next line with its terminator, its stream position, whether
// it exceeded the limit (its bytes are then dropped), and any read error. The
// returned slice is only valid until the next call.
func (r *lineReader) next() (line []byte, at pos, tooLong bool, err error) {
	at = r.pos
	r.buf = r.buf[:0]
	n := 0
	for {
		frag, e := r.br.ReadSlice('\n')
		n += len(frag)
		if !tooLong {
			if r.limit >= 0 && int64(len(r.buf)+len(frag)) > r.limit {
				tooLong, r.buf = true, r.buf[:0]
			} else {
				r.buf = append(r.buf, frag...)
			}
		}
		if e == bufio.ErrBufferFull {
			continue
		}
		r.pos.byte += n
		if e == nil {
			r.pos.line++
		}
		return r.buf, at, tooLong, e
	}
}

// isBlank mirrors the lexer: a line that is empty or only spaces and tabs,
// ignoring its terminator ("\n", "\r\n", or a final "\r").
func isBlank(b []byte) bool {
	for _, c := range b {
		if c != ' ' && c != '\t' && c != '\r' && c != '\n' {
			return false
		}
	}
	return true
}

// isAttrStart mirrors the lexer: a line that begins an attribute ("name: …").
func isAttrStart(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	switch b[0] {
	case ' ', '\t', '+', '#', '\r', '\n':
		return false
	}
	for _, c := range b {
		switch c {
		case ':':
			return true
		case '#', '\n':
			return false
		}
	}
	return false
}
