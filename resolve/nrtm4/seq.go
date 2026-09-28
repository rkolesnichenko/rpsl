package nrtm4

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/rkolesnichenko/rpsl/ast"
)

// rs starts every record of a JSON text sequence (RFC 7464 §2).
const rs = 0x1E

// seqReader reads the records of a JSON text sequence, each at most max
// bytes. A record is the text between one RS and the next, white space
// trimmed; an empty one is skipped, and anything but white space before the
// first RS is an error. A record returned is valid until the next call:
// every caller decodes it first.
type seqReader struct {
	r     *bufio.Reader
	max   int
	begun bool
	buf   []byte // a record read in several pieces, reused
}

func newSeqReader(r io.Reader, max int) *seqReader {
	return &seqReader{r: bufio.NewReaderSize(r, 64<<10), max: max}
}

// next returns the next record, or io.EOF after the last.
func (s *seqReader) next() ([]byte, error) {
	for {
		rec, err := s.until()
		if err != nil && err != io.EOF {
			return nil, err
		}
		rec = bytes.TrimSpace(rec)
		if !s.begun {
			// Everything up to the first RS: nothing but white space.
			s.begun = true
			if len(rec) > 0 {
				return nil, errors.New("data before the first record separator")
			}
			if err == io.EOF {
				return nil, io.EOF
			}
			continue
		}
		if len(rec) > 0 {
			return rec, nil
		}
		if err == io.EOF {
			return nil, io.EOF
		}
	}
}

// until reads up to the next RS, which it consumes, or to the end. A record
// in the reader's buffer whole is returned from it, not copied.
func (s *seqReader) until() ([]byte, error) {
	out := s.buf[:0]
	for {
		chunk, err := s.r.ReadSlice(rs)
		if len(out)+len(chunk) > s.max+1 {
			return nil, fmt.Errorf("a record longer than %d bytes", s.max)
		}
		if err == nil && len(out) == 0 {
			return chunk[:len(chunk)-1], nil
		}
		out = append(out, chunk...)
		s.buf = out
		switch err {
		case nil:
			return out[:len(out)-1], nil
		case bufio.ErrBufferFull:
			continue
		default:
			if len(out) > s.max { // the last record: no separator follows it
				return nil, fmt.Errorf("a record longer than %d bytes", s.max)
			}
			return out, err
		}
	}
}

// hasPrimaryKey reports whether an object has what its identity needs: a
// class, a value for it, and for a route or route6 an origin: — the key a
// delete names it by (§8.3). The key itself is resolve.Corpus's to read.
func hasPrimaryKey(o *ast.Object) bool {
	class := o.Class()
	if class == "" || strings.TrimSpace(o.Key()) == "" {
		return false
	}
	if class == "route" || class == "route6" {
		a, ok := o.GetFirst("origin")
		return ok && strings.TrimSpace(a.Value) != ""
	}
	return true
}
