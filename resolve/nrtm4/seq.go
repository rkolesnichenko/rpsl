package nrtm4

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/types"
)

// rs starts every record of a JSON text sequence (RFC 7464 §2).
const rs = 0x1E

// seqReader reads the records of a JSON text sequence, each at most max
// bytes. A record is the text between one RS and the next, white space
// trimmed; an empty one is skipped, and anything but white space before the
// first RS is an error.
type seqReader struct {
	r     *bufio.Reader
	max   int
	begun bool
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

// until reads up to the next RS, which it consumes, or to the end.
func (s *seqReader) until() ([]byte, error) {
	var out []byte
	for {
		chunk, err := s.r.ReadSlice(rs)
		if len(out)+len(chunk) > s.max+1 {
			return nil, fmt.Errorf("a record longer than %d bytes", s.max)
		}
		out = append(out, chunk...)
		switch err {
		case nil:
			return out[:len(out)-1], nil
		case bufio.ErrBufferFull:
			continue
		default:
			return out, err
		}
	}
}

// key returns the key a mirror stores an object under: its class and its
// primary key (§8.3), canonical, so that a delete matches however either side
// spells it — case, "AS1" or "as1", "2001:DB8::/32" or "2001:db8::/32".
func key(class, pk string) string {
	class = strings.ToLower(strings.TrimSpace(class))
	pk = strings.TrimSpace(pk)
	switch class {
	case "route", "route6":
		// The prefix and the origin run together: "192.0.2.0/24AS64500".
		if i := strings.LastIndex(strings.ToUpper(pk), "AS"); i > 0 {
			p, perr := types.ParsePrefix(pk[:i])
			a, aerr := types.ParseASN(pk[i:])
			if perr == nil && aerr == nil {
				return class + " " + p.Masked().String() + a.String()
			}
		}
	case "aut-num":
		if a, err := types.ParseASN(pk); err == nil {
			return class + " " + a.String()
		}
	case "as-set", "route-set", "rtr-set", "filter-set", "peering-set":
		if n, err := types.ParseSetName(pk); err == nil {
			return class + " " + n.String()
		}
	}
	return class + " " + strings.ToUpper(pk)
}

// objectKey is key for an object's own text: its class, and its class
// attribute's value — for a route or route6, the prefix and the origin.
func objectKey(o *ast.Object) (string, bool) {
	class := o.Class()
	if class == "" {
		return "", false
	}
	pk := o.Key()
	if class == "route" || class == "route6" {
		origin, ok := o.GetFirst("origin")
		if !ok {
			return "", false
		}
		pk = strings.TrimSpace(pk) + strings.TrimSpace(origin.Value)
	}
	return key(class, pk), true
}
