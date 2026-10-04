package irrdq

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/resolve/internal/irrdoracle"
)

// fuzzMaxReply is the reply limit FuzzSession applies as irrdserver applies
// MaxReply, small enough that most data answers go over it.
const fuzzMaxReply = 64

// FuzzSession: any command lines, through one session over the fixture, in
// IRRd and RFC mode: no panic, and every reply is well formed — an A-frame's
// length is its payload's, any other reply one of C, D, E, an F line, or a
// RIPE-style answer ending in two blank lines — and a reply over a limit,
// refused as a server refuses it, is one F line that closes the connection
// exactly when the reply would have.
func FuzzSession(f *testing.F) {
	for _, c := range irrdoracle.Cases() {
		f.Add(c.Send)
	}
	snaps := map[bool]*Snapshot{}
	f.Fuzz(func(t *testing.T, send string) {
		for _, rfc := range []bool{false, true} {
			if snaps[rfc] == nil {
				snaps[rfc] = fixture(t, SnapshotOptions{RFC: rfc})
			}
			snap := snaps[rfc]
			s := NewSession(func() *Snapshot { return snap })
			for _, line := range strings.Split(send, "\n") {
				r, err := s.Do(context.Background(), line)
				if err != nil {
					t.Fatalf("Do(%q): %v", line, err)
				}
				var b strings.Builder
				if n, _ := r.WriteTo(&b); int(n) != r.Len() {
					t.Fatalf("%q: WriteTo wrote %d bytes, Len is %d", line, n, r.Len())
				}
				checkReply(t, line, b.String())
				if r.Len() > fuzzMaxReply {
					rf := r.Refused("Answer larger than " + strconv.Itoa(fuzzMaxReply) + " bytes")
					var fb strings.Builder
					rf.WriteTo(&fb)
					if !strings.HasPrefix(fb.String(), "F ") || rf.Close() != r.Close() {
						t.Fatalf("%q: refused as %q (close %v), the reply closing %v", line, fb.String(), rf.Close(), r.Close())
					}
					checkReply(t, line, fb.String())
				}
				if r.Close() {
					break
				}
			}
		}
	})
}

// checkReply fails unless out is one well-formed reply to line.
func checkReply(t *testing.T, line, out string) {
	t.Helper()
	switch {
	case out == "", out == "C\n", out == "D\n", out == "E\n":
	case strings.HasPrefix(out, "F "):
		if strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") {
			t.Fatalf("%q: a broken F line %q", line, out)
		}
	case strings.HasPrefix(out, "A"):
		nl := strings.IndexByte(out, '\n')
		if nl < 0 {
			t.Fatalf("%q: a frame without its length line %q", line, out)
		}
		n, err := strconv.Atoi(out[1:nl])
		if err != nil || len(out) != nl+1+n+2 || !strings.HasSuffix(out, "\nC\n") {
			t.Fatalf("%q: a broken frame %q", line, out)
		}
	default:
		if !strings.HasSuffix(out, "\n\n\n") {
			t.Fatalf("%q: a RIPE-style answer without its ending: %q", line, out)
		}
	}
}
