package irrdq

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/rkolesnichenko/rpsl/types"
)

// An answer is a reply being built, with its running length checked
// against the session's byte budget (Session.SetMaxReply). Once it passes
// the budget nothing more is kept and the reply is the refusal, so an
// answer far over the budget is never built, nor copied, only to be thrown
// away. A large piece — a route's text, an object's — is held by reference
// and copied once, into the reply; small pieces (words, separators,
// rpki-ov-state: lines) are packed as they come, so that a list of short
// words costs no more than its own bytes. The reply is written once, into a
// buffer of its exact size.
type answer struct {
	parts []string        // the pieces so far, in order, cur's not included
	cur   strings.Builder // small pieces since the last of parts
	n     int64           // the bytes so far
	max   int64           // 0: no budget
	over  bool            // the pieces passed max; none is kept
}

// smallPiece is the length below which a piece is packed rather than held:
// below it a reference (16 bytes) is not worth keeping.
const smallPiece = 128

// newAnswer starts an answer under the session's budget.
func (s *Session) newAnswer() *answer { return &answer{max: s.maxReply} }

// add appends pieces; false once the answer is over its budget, after which
// nothing more is kept.
func (a *answer) add(pieces ...string) bool {
	n := 0
	for _, p := range pieces {
		n += len(p)
	}
	if !a.grow(n) {
		return false
	}
	for _, p := range pieces {
		if len(p) < smallPiece {
			a.cur.WriteString(p)
			continue
		}
		if a.cur.Len() > 0 {
			a.parts = append(a.parts, a.cur.String()) // no copy; Reset starts a new buffer
			a.cur.Reset()
		}
		a.parts = append(a.parts, p)
	}
	return true
}

// grow counts n more bytes; false, and nothing kept from now on, once that
// passes the budget.
func (a *answer) grow(n int) bool {
	if a.over {
		return false
	}
	a.n += int64(n)
	if a.max > 0 && a.n > a.max {
		a.over, a.parts = true, nil
		a.cur.Reset()
		return false
	}
	return true
}

// addAS adds an AS number as RPSL writes it ("AS65001"), without building
// its text apart.
func (a *answer) addAS(as types.ASN) bool {
	var buf [len("AS4294967295")]byte
	b := strconv.AppendUint(append(buf[:0], "AS"...), uint64(as), 10)
	if !a.grow(len(b)) {
		return false
	}
	a.cur.Write(b)
	return true
}

// addPrefix adds a prefix as netip writes it, without building its text
// apart.
func (a *answer) addPrefix(p netip.Prefix) bool {
	var buf [len("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128")]byte
	b := p.AppendTo(buf[:0])
	if !a.grow(len(b)) {
		return false
	}
	a.cur.Write(b)
	return true
}

// writeTo writes the pieces to b, in order.
func (a *answer) writeTo(b *strings.Builder) {
	for _, p := range a.parts {
		b.WriteString(p)
	}
	b.WriteString(a.cur.String())
}

// frame is IRRd's data answer of the pieces — "A<len>", the pieces (the
// last ending in the newline len counts), "C" — or the refusal when that is
// over the budget.
func (a *answer) frame() Reply {
	if a.over {
		return tooLarge(a.max)
	}
	head := "A" + strconv.FormatInt(a.n, 10) + "\n"
	total := int64(len(head)) + a.n + int64(len("C\n"))
	if a.max > 0 && total > a.max {
		return tooLarge(a.max)
	}
	var b strings.Builder
	b.Grow(int(total))
	b.WriteString(head)
	a.writeTo(&b)
	b.WriteString("C\n")
	return Reply{text: b.String()}
}

// plain is the pieces as they stand (a RIPE-style answer), or the refusal.
func (a *answer) plain() Reply {
	if a.over {
		return tooLarge(a.max)
	}
	var b strings.Builder
	b.Grow(int(a.n))
	a.writeTo(&b)
	return Reply{text: b.String()}
}

// words is the data answer listing ws, separated by spaces, or "D" when ws
// is empty.
func (a *answer) words(ws []string) Reply {
	if len(ws) == 0 {
		return notFound
	}
	for i, w := range ws {
		if i > 0 {
			a.add(" ")
		}
		if !a.add(w) {
			break
		}
	}
	a.add("\n")
	return a.frame()
}

// tooLarge is the refusal of an answer over a budget of max bytes.
func tooLarge(max int64) Reply { return Fail(tooLargeMsg(max)) }

// tooLargeMsg is tooLarge's message.
func tooLargeMsg(max int64) string { return fmt.Sprintf("Answer larger than %d bytes", max) }
