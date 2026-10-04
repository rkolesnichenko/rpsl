package irrdq

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rkolesnichenko/rpsl/types"
)

// A Reply is what the server writes for one command, and whether the
// connection closes after it.
type Reply struct {
	text  string
	close bool
	cause error // why an internal error was answered; never sent
}

// WriteTo writes the reply's bytes to w.
func (r Reply) WriteTo(w io.Writer) (int64, error) {
	n, err := io.WriteString(w, r.text)
	return int64(n), err
}

// Close reports whether the connection closes once the reply is written.
func (r Reply) Close() bool { return r.close }

// Len is the number of bytes WriteTo writes.
func (r Reply) Len() int { return len(r.text) }

// Cause is why the reply is IRRd's internal-error answer — a Source's error,
// with the selected registries named — or nil. The client is told only that
// an internal error occurred; Cause is for the server's log.
func (r Reply) Cause() error { return r.cause }

// frame is IRRd's data answer: "A<len>", the payload and a newline (counted
// in len), then "C". It is for small answers; one that can grow large is
// built by an answer, under the session's budget.
func frame(payload string) Reply {
	a := &answer{}
	a.add(payload, "\n")
	return a.frame()
}

var (
	ok       = Reply{text: "C\n"}
	notFound = Reply{text: "D\n"} // IRRd's answer when nothing matches
	nothing  = Reply{}
)

// Fail is IRRd's error answer, "F <msg>".
func Fail(msg string) Reply { return Reply{text: "F " + msg + "\n"} }

// internalErr is IRRd's answer when a query fails for a reason of the
// server's own (a Source's error): the message only, the cause kept beside
// it for the server's log (Cause).
func internalErr(cause error) Reply {
	r := Fail(internalErrorText)
	r.cause = cause
	return r
}

// Refused is IRRd's error answer msg in place of r, closing the connection
// when r would have: what a server sends when it cannot send r itself.
func (r Reply) Refused(msg string) Reply {
	f := Fail(msg)
	f.close = r.close
	return f
}

// A Session is one client connection's state: its selected registries, its
// persistent mode, its timeout. It is not safe for concurrent use: a
// connection's commands are answered one at a time, in order.
type Session struct {
	snapshot   func() *Snapshot
	sel        []string // nil: the snapshot's default
	persistent bool
	timeout    time.Duration
	maxReply   int64 // 0: no budget
}

// NewSession starts a session that reads the current snapshot from snapshot,
// once per command.
func NewSession(snapshot func() *Snapshot) *Session { return &Session{snapshot: snapshot} }

// Timeout is what "!t" set, or 0.
func (s *Session) Timeout() time.Duration { return s.timeout }

// SetMaxReply sets the session's byte budget: a reply longer than n bytes is
// "F Answer larger than <n> bytes" instead, and an answer that can grow large
// (route objects, a list of origins, prefixes or members, RIPE-style
// objects) stops being built as soon as it passes n, so a far larger answer
// costs no more memory than n. n <= 0 removes the budget (the default).
func (s *Session) SetMaxReply(n int64) { s.maxReply = max(n, 0) }

// sources is the session's selected registry names.
func (s *Session) sources(snap *Snapshot) []string {
	if s.sel != nil {
		return s.sel
	}
	return snap.dflt
}

// Do answers one command line (its "\n" already cut). The line is stripped
// first, as IRRd strips it (irrd/server/whois/server.py: Python's
// str.strip(), so a "\r", tabs and spaces at either end go, and so do the
// separators U+001C-U+001F); a blank line is no command and reads no
// snapshot. Without "!!" the connection closes after the first command;
// "!q" closes it.
//
// The error is non-nil only when ctx ended. The reply is then not to be
// sent, since it may be cut short, but its Close still says whether the
// connection closes.
func (s *Session) Do(ctx context.Context, line string) (Reply, error) {
	line = strings.TrimFunc(line, pySpace)
	if line == "" {
		return nothing, nil
	}
	snap := s.snapshot()
	r := s.do(ctx, snap, line)
	if s.maxReply > 0 && int64(r.Len()) > s.maxReply {
		r = r.Refused(tooLargeMsg(s.maxReply))
	}
	if r.cause != nil {
		r.cause = fmt.Errorf("sources %s: %w", strings.Join(s.sources(snap), ","), r.cause)
	}
	if !s.persistent && line != "!!" {
		r.close = true
	}
	return r, ctx.Err()
}

func (s *Session) do(ctx context.Context, snap *Snapshot, line string) Reply {
	if strings.IndexByte(line, 0) >= 0 {
		return Fail("Queries may not contain null bytes")
	}
	// "-V <agent> !<command>" is the IRRd command, the user agent dropped
	// (IRRd's handle_query, irrd issue #985): split at single spaces, as
	// IRRd splits it.
	if rest, found := strings.CutPrefix(line, "-V "); found {
		if _, cmd, two := strings.Cut(rest, " "); two && strings.HasPrefix(cmd, "!") {
			line = cmd
		}
	}
	if line[0] != '!' {
		return s.ripe(ctx, snap, line)
	}
	if line == "!" {
		return Fail("Missing IRRD command")
	}
	cmd, size := utf8.DecodeRuneInString(line[1:])
	arg := line[1+size:]
	switch cmd {
	case '!':
		s.persistent = true
		return nothing
	case 'q', 'Q':
		return Reply{close: true}
	case 'v':
		return frame("IRRd -- version 4.5.3 (rpsld" + suffix(snap.opts.Version) + ")")
	}
	if arg == "" {
		switch cmd {
		case 'a':
			return Fail("Missing required set name for A query")
		case 'i', 'g', '6', 's', 'j', 'n', 't', 'm', 'r', 'o':
			return Fail("Missing parameter for " + string(cmd) + " query")
		}
	}
	switch cmd {
	case 'n':
		return ok
	case 't':
		v, err := strconv.Atoi(arg)
		if err != nil || v < 1 || v > 1000 {
			return Fail("Invalid value for timeout: " + arg)
		}
		s.timeout = time.Duration(v) * time.Second
		return ok
	case 's':
		return s.selectSources(snap, arg)
	case 'j':
		return serials(snap, arg)
	}
	if h := commands[cmd]; h != nil {
		return h(ctx, s, snap, arg)
	}
	return Fail("Unrecognised command: " + string(cmd))
}

func suffix(v string) string {
	if v == "" {
		return ""
	}
	return " " + v
}

// commands are the query commands Tasks 5-7 add: '!' + letter -> handler.
var commands = map[rune]func(ctx context.Context, s *Session, snap *Snapshot, arg string) Reply{}

// selectSources answers "!s": "-lc" lists the selection, "-*" is accepted
// and changes nothing (as IRRd 4.5.3 does), and a list of names selects
// them, in the order given, when every one is a registry; otherwise the
// selection stays as it was. The list is split at commas only, as IRRd
// splits it: a name with spaces around it is no registry.
func (s *Session) selectSources(snap *Snapshot, arg string) Reply {
	switch arg {
	case "-lc":
		return frame(strings.Join(s.sources(snap), ","))
	case "-*":
		return ok
	}
	next, found := snap.selection(arg)
	if !found {
		return Fail(unavailable)
	}
	s.sel = next
	return ok
}

// unavailable is IRRd's refusal of a selection naming a source it lacks.
const unavailable = "One or more selected sources are unavailable."

// selection reads a list of registry names ("!s", RIPE-style "-s"): split at
// commas only, as IRRd splits it, each name canonical upper-case, a repeated
// name kept once, where it first appears (IRRd selects with SQL's IN, which
// never repeats a row); ok is false unless every name is a registry of snap.
func (snap *Snapshot) selection(list string) (names []string, ok bool) {
	for _, n := range strings.Split(list, ",") {
		name, err := types.ParseSourceName(n)
		if err != nil || snap.byName[name] == nil {
			return nil, false
		}
		if !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	return names, true
}

// serials answers "!j": NAME:N:0-<serial> per registry ("-" for serial 0),
// then NAME:X:Database unknown for each name no registry has, each group in
// the order asked; "-*" asks for every registry, in precedence order. The
// list is split at commas only, as IRRd splits it, and each name upper-cased.
func serials(snap *Snapshot, arg string) Reply {
	var names []string
	if arg == "-*" {
		for _, r := range snap.regs {
			names = append(names, r.name)
		}
	} else {
		names = strings.Split(arg, ",")
	}
	var known, unknown []string
	for _, n := range names {
		up := strings.ToUpper(n)
		r := snap.byName[up]
		switch {
		case r == nil:
			unknown = append(unknown, up+":X:Database unknown")
		case r.serial == 0:
			known = append(known, up+":N:-")
		default:
			known = append(known, fmt.Sprintf("%s:N:0-%d", up, r.serial))
		}
	}
	return frame(strings.Join(append(known, unknown...), "\n"))
}
