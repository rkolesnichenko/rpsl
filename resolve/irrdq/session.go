package irrdq

import (
	"context"
	"fmt"
	"io"
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

// frame is IRRd's data answer: "A<len>", the payload and a newline (counted
// in len), then "C".
func frame(payload string) Reply {
	payload += "\n"
	return Reply{text: fmt.Sprintf("A%d\n%sC\n", len(payload), payload)}
}

var (
	ok      = Reply{text: "C\n"}
	nothing = Reply{}
)

// Fail is IRRd's error answer, "F <msg>".
func Fail(msg string) Reply { return Reply{text: "F " + msg + "\n"} }

// A Session is one client connection's state: its selected registries, its
// persistent mode, its timeout. It is not safe for concurrent use: a
// connection's commands are answered one at a time, in order.
type Session struct {
	snapshot   func() *Snapshot
	sel        []string // nil: the snapshot's default
	persistent bool
	timeout    time.Duration
}

// NewSession starts a session that reads the current snapshot from snapshot,
// once per command.
func NewSession(snapshot func() *Snapshot) *Session { return &Session{snapshot: snapshot} }

// Timeout is what "!t" set, or 0.
func (s *Session) Timeout() time.Duration { return s.timeout }

// sources is the session's selected registry names.
func (s *Session) sources(snap *Snapshot) []string {
	if s.sel != nil {
		return s.sel
	}
	return snap.dflt
}

// Do answers one command line (its "\n" already cut; a trailing "\r" is
// dropped). A blank line is no command and reads no snapshot. Without "!!"
// the connection closes after the first command; "!q" closes it.
//
// The error is non-nil only when ctx ended. The reply is then not to be
// sent, since it may be cut short, but its Close still says whether the
// connection closes.
func (s *Session) Do(ctx context.Context, line string) (Reply, error) {
	line = strings.TrimRight(line, "\r")
	if strings.TrimSpace(line) == "" {
		return nothing, nil
	}
	snap := s.snapshot()
	r := s.do(ctx, snap, line)
	if !s.persistent && line != "!!" {
		r.close = true
	}
	return r, ctx.Err()
}

func (s *Session) do(ctx context.Context, snap *Snapshot, line string) Reply {
	if strings.IndexByte(line, 0) >= 0 {
		return Fail("Queries may not contain null bytes")
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
		case 'i', 'g', '6', 's', 'j', 'n', 't', 'm', 'r':
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
// selection stays as it was.
func (s *Session) selectSources(snap *Snapshot, arg string) Reply {
	switch arg {
	case "-lc":
		return frame(strings.Join(s.sources(snap), ","))
	case "-*":
		return ok
	}
	var next []string
	for _, n := range strings.Split(arg, ",") {
		name, err := types.ParseSourceName(strings.TrimSpace(n))
		if err != nil || snap.byName[name] == nil {
			return Fail("One or more selected sources are unavailable.")
		}
		next = append(next, name)
	}
	s.sel = next
	return ok
}

// serials answers "!j": NAME:N:0-<serial> per registry ("-" for serial 0),
// then NAME:X:Database unknown for each name no registry has, each group in
// the order asked; "-*" asks for every registry, in precedence order.
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
		up := strings.ToUpper(strings.TrimSpace(n))
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

// ripe answers a RIPE-style query (Task 6).
func (s *Session) ripe(ctx context.Context, snap *Snapshot, line string) Reply {
	return Reply{text: "%% ERROR: Unrecognised flag/search: " + line + "\n\n\n"}
}
