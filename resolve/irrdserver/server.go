// Package irrdserver serves resolve/irrdq on sockets: IRRd's query protocol
// and RIPE-style queries on one port, as IRRd 4 does, with explicit limits.
// Each connection is a Session; each command reads the current snapshot
// once, so one answer comes from one snapshot.
//
// A line over MaxLine, an answer over MaxReply and a command past QueryTime
// are each answered as IRRd answers an error, with an F line and its
// reason, never with a truncated answer; a connection past MaxConns, or
// idle past its timeout, is closed.
package irrdserver

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/rkolesnichenko/rpsl/resolve/irrdq"
)

// Limits bound what one client can take. A zero field is its default.
type Limits struct {
	// MaxConns is the connections served at once; one more is closed as
	// soon as it is accepted, unanswered. 256.
	MaxConns int
	// IdleTimeout is how long the server waits for a command, or for the
	// client to read a part of an answer; "!t" overrides it for the
	// connection. 30s, IRRd's.
	IdleTimeout time.Duration
	// MaxLine is the bytes in one command line, its "\n" not counted (a
	// "\r" before it is). A longer line is answered "F Line too long" and
	// the connection closed. 1 MiB.
	MaxLine int
	// MaxReply is the bytes in one answer; a longer one is answered
	// "F Answer larger than …" instead. The session stops building an
	// answer's text as soon as it passes MaxReply
	// (irrdq.Session.SetMaxReply), so a far larger one's text is never
	// built; the list some answers are made from (a set's members or
	// expansion, an AS's prefixes, an inverse search's objects) is gathered
	// whole first, bounded by the registry rather than by MaxReply. 256 MiB.
	MaxReply int64
	// QueryTime is one command's evaluation; a command still evaluating
	// after it is answered "F Query took longer than …". 60s.
	QueryTime time.Duration
}

func (l Limits) withDefaults() Limits {
	if l.MaxConns <= 0 {
		l.MaxConns = 256
	}
	if l.IdleTimeout <= 0 {
		l.IdleTimeout = 30 * time.Second
	}
	if l.MaxLine <= 0 {
		l.MaxLine = 1 << 20
	}
	if l.MaxReply <= 0 {
		l.MaxReply = 256 << 20
	}
	if l.QueryTime <= 0 {
		l.QueryTime = 60 * time.Second
	}
	return l
}

// ErrServerClosed is what Serve returns after Shutdown.
var ErrServerClosed = errors.New("irrdserver: server closed")

// A Server answers IRRd and RIPE-style queries from the snapshot Snapshot
// returns. Set its fields before the first Serve; a Server serves any
// number of listeners until Shutdown.
type Server struct {
	Snapshot   func() *irrdq.Snapshot
	Limits     Limits
	Log        *slog.Logger // nil: nothing logged
	LogQueries bool         // one log line per command

	once    sync.Once
	lim     Limits
	sem     chan struct{}
	base    context.Context // every command's context; cancelled when Shutdown gives up waiting
	cancel  context.CancelFunc
	mu      sync.Mutex
	lns     map[net.Listener]struct{}
	conns   map[*conn]struct{}
	wg      sync.WaitGroup
	closing atomic.Bool
}

// conn is one served connection. stop, under mu, says Shutdown has begun:
// the connection reads no further command. Setting a read deadline and
// checking stop happen under the same lock, so a connection about to wait
// for a command either sees stop or has its deadline overridden by
// Shutdown's.
type conn struct {
	nc   net.Conn
	mu   sync.Mutex
	stop bool
}

// arm sets the read deadline to t unless Shutdown has begun; false then.
func (c *conn) arm(t time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stop {
		return false
	}
	c.nc.SetReadDeadline(t)
	return true
}

// halt stops the connection reading: a read in progress ends now.
func (c *conn) halt() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stop = true
	c.nc.SetReadDeadline(time.Now())
}

func (s *Server) init() {
	s.once.Do(func() {
		s.lim = s.Limits.withDefaults()
		s.sem = make(chan struct{}, s.lim.MaxConns)
		s.base, s.cancel = context.WithCancel(context.Background())
		s.lns, s.conns = map[net.Listener]struct{}{}, map[*conn]struct{}{}
	})
}

func (s *Server) log(level slog.Level, msg string, args ...any) {
	if s.Log != nil {
		s.Log.Log(context.Background(), level, msg, args...)
	}
}

// Serve accepts connections on ln until Shutdown (then ErrServerClosed) or
// an accept error it cannot retry. It closes ln when it returns.
func (s *Server) Serve(ln net.Listener) error {
	s.init()
	defer ln.Close()
	if s.Snapshot == nil {
		return errors.New("irrdserver: Server.Snapshot is nil")
	}
	s.mu.Lock()
	if s.closing.Load() {
		s.mu.Unlock()
		return ErrServerClosed
	}
	s.lns[ln] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.lns, ln)
		s.mu.Unlock()
	}()
	var backoff time.Duration
	for {
		nc, err := ln.Accept()
		if err != nil {
			if s.closing.Load() {
				return ErrServerClosed
			}
			if retryable(err) {
				backoff = min(max(2*backoff, 5*time.Millisecond), time.Second)
				s.log(slog.LevelWarn, "accept failed; retrying", "err", err, "after", backoff)
				time.Sleep(backoff)
				continue
			}
			return err
		}
		backoff = 0
		select {
		case s.sem <- struct{}{}:
		default:
			s.log(slog.LevelWarn, "refused: too many connections", "remote", nc.RemoteAddr().String(), "max", s.lim.MaxConns)
			nc.Close()
			continue
		}
		c := &conn{nc: nc}
		s.mu.Lock()
		if s.closing.Load() {
			s.mu.Unlock()
			<-s.sem
			nc.Close()
			return ErrServerClosed
		}
		s.conns[c] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go s.handle(c)
	}
}

// retryable reports whether an accept error passes: a timeout, or running
// out of file descriptors for a moment.
func retryable(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) || errors.Is(err, syscall.ECONNABORTED)
}

var errLineTooLong = errors.New("line too long")

// readLine reads one line without its "\n", at most max bytes long. A line
// is too long as soon as more than max of its bytes have arrived, newline or
// not, so a client waiting with a part of one is refused at once. A line
// cut off by the end of the input is no command (unless already too long).
func readLine(br *bufio.Reader, max int) (string, error) {
	var line []byte
	scanned := 0 // the buffered bytes already known to hold no newline
	for {
		buf, _ := br.Peek(br.Buffered())
		if i := bytes.IndexByte(buf[scanned:], '\n'); i >= 0 {
			i += scanned
			if len(line)+i > max {
				return "", errLineTooLong
			}
			line = append(line, buf[:i]...)
			br.Discard(i + 1)
			return string(line), nil
		}
		if len(line)+len(buf) > max {
			return "", errLineTooLong
		}
		scanned = len(buf)
		if len(buf) == br.Size() {
			line = append(line, buf...)
			br.Discard(len(buf))
			buf, scanned = nil, 0
		}
		// Wait for at least one more byte.
		if _, err := br.Peek(len(buf) + 1); err != nil {
			return "", err
		}
	}
}

// lineBuffered reports whether a whole further command line is buffered.
func lineBuffered(br *bufio.Reader) bool {
	b, _ := br.Peek(br.Buffered())
	return bytes.IndexByte(b, '\n') >= 0
}

// deadlineWriter writes to a connection in pieces, each with its own write
// deadline: the timeout bounds how long the client takes to read a piece,
// not the whole of a large answer.
type deadlineWriter struct {
	nc      net.Conn
	timeout time.Duration
}

const writePiece = 64 << 10

func (w *deadlineWriter) Write(p []byte) (int, error) {
	n := 0
	for len(p) > 0 {
		piece := p[:min(len(p), writePiece)]
		w.nc.SetWriteDeadline(time.Now().Add(w.timeout))
		m, err := w.nc.Write(piece)
		n += m
		if err != nil {
			return n, err
		}
		p = p[m:]
	}
	return n, nil
}

func (s *Server) handle(c *conn) {
	remote := c.nc.RemoteAddr().String()
	defer func() {
		if v := recover(); v != nil {
			s.log(slog.LevelError, "panic answering a connection", "remote", remote, "panic", v, "stack", string(debug.Stack()))
		}
		c.nc.Close()
		s.mu.Lock()
		delete(s.conns, c)
		s.mu.Unlock()
		<-s.sem
		s.wg.Done()
	}()
	sess := irrdq.NewSession(s.Snapshot)
	sess.SetMaxReply(s.lim.MaxReply)
	idle := func() time.Duration {
		if t := sess.Timeout(); t > 0 {
			return t
		}
		return s.lim.IdleTimeout
	}
	br := bufio.NewReaderSize(c.nc, 64<<10)
	w := &deadlineWriter{nc: c.nc}
	bw := bufio.NewWriterSize(w, writePiece)
	// end writes out every answer still buffered — each whole, since a
	// reply is buffered complete or not at all — and closes the connection
	// gently. Every exit but a failed write, or Shutdown giving up, ends so:
	// the client may still be reading.
	end := func() {
		w.timeout = idle()
		if bw.Flush() == nil {
			s.linger(c, br)
		}
	}
	for {
		if !c.arm(time.Now().Add(idle())) {
			end() // Shutdown: no further command
			return
		}
		line, err := readLine(br, s.lim.MaxLine)
		if errors.Is(err, errLineTooLong) {
			s.log(slog.LevelInfo, "refused: line too long", "remote", remote, "max", s.lim.MaxLine)
			fmt.Fprintf(bw, "F Line too long: over %d bytes\n", s.lim.MaxLine)
			end()
			return
		}
		if err != nil {
			end() // the client finished sending, a deadline passed, or Shutdown
			return
		}
		began := time.Now()
		deadline := began.Add(s.lim.QueryTime)
		ctx, cancel := context.WithDeadline(s.base, deadline)
		r, err := sess.Do(ctx, line)
		cancel()
		// The context's timer may not have fired yet: a command that took
		// longer than QueryTime is refused whether or not it noticed.
		if err == nil && !time.Now().Before(deadline) {
			err = context.DeadlineExceeded
		}
		switch {
		case s.base.Err() != nil:
			// Shutdown gave up waiting and is closing every connection: the
			// command is abandoned, unanswered. It did not overrun
			// QueryTime, and nothing more can be written anyway.
			s.log(slog.LevelInfo, "command abandoned at shutdown", "remote", remote, "line", line)
			return
		case err != nil:
			r = r.Refused("Query took longer than " + s.lim.QueryTime.String())
		}
		// An answer over MaxReply the session has refused already
		// (SetMaxReply), without building it.
		if cause := r.Cause(); cause != nil {
			// The client is told only that an internal error occurred.
			args := []any{"remote", remote, "command", commandName(line), "err", cause}
			if s.LogQueries {
				args = append(args, "line", line)
			}
			s.log(slog.LevelError, "query failed", args...)
		}
		if s.LogQueries {
			s.log(slog.LevelInfo, "query", "remote", remote, "line", line, "bytes", r.Len(), "took", time.Since(began))
		}
		w.timeout = idle()
		if _, err := r.WriteTo(bw); err != nil {
			return
		}
		if r.Close() || !lineBuffered(br) {
			if err := bw.Flush(); err != nil {
				return
			}
		}
		if r.Close() {
			end()
			return
		}
	}
}

// commandName is what a log line names a command by when the line itself is
// not logged (LogQueries): "!" and its letter, or "RIPE-style" for a query
// without "!" (whose words may be anything the client sent).
func commandName(line string) string {
	line = strings.TrimSpace(line)
	if rest, found := strings.CutPrefix(line, "-V "); found {
		if _, cmd, two := strings.Cut(rest, " "); two && strings.HasPrefix(cmd, "!") {
			line = cmd
		}
	}
	if !strings.HasPrefix(line, "!") {
		return "RIPE-style"
	}
	_, size := utf8.DecodeRuneInString(line[1:])
	return line[:1+size]
}

// lingerTime bounds how long a closing connection waits for the client to
// finish sending.
const lingerTime = time.Second

// linger closes c's write side and discards what the client still sends,
// until it closes too or lingerTime passes (or IdleTimeout, when shorter),
// so that closing with input unread does not reset the connection and lose
// the answers just written. Shutdown does not wait for lingering: a
// connection already lingering when Shutdown halts it stops at once (halt
// sets its read deadline to now), but one that reaches linger after the
// halt — having finished its command — sets the deadline anew and lingers,
// so a client that keeps sending can delay Shutdown by up to lingerTime.
// Once Shutdown's context ends it closes every connection, lingering or not.
func (s *Server) linger(c *conn, br *bufio.Reader) {
	tc, ok := c.nc.(interface{ CloseWrite() error })
	if !ok || tc.CloseWrite() != nil {
		return
	}
	c.nc.SetReadDeadline(time.Now().Add(min(lingerTime, s.lim.IdleTimeout)))
	io.Copy(io.Discard, br)
}

// Shutdown stops accepting, lets each connection finish the command it is
// answering, writes out every answer completed so far, whole, and closes
// the connections; no further command is started. At ctx's end it gives
// up: it cancels the commands still running, which are abandoned
// unanswered, closes what is left as it stands (an answer being written
// then may be cut short), waits for it and returns ctx's error.
func (s *Server) Shutdown(ctx context.Context) error {
	s.init()
	s.mu.Lock()
	s.closing.Store(true)
	for ln := range s.lns {
		ln.Close()
	}
	for c := range s.conns {
		c.halt()
	}
	s.mu.Unlock()
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
		s.cancel()
		return nil
	case <-ctx.Done():
		s.cancel()
		s.mu.Lock()
		for c := range s.conns {
			c.nc.Close()
		}
		s.mu.Unlock()
		<-done
		return ctx.Err()
	}
}
