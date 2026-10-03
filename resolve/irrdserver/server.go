// Package irrdserver serves resolve/irrdq on sockets: IRRd's query protocol
// and RIPE-style queries on one port, as IRRd 4 does, with explicit limits.
// Each connection is a Session; each command reads the current snapshot
// once, so one answer comes from one snapshot.
//
// Every limit is answered as IRRd answers an error, with an F line and its
// reason, never with a truncated answer.
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
	"sync"
	"sync/atomic"
	"syscall"
	"time"

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
	// "F Answer larger than …" instead. 256 MiB.
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
	for {
		buf, _ := br.Peek(br.Buffered())
		if i := bytes.IndexByte(buf, '\n'); i >= 0 {
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
		if len(buf) == br.Size() {
			line = append(line, buf...)
			br.Discard(len(buf))
			buf = nil
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
	idle := func() time.Duration {
		if t := sess.Timeout(); t > 0 {
			return t
		}
		return s.lim.IdleTimeout
	}
	br := bufio.NewReaderSize(c.nc, 64<<10)
	w := &deadlineWriter{nc: c.nc}
	bw := bufio.NewWriterSize(w, writePiece)
	for {
		if !c.arm(time.Now().Add(idle())) {
			return // Shutdown: no further command
		}
		line, err := readLine(br, s.lim.MaxLine)
		if errors.Is(err, errLineTooLong) {
			s.log(slog.LevelInfo, "refused: line too long", "remote", remote, "max", s.lim.MaxLine)
			w.timeout = idle()
			fmt.Fprintf(bw, "F Line too long: over %d bytes\n", s.lim.MaxLine)
			if bw.Flush() == nil {
				s.linger(c, br)
			}
			return
		}
		if err != nil {
			return // the client went away, a deadline passed, or Shutdown
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
		case err != nil:
			r = r.Refused("Query took longer than " + s.lim.QueryTime.String())
		case int64(r.Len()) > s.lim.MaxReply:
			r = r.Refused(fmt.Sprintf("Answer larger than %d bytes", s.lim.MaxReply))
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
			s.linger(c, br)
			return
		}
	}
}

// lingerTime bounds how long a closing connection waits for the client to
// finish sending.
const lingerTime = time.Second

// linger closes c's write side and discards what the client still sends,
// until it closes too or lingerTime passes, so that closing with input
// unread does not reset the connection and lose the answer just written.
func (s *Server) linger(c *conn, br *bufio.Reader) {
	tc, ok := c.nc.(interface{ CloseWrite() error })
	if !ok || tc.CloseWrite() != nil {
		return
	}
	if !c.arm(time.Now().Add(min(lingerTime, s.lim.IdleTimeout))) {
		return
	}
	io.Copy(io.Discard, br)
}

// Shutdown stops accepting, lets each connection finish the command it is
// answering (and writing), and closes them all. At ctx's end it cancels the
// commands still running, closes what is left, waits for it and returns
// ctx's error.
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
