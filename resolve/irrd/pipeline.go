package irrd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rkolesnichenko/rpsl/resolve/internal/netconn"
)

// Pipelining (Source.Pipeline). A pipe is one persistent connection shared by
// concurrent queries: a writer takes the pipe's lock, queues its call and
// writes its command, so calls are queued in the order their commands go out;
// one reader goroutine reads the answers in that same order and hands each to
// its call. IRRd answers commands in the order it reads them, so the n-th
// answer is the n-th command's.
//
// Only a transport or framing error breaks a pipe, since after one the stream
// cannot be trusted: every call waiting on it fails, and each is retried once
// on a fresh pipe (IRRd queries are reads, so repeating one is safe). A "not
// found" or a refused query ('D', 'F') is that query's own answer. A caller
// that gives up only stops waiting: its answer is still read, so the stream
// stays in step for the calls behind it.

// pipe is one pipelined connection.
type pipe struct {
	s    *Source
	conn net.Conn
	br   *bufio.Reader

	mu    sync.Mutex // orders queueing and writing
	queue chan *call // calls whose commands are written, awaiting answers
	load  atomic.Int64

	breakOnce sync.Once
	broken    chan struct{} // closed when the pipe breaks; err says why
	err       error
	dead      chan struct{} // closed once the reader has failed every queued call
}

type call struct{ done chan result }

type result struct {
	payload []byte
	err     error
}

// doPipelined runs one query on a pipe, retrying once on a fresh pipe when
// the one it was queued on broke under it.
func (s *Source) doPipelined(ctx context.Context, cmd string) ([]byte, error) {
	for attempt := 0; ; attempt++ {
		p, err := s.pipeFor(ctx)
		if err != nil {
			return nil, netconn.Err(ctx, err)
		}
		payload, err := p.call(ctx, cmd)
		if err == nil || errors.Is(err, errNotFound) || errors.Is(err, errQuery) || errors.Is(err, ErrClosed) ||
			ctx.Err() != nil || attempt > 0 || !isStale(err) {
			return payload, netconn.Err(ctx, err)
		}
	}
}

// pipeFor returns the least loaded pipe with room, opening another while
// fewer than MaxConns are open, or else the least loaded pipe, where the call
// waits for room. The pipe returned counts the call in its load.
func (s *Source) pipeFor(ctx context.Context) (*pipe, error) {
	for {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return nil, ErrClosed
		}
		live := s.pipes[:0]
		var best *pipe
		for _, p := range s.pipes {
			if p.isBroken() {
				continue
			}
			live = append(live, p)
			if best == nil || p.load.Load() < best.load.Load() {
				best = p
			}
		}
		clear(s.pipes[len(live):])
		s.pipes = live
		if best != nil && best.load.Load() < int64(s.Pipeline) {
			best.load.Add(1)
			s.mu.Unlock()
			return best, nil
		}
		s.mu.Unlock()

		if s.trySlot() {
			p, err := s.newPipe(ctx)
			if err != nil {
				s.releaseSlot()
				return nil, err
			}
			s.mu.Lock()
			if s.closed {
				s.mu.Unlock()
				p.shut(ErrClosed)
				return nil, ErrClosed
			}
			p.load.Add(1)
			s.pipes = append(s.pipes, p)
			s.mu.Unlock()
			return p, nil
		}
		if best != nil {
			best.load.Add(1)
			return best, nil
		}
		// Every connection slot is taken by a pipe still being dialed.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// trySlot takes a connection slot if one is free. A pipe holds its slot until
// it breaks or the Source closes.
func (s *Source) trySlot() bool {
	if s.MaxConns < 0 {
		return true
	}
	s.mu.Lock()
	if s.slots == nil {
		s.slots = make(chan struct{}, s.maxConns())
	}
	slots := s.slots
	s.mu.Unlock()
	select {
	case slots <- struct{}{}:
		return true
	default:
		return false
	}
}

// newPipe dials a persistent connection and starts its reader.
func (s *Source) newPipe(ctx context.Context) (*pipe, error) {
	pc, err := s.newPConn(ctx)
	if err != nil {
		return nil, err
	}
	p := &pipe{
		s:      s,
		conn:   pc.conn,
		br:     pc.br,
		queue:  make(chan *call, s.Pipeline),
		broken: make(chan struct{}),
		dead:   make(chan struct{}),
	}
	go p.read()
	return p, nil
}

func (p *pipe) isBroken() bool {
	select {
	case <-p.broken:
		return true
	default:
		return false
	}
}

// shut breaks the pipe with err, closing its connection; the first cause wins.
func (p *pipe) shut(err error) {
	p.breakOnce.Do(func() {
		p.err = err
		close(p.broken)
		_ = p.conn.Close()
		p.s.releaseSlot()
	})
}

// call queues cmd and waits for its answer. The pipe's load already counts it.
func (p *pipe) call(ctx context.Context, cmd string) ([]byte, error) {
	c := &call{done: make(chan result, 1)}
	p.mu.Lock()
	select {
	case p.queue <- c:
	case <-p.broken:
		p.mu.Unlock()
		p.load.Add(-1)
		return nil, p.err
	case <-ctx.Done():
		p.mu.Unlock()
		p.load.Add(-1)
		return nil, ctx.Err()
	}
	if t := p.s.timeout(); t > 0 {
		_ = p.conn.SetWriteDeadline(time.Now().Add(t))
	}
	if _, err := fmt.Fprintf(p.conn, "%s\n", cmd); err != nil {
		p.shut(err) // the reader fails c with the rest
	}
	p.mu.Unlock()

	select {
	case r := <-c.done:
		return r.payload, r.err
	case <-p.dead:
		select { // the answer may have come just before the pipe broke
		case r := <-c.done:
			return r.payload, r.err
		default:
			return nil, p.err
		}
	case <-ctx.Done():
		return nil, ctx.Err() // the reader still consumes the answer
	}
}

// read hands each answer to its call, in order, until the pipe breaks; then
// it fails every call still queued.
func (p *pipe) read() {
	defer close(p.dead)
	for {
		var c *call
		select {
		case c = <-p.queue:
		case <-p.broken:
			p.failQueued()
			return
		}
		if t := p.s.timeout(); t > 0 {
			_ = p.conn.SetReadDeadline(time.Now().Add(t))
		}
		payload, err := readFrame(p.br, p.s.maxResponse())
		p.load.Add(-1)
		if err != nil && !errors.Is(err, errNotFound) && !errors.Is(err, errQuery) {
			p.shut(err)
			c.done <- result{nil, p.err}
			p.failQueued()
			return
		}
		c.done <- result{payload, err}
	}
}

// failQueued fails the calls queued on a broken pipe. A writer holding the
// pipe's lock may be queueing one more; once the lock is free, none can be.
func (p *pipe) failQueued() {
	drain := func() {
		for {
			select {
			case c := <-p.queue:
				p.load.Add(-1)
				c.done <- result{nil, p.err}
			default:
				return
			}
		}
	}
	drain()
	p.mu.Lock() // no writer is between queueing and writing now
	drain()
	p.mu.Unlock()
}
