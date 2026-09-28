package irrd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
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

	// handoff is set when the pipe is retired for another Source of its
	// family (retirePipe): it takes no new calls, and once the answers queued
	// on it are read it closes and hands its slot over. shut swaps in
	// shutMarker, so a pipe already shut cannot be retired.
	handoff atomic.Pointer[slotHandoff]
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
			return s.openPipe(ctx)
		}
		// Every slot is held: by this Source's pipes, by those of the parent
		// or another scoped lookup (they share MaxConns), or by one still
		// being dialed. A pipe keeps its slot while it lives, so free an idle
		// one of the family's if there is one.
		if s.reclaimIdlePipe() {
			continue
		}
		if best != nil {
			// Join it only if it is still ours: a pipe reclaimed or retired
			// meanwhile has left s.pipes and must never gain a call.
			s.mu.Lock()
			ok := slices.Contains(s.pipes, best) && !best.isBroken()
			if ok {
				best.load.Add(1)
			}
			s.mu.Unlock()
			if ok {
				return best, nil
			}
			continue
		}
		// No pipe of its own: rather than wait for a family pipe to go idle,
		// which under steady load it never does, retire one and take its slot
		// once its queued answers are read.
		if h := s.retirePipe(); h != nil {
			if !s.awaitSlot(ctx, h) {
				return nil, ctx.Err()
			}
			return s.openPipe(ctx)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// openPipe opens a pipe on the connection slot the caller holds, counting
// the call in its load; on failure the slot is released.
func (s *Source) openPipe(ctx context.Context) (*pipe, error) {
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

// errReclaimed closes a pipe whose connection slot another Source of the
// same family needs. Every call joins a pipe under its owner's lock and only
// while the pipe is in the owner's pipes, which a reclaimed or retired pipe
// has left, so no call should see it; it is stale (net.ErrClosed) all the
// same, so one that did would be retried on a fresh pipe.
var errReclaimed = fmt.Errorf("irrd: pipe reclaimed for another source list: %w", net.ErrClosed)

// shutMarker is the handoff of a pipe that has been shut.
var shutMarker = new(slotHandoff)

// slotHandoff passes the connection slot of a retired pipe to the call that
// retired it, so that no other query takes the slot first.
type slotHandoff struct {
	mu        sync.Mutex
	given     bool
	abandoned bool
	ready     chan struct{} // closed when given
}

// give hands the slot over, unless the waiter gave up, when the slot must be
// released instead.
func (h *slotHandoff) give() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.abandoned {
		return false
	}
	h.given = true
	close(h.ready)
	return true
}

// wait reports whether the slot arrived; a waiter that gives up (ctx) holds
// the slot anyway if it arrived meanwhile.
func (h *slotHandoff) wait(ctx context.Context) bool {
	select {
	case <-h.ready:
		return true
	case <-ctx.Done():
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.given {
		return true
	}
	h.abandoned = true
	return false
}

// root is the Source whose MaxConns budget s shares: its parent for a
// scoped lookup's sub-source, else s.
func (s *Source) root() *Source {
	if s.parent != nil {
		return s.parent
	}
	return s
}

// family returns the Sources sharing s's MaxConns budget other than s: the
// root and its sub-sources.
func (s *Source) family() []*Source {
	root := s.root()
	root.mu.Lock()
	defer root.mu.Unlock()
	var out []*Source
	if root != s {
		out = append(out, root)
	}
	for _, sub := range root.scoped {
		if sub != s {
			out = append(out, sub)
		}
	}
	return out
}

// reclaimIdlePipe shuts one idle pipe of another Source of s's family,
// freeing its slot. It reports whether it found one.
func (s *Source) reclaimIdlePipe() bool {
	for _, m := range s.family() {
		m.mu.Lock()
		var idle *pipe
		for i, p := range m.pipes {
			if !p.isBroken() && p.load.Load() == 0 {
				idle = p
				m.pipes = slices.Delete(m.pipes, i, i+1) // zeroes the vacated tail
				break
			}
		}
		m.mu.Unlock()
		if idle != nil {
			idle.shut(errReclaimed)
			return true
		}
	}
	return false
}

// retirePipe retires the least loaded pipe of another Source of s's family:
// it leaves its owner's pipes, so no new call joins it, and closes once the
// answers already queued on it are read, handing its slot to s through the
// handoff returned. It returns nil when there is no pipe to retire, or when a
// call of s already waits for one (the pipe that call opens serves the rest).
func (s *Source) retirePipe() *slotHandoff {
	root := s.root()
	root.reclaimMu.Lock()
	defer root.reclaimMu.Unlock()
	if s.waiting > 0 {
		return nil
	}
	var victim *pipe
	var owner *Source
	for _, m := range s.family() {
		m.mu.Lock()
		for _, p := range m.pipes {
			if !p.isBroken() && (victim == nil || p.load.Load() < victim.load.Load()) {
				victim, owner = p, m
			}
		}
		m.mu.Unlock()
	}
	if victim == nil {
		return nil
	}
	owner.mu.Lock()
	i := slices.Index(owner.pipes, victim)
	if i >= 0 {
		owner.pipes = slices.Delete(owner.pipes, i, i+1)
	}
	owner.mu.Unlock()
	h := &slotHandoff{ready: make(chan struct{})}
	if i < 0 || !victim.handoff.CompareAndSwap(nil, h) {
		return nil // it broke or was retired meanwhile; its slot is free or promised
	}
	root.retiring = slices.DeleteFunc(root.retiring, (*pipe).isBroken)
	root.retiring = append(root.retiring, victim)
	s.waiting++
	if victim.load.Load() == 0 {
		victim.shut(errReclaimed) // its last answer came before the handoff was set
	}
	return h
}

// awaitSlot waits for the slot of the pipe retired for s, reporting whether
// s now holds it.
func (s *Source) awaitSlot(ctx context.Context, h *slotHandoff) bool {
	got := h.wait(ctx)
	root := s.root()
	root.reclaimMu.Lock()
	s.waiting--
	root.reclaimMu.Unlock()
	return got
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
		if h := p.handoff.Swap(shutMarker); h != nil && h.give() {
			return // the slot now belongs to the call that retired the pipe
		}
		p.s.releaseSlot()
	})
}

// finished uncounts a call from the pipe's load; the last call of a retired
// pipe closes it.
func (p *pipe) finished() {
	if p.load.Add(-1) == 0 && p.handoff.Load() != nil {
		p.shut(errReclaimed)
	}
}

// call queues cmd and waits for its answer. The pipe's load already counts it.
func (p *pipe) call(ctx context.Context, cmd string) ([]byte, error) {
	c := &call{done: make(chan result, 1)}
	p.mu.Lock()
	select {
	case p.queue <- c:
	case <-p.broken:
		p.mu.Unlock()
		p.finished()
		return nil, p.err
	case <-ctx.Done():
		p.mu.Unlock()
		p.finished()
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
		if err != nil && !errors.Is(err, errNotFound) && !errors.Is(err, errQuery) {
			p.load.Add(-1)
			p.shut(err)
			c.done <- result{nil, p.err}
			p.failQueued()
			return
		}
		c.done <- result{payload, err}
		p.finished() // after the answer is handed over: a retired pipe closes here
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
