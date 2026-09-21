// Package irrd implements a resolve.Source backed by an IRRd query-protocol
// server (RADB, NTT, RIPE-NONAUTH mirrors, …) over TCP/43 — the same servers
// and commands bgpq4 uses. Network access is confined to this sub-package; the
// core resolve engine stays pure and socket-free.
//
// Membership note: GetSet issues the one-level "!i" query, whose result is the
// server's already-resolved membership (it folds in indirect mbrs-by-ref
// members). The engine must therefore not resolve indirect membership again, so
// MembersByRef intentionally returns nothing for this backend. (MemSource, by
// contrast, holds raw objects and resolves membership itself.)
package irrd

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/internal/netconn"
	"github.com/rkolesnichenko/rpsl/types"
)

// Source is a resolve.Source backed by an IRRd query-protocol server.
//
// By default each query uses a fresh connection. Set KeepAlive to reuse
// persistent connections from an internal pool — fewer TCP handshakes when
// expanding large set graphs; a reused connection the server has meanwhile
// closed is retried once on a fresh one. Every query honours its context:
// cancelling it, or its deadline passing, aborts a pending read at once.
// A Source is safe for concurrent use; MaxConns bounds its concurrent
// connections. A KeepAlive Source should be Close()d to release pooled
// connections; it keeps working afterwards but no longer pools.
type Source struct {
	Addr        string                                      // "whois.radb.net:43"
	Sources     string                                      // optional "!s" precedence, e.g. "RADB,RIPE"
	Timeout     time.Duration                               // per-query dial+I/O deadline; 0 = DefaultTimeout, < 0 = none (ctx only)
	MaxResponse int64                                       // cap on one response payload; 0 = 256 MiB
	Dial        func(ctx context.Context) (net.Conn, error) // override transport in tests; nil = net.Dialer

	KeepAlive bool // reuse persistent connections from a pool
	MaxConns  int  // max concurrent connections, and pooled ones with KeepAlive (default 4)

	mu     sync.Mutex
	idle   []*pconn
	slots  chan struct{} // semaphore of MaxConns, created on first use
	closed bool
}

var _ resolve.Source = (*Source)(nil)

// DefaultTimeout is the per-query deadline used when Source.Timeout is zero, so
// a stalled server cannot hang a caller that passes context.Background().
const DefaultTimeout = 60 * time.Second

// pconn is a persistent IRRd connection (in "!!" mode) retained in the pool.
type pconn struct {
	conn net.Conn
	br   *bufio.Reader
}

// errNotFound is the internal sentinel for a 'D' (key not found) response.
var errNotFound = errors.New("irrd: key not found")

// defaultMaxResponse caps a single IRRd response payload. 256 MiB dwarfs any
// real "!i" or route payload; memory still grows only with the bytes that
// actually arrive, whatever length a header claims.
const defaultMaxResponse = 256 << 20

func (s *Source) timeout() time.Duration {
	switch {
	case s.Timeout == 0:
		return DefaultTimeout
	case s.Timeout < 0:
		return 0
	}
	return s.Timeout
}

func (s *Source) maxResponse() int64 {
	if s.MaxResponse > 0 {
		return s.MaxResponse
	}
	return defaultMaxResponse
}

// GetSet fetches a set's one-level membership via "!i" and synthesizes a typed
// set object. A missing set maps to resolve.ErrNotFound.
func (s *Source) GetSet(ctx context.Context, name types.SetName) (object.Set, error) {
	if name.IsZero() {
		return nil, errors.New("irrd: empty set name")
	}
	payload, err := s.do(ctx, "!i"+name.String())
	if err != nil {
		if errors.Is(err, errNotFound) {
			return nil, resolve.ErrNotFound
		}
		return nil, err
	}
	members := parseMembers(string(payload), name.Class())
	if name.Class() == types.AsSet {
		return object.AsSet{Name: name, Members: members}, nil
	}
	return object.RouteSet{Name: name, Members: members}, nil
}

// OriginatedRoutes fetches prefixes originated by as via "!g" (IPv4) and "!6"
// (IPv6), as constrained by afi. A "no routes" (D) response is an empty result,
// not an error.
func (s *Source) OriginatedRoutes(ctx context.Context, as types.ASN, afi types.AFI) ([]netip.Prefix, error) {
	var out []netip.Prefix
	if afi != types.AFIv6 { // v4 or unconstrained
		v4, err := s.routes(ctx, "!g"+as.String())
		if err != nil {
			return nil, err
		}
		out = append(out, v4...)
	}
	if afi != types.AFIv4 { // v6 or unconstrained
		v6, err := s.routes(ctx, "!6"+as.String())
		if err != nil {
			return nil, err
		}
		out = append(out, v6...)
	}
	return out, nil
}

// MembersByRef returns nothing: indirect membership is already folded into the
// server's "!i" result (see the package note).
func (s *Source) MembersByRef(context.Context, types.SetName, []string) ([]object.Object, error) {
	return nil, nil
}

// routes runs a route query, treating not-found as an empty set.
func (s *Source) routes(ctx context.Context, cmd string) ([]netip.Prefix, error) {
	payload, err := s.do(ctx, cmd)
	if err != nil {
		if errors.Is(err, errNotFound) {
			return nil, nil
		}
		return nil, err
	}
	var out []netip.Prefix
	for _, tok := range strings.Fields(string(payload)) {
		if p, err := netip.ParsePrefix(tok); err == nil {
			out = append(out, p)
		}
	}
	return out, nil
}

// do runs one query, waiting for a connection slot (MaxConns) first.
func (s *Source) do(ctx context.Context, cmd string) ([]byte, error) {
	if err := s.acquireSlot(ctx); err != nil {
		return nil, err
	}
	defer s.releaseSlot()
	if s.KeepAlive {
		return s.doPooled(ctx, cmd)
	}
	conn, err := s.dial(ctx)
	if err != nil {
		return nil, netconn.Err(ctx, err)
	}
	defer conn.Close()
	release := netconn.Bind(ctx, conn, s.timeout())
	defer release()
	br := bufio.NewReader(conn)
	// Without "!!" (persistent mode) IRRd answers one command and closes the
	// connection, so the "!s" source selection would consume it.
	if _, err := io.WriteString(conn, "!!\n"); err != nil {
		return nil, netconn.Err(ctx, err)
	}
	if err := s.selectSources(conn, br); err != nil {
		return nil, netconn.Err(ctx, err)
	}
	if _, err := fmt.Fprintf(conn, "%s\n", cmd); err != nil {
		return nil, netconn.Err(ctx, err)
	}
	payload, err := readFrame(br, s.maxResponse())
	_, _ = io.WriteString(conn, "!q\n") // best-effort graceful quit
	return payload, netconn.Err(ctx, err)
}

// doPooled runs one query on a pooled connection. A reused connection that
// fails at the transport level (the server closed it while idle) is discarded
// and the query retried once on a fresh connection; IRRd queries are reads, so
// repeating one is safe.
func (s *Source) doPooled(ctx context.Context, cmd string) ([]byte, error) {
	pc, reused, err := s.acquire(ctx)
	for attempt := 0; ; attempt++ {
		if err != nil {
			return nil, netconn.Err(ctx, err)
		}
		payload, reusable, qerr := s.exchange(ctx, pc, cmd)
		if reusable {
			s.release(pc)
		} else {
			_ = pc.conn.Close()
		}
		if qerr == nil || errors.Is(qerr, errNotFound) || !reused || attempt > 0 || ctx.Err() != nil || !isStale(qerr) {
			return payload, netconn.Err(ctx, qerr)
		}
		pc, err = s.newPConn(ctx)
		reused = false
	}
}

// exchange sends cmd on pc and reads its response, reporting whether pc is
// still in a clean state to be pooled again.
func (s *Source) exchange(ctx context.Context, pc *pconn, cmd string) (payload []byte, reusable bool, err error) {
	release := netconn.Bind(ctx, pc.conn, s.timeout())
	if _, err := fmt.Fprintf(pc.conn, "%s\n", cmd); err != nil {
		release()
		return nil, false, err
	}
	payload, err = readFrame(pc.br, s.maxResponse())
	clean := release()
	if err != nil && !errors.Is(err, errNotFound) {
		return nil, false, err // protocol or transport error: the stream is out of sync
	}
	return payload, clean, err
}

// isStale reports whether err means the connection was already closed by the
// server, as opposed to a timeout or a protocol error.
func isStale(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE)
}

// acquire returns an idle pooled connection (reused) or a freshly dialed one.
func (s *Source) acquire(ctx context.Context) (pc *pconn, reused bool, err error) {
	s.mu.Lock()
	if n := len(s.idle); n > 0 {
		pc := s.idle[n-1]
		s.idle = s.idle[:n-1]
		s.mu.Unlock()
		return pc, true, nil
	}
	s.mu.Unlock()
	pc, err = s.newPConn(ctx)
	return pc, false, err
}

// newPConn dials a connection and puts it in persistent ("!!") mode.
func (s *Source) newPConn(ctx context.Context) (*pconn, error) {
	conn, err := s.dial(ctx)
	if err != nil {
		return nil, err
	}
	release := netconn.Bind(ctx, conn, s.timeout())
	br := bufio.NewReader(conn)
	if _, err = io.WriteString(conn, "!!\n"); err == nil { // persistent mode; no response
		err = s.selectSources(conn, br)
	}
	if clean := release(); err != nil || !clean {
		_ = conn.Close()
		if err == nil {
			err = netconn.Err(ctx, errors.New("irrd: connection setup interrupted"))
		}
		return nil, err
	}
	return &pconn{conn: conn, br: br}, nil
}

// selectSources sends the "!s" source list, if any. A server that refuses it
// is an error, never a "not found" that would make every set look missing.
func (s *Source) selectSources(conn net.Conn, br *bufio.Reader) error {
	if s.Sources == "" {
		return nil
	}
	if _, err := fmt.Fprintf(conn, "!s%s\n", sanitizeLine(s.Sources)); err != nil {
		return err
	}
	if _, err := readFrame(br, s.maxResponse()); err != nil {
		if errors.Is(err, errNotFound) {
			return fmt.Errorf("irrd: server rejected source list %q", s.Sources)
		}
		return fmt.Errorf("irrd: selecting sources %q: %w", s.Sources, err)
	}
	return nil
}

// release returns a connection to the pool, or closes it if the pool is full
// or the Source has been closed.
func (s *Source) release(pc *pconn) {
	s.mu.Lock()
	if !s.closed && len(s.idle) < s.maxConns() {
		s.idle = append(s.idle, pc)
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	_, _ = io.WriteString(pc.conn, "!q\n")
	_ = pc.conn.Close()
}

func (s *Source) maxConns() int {
	if s.MaxConns > 0 {
		return s.MaxConns
	}
	return 4
}

// acquireSlot waits (honouring ctx) until fewer than MaxConns queries hold a
// connection.
func (s *Source) acquireSlot(ctx context.Context) error {
	s.mu.Lock()
	if s.slots == nil {
		s.slots = make(chan struct{}, s.maxConns())
	}
	slots := s.slots
	s.mu.Unlock()
	select {
	case slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Source) releaseSlot() {
	s.mu.Lock()
	slots := s.slots
	s.mu.Unlock()
	<-slots
}

// Close releases all pooled connections. Later queries still work, on fresh
// connections that are no longer pooled. It is safe to call on a non-KeepAlive
// Source (a no-op) and may be called multiple times.
func (s *Source) Close() error {
	s.mu.Lock()
	conns := s.idle
	s.idle, s.closed = nil, true
	s.mu.Unlock()
	for _, pc := range conns {
		_, _ = io.WriteString(pc.conn, "!q\n")
		_ = pc.conn.Close()
	}
	return nil
}

func (s *Source) dial(ctx context.Context) (net.Conn, error) {
	if s.Dial != nil {
		return s.Dial(ctx)
	}
	d := net.Dialer{Timeout: s.timeout()}
	return d.DialContext(ctx, "tcp", s.Addr)
}

// sanitizeLine strips control characters from a value interpolated into a
// line-oriented protocol command, so a stray newline in caller-supplied config
// (e.g. Sources) cannot inject an extra command line.
func sanitizeLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r < ' ' {
			return -1
		}
		return r
	}, s)
}

// readFrame parses one IRRd response: "A<len>\n<payload>C\n" (data; <len>
// includes the payload's trailing newline), "C\n" (empty success), "D\n" (not
// found → errNotFound), or "F <msg>" (error). A payload longer than max is
// rejected before it is read, and memory grows only with the bytes that arrive,
// never with the length a header claims.
func readFrame(br *bufio.Reader, max int64) ([]byte, error) {
	header, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	header = strings.TrimRight(header, "\r\n")
	if header == "" {
		return nil, errors.New("irrd: empty response header")
	}
	switch header[0] {
	case 'A':
		n, err := strconv.ParseInt(header[1:], 10, 64)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("irrd: bad length header %q", header)
		}
		if n > max {
			return nil, fmt.Errorf("irrd: response of %d bytes exceeds MaxResponse (%d)", n, max)
		}
		var buf bytes.Buffer
		if _, err := io.CopyN(&buf, br, n); err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return nil, err
		}
		trailer, err := br.ReadString('\n') // trailing "C" status line
		if err != nil {
			return nil, err
		}
		if !strings.HasPrefix(trailer, "C") {
			return nil, fmt.Errorf("irrd: missing 'C' status after payload, got %q",
				strings.TrimRight(trailer, "\r\n"))
		}
		return buf.Bytes(), nil
	case 'C':
		return []byte{}, nil
	case 'D':
		return nil, errNotFound
	case 'F':
		return nil, fmt.Errorf("irrd: query error: %s", strings.TrimSpace(header[1:]))
	default:
		return nil, fmt.Errorf("irrd: unexpected response %q", header)
	}
}

// parseMembers turns a whitespace-separated "!i" payload into typed members.
func parseMembers(payload string, class types.SetClass) []object.SetMember {
	var out []object.SetMember
	for _, tok := range strings.Fields(payload) {
		m, _ := object.ParseSetMember(tok, class) // unparseable tokens stay MemberInvalid
		out = append(out, m)
	}
	return out
}
