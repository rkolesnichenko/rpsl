// Package irrd implements a resolve.Source backed by an IRRd query-protocol
// server (RADB, NTT, RIPE-NONAUTH mirrors, …) over TCP/43 — the same servers
// and commands bgpq4 uses. Network access is confined to this sub-package; the
// core resolve engine stays pure and socket-free.
//
// Membership note: for an as-set or route-set GetSet issues the one-level "!i"
// query, whose result is the server's already-resolved membership (it folds in
// indirect mbrs-by-ref members). The engine must therefore not resolve indirect
// membership again, so MembersByRef returns nothing for those. (MemSource, by
// contrast, holds raw objects and resolves membership itself.) The other set
// classes — rtr-set, peering-set, filter-set — "!i" does not serve, so GetSet
// fetches them whole with "!m". The query protocol has no inverse query for
// the inet-rtr member-of claims an rtr-set's mbrs-by-ref admits, so
// MembersByRef returns ErrIndirectUnsupported for such a set; use the whois
// Source for it.
package irrd

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rkolesnichenko/rpsl"
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
// connections. Close releases pooled connections; queries after it return
// ErrClosed. Like http.Transport, a Source must not be copied or have its
// fields changed after first use.
//
// Sources lists IRR source names in priority order ("!s"): a set defined in
// several of them is taken from the first, while routes are the union of all.
// Each name must be letters, digits, '-' or '_'.
type Source struct {
	Addr        string                                      // "whois.radb.net:43"
	Sources     []string                                    // optional "!s" priority, e.g. {"RADB", "RIPE"}
	Timeout     time.Duration                               // one deadline per query: slot wait, dial, I/O, retry; 0 = DefaultTimeout, < 0 = none (ctx only)
	MaxResponse int64                                       // cap on one response payload; 0 = 32 MiB, < 0 = none
	Dial        func(ctx context.Context) (net.Conn, error) // override transport in tests; nil = net.Dialer

	KeepAlive bool // reuse persistent connections from a pool
	MaxConns  int  // max concurrent connections, and pooled ones with KeepAlive; 0 = 4, < 0 = none

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

// ErrClosed is returned by queries on a Source after Close.
var ErrClosed = errors.New("irrd: source closed")

// ErrIndirectUnsupported is returned by MembersByRef for an rtr-set with
// mbrs-by-ref: the IRRd query protocol cannot list the inet-rtr objects that
// claim membership in it, and an answer without them would silently be
// smaller. The whois Source can.
var ErrIndirectUnsupported = errors.New("irrd: indirect rtr-set members need a whois Source")

// defaultMaxConns is MaxConns when zero.
const defaultMaxConns = 4

// defaultMaxResponse caps a single IRRd response payload. 32 MiB is over twenty
// times the largest real "!i" or route payload (RADB's RS-ALGAR lists 1.3 MB of
// members; AS45899 originates 72,827 routes), and a decoded "!i" answer holds
// about 100 bytes per member however short its text, so a larger cap buys
// nothing but a hostile server's leverage. Memory grows only with the bytes
// that actually arrive, whatever length a header claims.
const defaultMaxResponse = 32 << 20

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
	switch {
	case s.MaxResponse == 0:
		return defaultMaxResponse
	case s.MaxResponse < 0:
		return math.MaxInt64
	}
	return s.MaxResponse
}

// sourceList validates Sources and returns the "!s" argument ("" for none).
func (s *Source) sourceList() (string, error) {
	names := make([]string, len(s.Sources))
	for i, n := range s.Sources {
		if !validSourceName(n) {
			return "", fmt.Errorf("irrd: invalid source name %q", n)
		}
		names[i] = strings.ToUpper(n)
	}
	return strings.Join(names, ","), nil
}

// validSourceName reports whether n is a plain IRR source name: letters,
// digits, '-' and '_' only, so it cannot carry another command or argument.
func validSourceName(n string) bool {
	if n == "" {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// GetSet fetches a set. For an as-set or route-set it asks for the one-level
// membership via "!i" and synthesizes a typed set object. IRRd answers "!i"
// alike for a missing set and for one with no members, so on that answer
// GetSet asks for the object itself ("!m"): a set that exists is returned
// empty, and a missing one maps to resolve.ErrNotFound. A set of any other
// class is fetched with "!m" and decoded.
func (s *Source) GetSet(ctx context.Context, name types.SetName) (object.NamedSet, error) {
	if name.IsZero() {
		return nil, errors.New("irrd: empty set name")
	}
	if c := name.Class(); c != types.ClassAsSet && c != types.ClassRouteSet {
		return s.fetchSet(ctx, name)
	}
	payload, err := s.do(ctx, "!i"+name.String())
	if errors.Is(err, errNotFound) {
		_, err = s.do(ctx, "!m"+name.Class().String()+","+name.String())
		payload = nil
	}
	if err != nil {
		if errors.Is(err, errNotFound) {
			return nil, resolve.ErrNotFound
		}
		return nil, err
	}
	members := parseMembers(string(payload), name.Class())
	if name.Class() == types.ClassAsSet {
		return object.AsSet{Name: name, Members: members}, nil
	}
	return object.RouteSet{Name: name, Members: members}, nil
}

// fetchSet fetches a set whole ("!m") and decodes it, refusing an answer that
// is not the set asked for.
func (s *Source) fetchSet(ctx context.Context, name types.SetName) (object.NamedSet, error) {
	payload, err := s.do(ctx, "!m"+name.Class().String()+","+name.String())
	if err != nil {
		if errors.Is(err, errNotFound) {
			return nil, resolve.ErrNotFound
		}
		return nil, err
	}
	raw, _ := rpsl.ParseObject(string(payload))
	obj, _ := object.Decode(raw)
	set, ok := obj.(object.NamedSet)
	if !ok || set.SetName() != name || set.Class() != name.Class().String() {
		return nil, fmt.Errorf("irrd: !m%s,%s answered with %s %q", name.Class(), name, raw.Class(), raw.Key())
	}
	return set, nil
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

// MembersByRef returns nothing for an as-set or route-set, whose indirect
// members the server's "!i" result already holds, and ErrIndirectUnsupported
// for an rtr-set with mbrs-by-ref (see the package note).
func (s *Source) MembersByRef(_ context.Context, set object.NamedSet) ([]object.Object, error) {
	if set != nil && set.SetName().Class() == types.ClassRtrSet && len(set.RefMntners()) > 0 {
		return nil, fmt.Errorf("irrd: %s: %w", set.SetName(), ErrIndirectUnsupported)
	}
	return nil, nil
}

// routes runs a route query, treating not-found as an empty set. A token that
// is not a prefix is an error: dropping it would shrink the result silently.
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
		p, err := types.ParsePrefix(tok) // RPSL's address grammar, as for every registry value
		if err != nil {
			return nil, fmt.Errorf("irrd: %s: invalid prefix %q in the response", cmd, tok)
		}
		out = append(out, p)
	}
	return out, nil
}

// do runs one query, waiting for a connection slot (MaxConns) first.
func (s *Source) do(ctx context.Context, cmd string) ([]byte, error) {
	if _, err := s.sourceList(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return nil, ErrClosed
	}
	ctx, cancel := netconn.WithTimeout(ctx, s.timeout())
	defer cancel()
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
	release := netconn.Bind(ctx, conn, 0)
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
	release := netconn.Bind(ctx, pc.conn, 0)
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
	release := netconn.Bind(ctx, conn, 0)
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
	list, err := s.sourceList()
	if err != nil || list == "" {
		return err
	}
	if _, err := fmt.Fprintf(conn, "!s%s\n", list); err != nil {
		return err
	}
	if _, err := readFrame(br, s.maxResponse()); err != nil {
		if errors.Is(err, errNotFound) {
			return fmt.Errorf("irrd: server rejected source list %q", list)
		}
		return fmt.Errorf("irrd: selecting sources %q: %w", list, err)
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
	switch {
	case s.MaxConns == 0:
		return defaultMaxConns
	case s.MaxConns < 0:
		return math.MaxInt
	}
	return s.MaxConns
}

// acquireSlot waits (honouring ctx) until fewer than MaxConns queries hold a
// connection.
func (s *Source) acquireSlot(ctx context.Context) error {
	if s.MaxConns < 0 {
		return ctx.Err() // unlimited: no semaphore
	}
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
	if s.MaxConns < 0 {
		return
	}
	s.mu.Lock()
	slots := s.slots
	s.mu.Unlock()
	<-slots
}

// Close releases all pooled connections; later queries return ErrClosed, and
// queries already running finish without returning their connections to the
// pool. It may be called more than once, and on a Source that never pooled.
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
	var d net.Dialer // ctx carries the query's deadline
	return d.DialContext(ctx, "tcp", s.Addr)
}

// readFrame parses one IRRd response: "A<len>\n<payload>C\n" (data; <len>
// includes the payload's trailing newline), "C\n" (empty success), "D\n" (not
// found → errNotFound), or "F <msg>" (error). A payload longer than max is
// rejected before it is read, and memory grows only with the bytes that arrive,
// never with the length a header claims.
func readFrame(br *bufio.Reader, max int64) ([]byte, error) {
	header, err := readStatusLine(br)
	if err != nil {
		return nil, err
	}
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
		trailer, err := readStatusLine(br) // the "C" status line that ends the frame
		if err != nil {
			return nil, err
		}
		if trailer != "C" {
			return nil, fmt.Errorf("irrd: expected 'C' status after payload, got %q", trailer)
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

// maxStatusLine bounds the header and status lines of a response ("A123",
// "C", "D", "F message"), which MaxResponse does not cover.
const maxStatusLine = 1 << 10

// readStatusLine reads one response line without its terminator, refusing one
// longer than maxStatusLine instead of buffering it.
func readStatusLine(br *bufio.Reader) (string, error) {
	var line []byte
	for {
		frag, err := br.ReadSlice('\n')
		if len(line)+len(frag) > maxStatusLine {
			return "", fmt.Errorf("irrd: response line longer than %d bytes", maxStatusLine)
		}
		line = append(line, frag...)
		switch err {
		case nil:
			return strings.TrimRight(string(line), "\r\n"), nil
		case bufio.ErrBufferFull:
			continue
		case io.EOF:
			if len(line) > 0 {
				err = io.ErrUnexpectedEOF
			}
		}
		return "", err
	}
}

// parseMembers turns a whitespace-separated "!i" payload into typed members,
// in a slice sized once, each member's text a substring of the payload.
func parseMembers(payload string, class types.SetClass) []object.SetMember {
	out := make([]object.SetMember, 0, countTokens(payload))
	for rest := payload; ; {
		var tok string
		if tok, rest = nextToken(rest); tok == "" {
			return out
		}
		m, _ := object.ParseSetMember(tok, class) // unparseable tokens stay MemberInvalid
		out = append(out, m)
	}
}

// nextToken splits the first run of non-space bytes off s. The payload is
// ASCII, as IRRd writes it; any other byte is part of a token.
func nextToken(s string) (tok, rest string) {
	i := 0
	for i < len(s) && isSpace(s[i]) {
		i++
	}
	j := i
	for j < len(s) && !isSpace(s[j]) {
		j++
	}
	return s[i:j], s[j:]
}

func countTokens(s string) int {
	n := 0
	for tok, rest := nextToken(s); tok != ""; tok, rest = nextToken(rest) {
		n++
	}
	return n
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'
}
