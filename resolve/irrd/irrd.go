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
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

// Source is a resolve.Source backed by an IRRd query-protocol server.
//
// By default each query uses a fresh connection (stateless, concurrency-safe).
// Set KeepAlive to reuse persistent connections from an internal pool — fewer
// TCP handshakes when expanding large set graphs. A KeepAlive Source must be
// Close()d to release pooled connections.
type Source struct {
	Addr    string                                      // "whois.radb.net:43"
	Sources string                                      // optional "!s" precedence, e.g. "RADB,RIPE"
	Timeout time.Duration                               // per-call dial+I/O deadline; 0 = no deadline
	Dial    func(ctx context.Context) (net.Conn, error) // override transport in tests; nil = net.Dialer

	KeepAlive bool // reuse persistent connections from a pool
	MaxConns  int  // max idle pooled connections when KeepAlive (default 2)

	mu   sync.Mutex
	idle []*pconn
}

var _ resolve.Source = (*Source)(nil)

// pconn is a persistent IRRd connection (in "!!" mode) retained in the pool.
type pconn struct {
	conn net.Conn
	br   *bufio.Reader
}

// errNotFound is the internal sentinel for a 'D' (key not found) response.
var errNotFound = errors.New("irrd: key not found")

// GetSet fetches a set's one-level membership via "!i" and synthesizes a typed
// set object. A missing set maps to resolve.ErrNotFound.
func (s *Source) GetSet(ctx context.Context, name types.SetName) (object.Set, error) {
	payload, err := s.do(ctx, "!i"+name.String())
	if err != nil {
		if errors.Is(err, errNotFound) {
			return nil, resolve.ErrNotFound
		}
		return nil, err
	}
	members := parseMembers(string(payload))
	if name.Class == types.AsSet {
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

// do runs one query. With KeepAlive it borrows a persistent connection from the
// pool (dialing a new one if none is idle), returning it on success and
// discarding it on error. Otherwise it opens and closes a fresh connection.
func (s *Source) do(ctx context.Context, cmd string) ([]byte, error) {
	if s.KeepAlive {
		return s.doPooled(ctx, cmd)
	}
	conn, err := s.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if s.Timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(s.Timeout))
	}
	br := bufio.NewReader(conn)

	if s.Sources != "" {
		if _, err := fmt.Fprintf(conn, "!s%s\n", s.Sources); err != nil {
			return nil, err
		}
		if _, err := readFrame(br); err != nil {
			return nil, err
		}
	}
	if _, err := fmt.Fprintf(conn, "%s\n", cmd); err != nil {
		return nil, err
	}
	payload, err := readFrame(br)
	// Best-effort graceful quit; ignore errors on the way out.
	_, _ = io.WriteString(conn, "!q\n")
	return payload, err
}

func (s *Source) doPooled(ctx context.Context, cmd string) ([]byte, error) {
	pc, err := s.acquire(ctx)
	if err != nil {
		return nil, err
	}
	if s.Timeout > 0 {
		_ = pc.conn.SetDeadline(time.Now().Add(s.Timeout))
	}
	if _, err := fmt.Fprintf(pc.conn, "%s\n", cmd); err != nil {
		_ = pc.conn.Close()
		return nil, err
	}
	payload, err := readFrame(pc.br)
	if err != nil && !errors.Is(err, errNotFound) {
		_ = pc.conn.Close() // protocol/transport error: do not reuse
		return nil, err
	}
	s.release(pc)
	return payload, err
}

// acquire returns an idle pooled connection or dials and initializes a new one.
func (s *Source) acquire(ctx context.Context) (*pconn, error) {
	s.mu.Lock()
	if n := len(s.idle); n > 0 {
		pc := s.idle[n-1]
		s.idle = s.idle[:n-1]
		s.mu.Unlock()
		return pc, nil
	}
	s.mu.Unlock()
	return s.newPConn(ctx)
}

// newPConn dials a connection and puts it in persistent ("!!") mode.
func (s *Source) newPConn(ctx context.Context) (*pconn, error) {
	conn, err := s.dial(ctx)
	if err != nil {
		return nil, err
	}
	if s.Timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(s.Timeout))
	}
	br := bufio.NewReader(conn)
	if _, err := io.WriteString(conn, "!!\n"); err != nil { // enable persistent mode; no response
		_ = conn.Close()
		return nil, err
	}
	if s.Sources != "" {
		if _, err := fmt.Fprintf(conn, "!s%s\n", s.Sources); err != nil {
			_ = conn.Close()
			return nil, err
		}
		if _, err := readFrame(br); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	return &pconn{conn: conn, br: br}, nil
}

// release returns a connection to the pool, or closes it if the pool is full.
func (s *Source) release(pc *pconn) {
	s.mu.Lock()
	if len(s.idle) < s.maxConns() {
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
	return 2
}

// Close releases all pooled connections. It is safe to call on a non-KeepAlive
// Source (a no-op) and may be called multiple times.
func (s *Source) Close() error {
	s.mu.Lock()
	conns := s.idle
	s.idle = nil
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
	d := net.Dialer{Timeout: s.Timeout}
	return d.DialContext(ctx, "tcp", s.Addr)
}

// readFrame parses one IRRd response: "A<len>\n<payload>\nC\n" (data), "C\n"
// (empty success), "D\n" (not found → errNotFound), or "F <msg>" (error).
func readFrame(br *bufio.Reader) ([]byte, error) {
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
		n, err := strconv.Atoi(header[1:])
		if err != nil {
			return nil, fmt.Errorf("irrd: bad length header %q", header)
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(br, buf); err != nil {
			return nil, err
		}
		if _, err := br.ReadString('\n'); err != nil { // trailing "C" status line
			return nil, err
		}
		return buf, nil
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
func parseMembers(payload string) []object.SetMember {
	var out []object.SetMember
	for _, tok := range strings.Fields(payload) {
		if as, err := types.ParseASN(tok); err == nil {
			out = append(out, object.SetMember{Kind: object.MemberAS, AS: as, Raw: tok})
			continue
		}
		if sn, err := types.ParseSetName(tok); err == nil {
			out = append(out, object.SetMember{Kind: object.MemberSet, Set: sn, Raw: tok})
			continue
		}
		if pr, err := types.ParsePrefixRange(tok); err == nil {
			out = append(out, object.SetMember{Kind: object.MemberPrefixRange, Range: pr, Raw: tok})
			continue
		}
		out = append(out, object.SetMember{Raw: tok})
	}
	return out
}
