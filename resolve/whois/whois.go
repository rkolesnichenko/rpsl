// Package whois implements a resolve.Source over the RIPE-DB style plain
// WHOIS query protocol (TCP/43), distinct from the IRRd "!" protocol. It fetches
// raw RPSL objects and reuses the library's own parser/decoder, so it resolves
// indirect (mbrs-by-ref) membership itself via inverse queries — unlike the IRRd
// backend, which relies on server-side "!i" expansion. It works against both
// the RIPE Database and IRRd servers (whois.radb.net): queries put every flag
// before "-i attr value", which IRRd requires. Network access is confined to
// this sub-package; the core resolve engine stays pure.
package whois

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	rpsl "github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/internal/netconn"
	"github.com/rkolesnichenko/rpsl/types"
)

// Source is a resolve.Source backed by a plain WHOIS server (whois.ripe.net,
// whois.radb.net, …). Each query uses one connection: the query is sent, the
// full response is read until the server closes, and objects are parsed with the
// library's own stack. Every query honours its context: cancelling it, or its
// deadline passing, aborts a pending read at once. A server error — RIPE's
// "%ERROR:NNN" other than 101 ("no entries"), or IRRd's "%% ERROR:" — is
// returned as ServerError, never as an empty result.
type Source struct {
	Addr        string                                      // "whois.ripe.net:43"
	Sources     []string                                    // optional "-s" filter: only objects from these sources
	Timeout     time.Duration                               // one deadline per query, dial and I/O; 0 = DefaultTimeout, < 0 = none (ctx only)
	MaxResponse int64                                       // per-call response byte cap; 0 = 32 MiB, < 0 = none
	Dial        func(ctx context.Context) (net.Conn, error) // override transport in tests; nil = net.Dialer
}

var _ resolve.Source = (*Source)(nil)

// DefaultTimeout is the per-query deadline used when Source.Timeout is zero, so
// a stalled server cannot hang a caller that passes context.Background().
const DefaultTimeout = 60 * time.Second

func (s *Source) timeout() time.Duration {
	switch {
	case s.Timeout == 0:
		return DefaultTimeout
	case s.Timeout < 0:
		return 0
	}
	return s.Timeout
}

// ServerError is a WHOIS server error reply: RIPE's "%ERROR:201: access denied"
// (rate limiting) with Code 201, or IRRd's "%% ERROR: One or more selected
// sources are unavailable." with Code 0 (IRRd errors carry no code).
// It is returned as a *ServerError. "%ERROR:101: no entries found" is not an
// error: it becomes resolve.ErrNotFound or an empty result.
type ServerError struct {
	Code    int
	Message string
}

// Error implements error.
func (e *ServerError) Error() string {
	if e.Code == 0 {
		return "whois: server error: " + e.Message
	}
	return fmt.Sprintf("whois: server error %d: %s", e.Code, e.Message)
}

// maxResponse caps a single WHOIS response. A hostile or wedged server could
// otherwise stream unbounded data into io.ReadAll and exhaust memory; we treat
// hitting the cap as an error. 32 MiB is over twenty times the largest real
// answer (the member-of claims of the most-claimed set in RIPE or RADB are
// about 1.5 MB), and decoding holds a response's objects in several times its
// size, so a larger cap buys nothing but a hostile server's leverage.
const maxResponse = 32 << 20

func (s *Source) maxResponse() int64 {
	switch {
	case s.MaxResponse == 0:
		return maxResponse
	case s.MaxResponse < 0:
		return math.MaxInt64
	}
	return s.MaxResponse
}

// GetSet fetches a set object of any class by name. When the server returns
// it from several sources, the one from the source listed first in Sources
// wins; without Sources, the first the server returns.
func (s *Source) GetSet(ctx context.Context, name types.SetName) (object.NamedSet, error) {
	if name.IsZero() {
		return nil, errors.New("whois: empty set name")
	}
	class := name.Class().String()
	objs, err := s.queryObjects(ctx, "-r -T "+class+" "+name.String())
	if err != nil {
		return nil, err
	}
	var best object.NamedSet
	bestRank := len(s.Sources)
	for _, o := range objs {
		set, ok := o.(object.NamedSet)
		if !ok || set.SetName() != name || set.Class() != class {
			continue
		}
		rank := slices.IndexFunc(s.Sources, func(n string) bool { return strings.EqualFold(n, set.SetSource()) })
		if rank < 0 {
			rank = len(s.Sources)
		}
		if best == nil || rank < bestRank {
			best, bestRank = set, rank
		}
	}
	if best == nil {
		return nil, resolve.ErrNotFound
	}
	return best, nil
}

// OriginatedRoutes returns prefixes originated by as, via the inverse "origin"
// query, filtered to afi.
func (s *Source) OriginatedRoutes(ctx context.Context, as types.ASN, afi types.AFI) ([]netip.Prefix, error) {
	objs, err := s.queryObjects(ctx, "-r -T route,route6 -i origin "+as.String())
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, o := range objs {
		var p netip.Prefix
		switch t := o.(type) {
		case object.Route:
			p = t.Prefix
		case object.Route6:
			p = t.Prefix
		default:
			continue
		}
		if p.IsValid() && afiMatches(afi, p) {
			out = append(out, p)
		}
	}
	return out, nil
}

// MembersByRef returns the objects whose membership claim in set is honored,
// via the inverse "member-of" query plus resolve.ClaimAllowed (maintainer and
// same-source check) — real indirect-membership resolution. It asks only for
// the classes that may join a set of set's class (RFC 2622 §5.1-5.3).
func (s *Source) MembersByRef(ctx context.Context, set object.NamedSet) ([]object.Object, error) {
	if set == nil || set.SetName().IsZero() {
		return nil, errors.New("whois: empty set name")
	}
	classes := claimantClasses(set.SetName().Class())
	if classes == "" {
		return nil, nil
	}
	objs, err := s.queryObjects(ctx, "-r -T "+classes+" -i member-of "+set.SetName().String())
	if err != nil {
		return nil, err
	}
	var out []object.Object
	for _, o := range objs {
		if resolve.ClaimAllowed(o, set) {
			out = append(out, o)
		}
	}
	return out, nil
}

// claimantClasses lists the classes whose member-of claims a set of class c
// honours: aut-nums join as-sets, routes route-sets and inet-rtrs rtr-sets. A
// peering-set or filter-set has no mbrs-by-ref, and no claimants.
func claimantClasses(c types.SetClass) string {
	switch c {
	case types.ClassAsSet:
		return "aut-num"
	case types.ClassRouteSet:
		return "route,route6"
	case types.ClassRtrSet:
		return "inet-rtr"
	}
	return ""
}

// queryObjects runs one WHOIS query and decodes every object in the response.
func (s *Source) queryObjects(ctx context.Context, q string) ([]object.Object, error) {
	if len(s.Sources) > 0 {
		names := make([]string, len(s.Sources))
		for i, n := range s.Sources {
			if !validSourceName(n) {
				return nil, fmt.Errorf("whois: invalid source name %q", n)
			}
			names[i] = strings.ToUpper(n)
		}
		q = "-s " + strings.Join(names, ",") + " " + q
	}
	data, err := s.query(ctx, q)
	if err != nil {
		return nil, err
	}
	text, serr := scanResponse(data)
	if serr != nil {
		return nil, serr
	}
	var out []object.Object
	for raw, diags := range rpsl.Parse(bytes.NewReader(text)) {
		// An object over the stream's size cap comes back empty; it exists,
		// and reading it as absent would shrink an expansion silently.
		for _, d := range diags {
			if d.Rule == "rpsl/object-too-large" {
				return nil, fmt.Errorf("whois: %s: an object in the response is too large: %s", q, d.Message)
			}
		}
		// Decode diagnostics are intentionally dropped: a server object we can't
		// fully decode yields a zero/partial object that simply fails the callers'
		// type switches, which is the desired graceful degradation here. The
		// mntner check (resolve.ClaimAllowed) reads the lossless Raw object's
		// member-of and mnt-by attributes, so a partial decode does not admit a
		// member that would otherwise be filtered out.
		o, _ := object.Decode(raw)
		out = append(out, o)
	}
	return out, nil
}

// query sends one query line and reads the full response until the server closes.
func (s *Source) query(ctx context.Context, q string) ([]byte, error) {
	ctx, cancel := netconn.WithTimeout(ctx, s.timeout())
	defer cancel()
	conn, err := s.dial(ctx)
	if err != nil {
		return nil, netconn.Err(ctx, err)
	}
	defer conn.Close()
	release := netconn.Bind(ctx, conn, 0)
	defer release()
	if _, err := io.WriteString(conn, q+"\n"); err != nil {
		return nil, netconn.Err(ctx, err)
	}
	// Bound the read: read up to max+1 and reject if the server tried to send
	// more, rather than letting io.ReadAll grow without limit.
	max := s.maxResponse()
	r := io.Reader(conn)
	if max < math.MaxInt64 {
		r = io.LimitReader(conn, max+1)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, netconn.Err(ctx, err)
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("whois: response exceeds %d bytes", max)
	}
	return data, nil
}

func (s *Source) dial(ctx context.Context) (net.Conn, error) {
	if s.Dial != nil {
		return s.Dial(ctx)
	}
	var d net.Dialer // ctx carries the query's deadline
	return d.DialContext(ctx, "tcp", s.Addr)
}

// scanResponse blanks out the "%" server-comment lines of a WHOIS response —
// they are not RPSL, and one glued to an object ("%ERROR:101: …" has colons)
// would otherwise parse as its first attribute — and returns the first server
// error, if any: RIPE's "%ERROR:NNN: msg" other than 101 ("no entries found"),
// or IRRd's "%% ERROR: msg" (Code 0). It rewrites data in place, each "%" line
// becoming an empty one, so a response costs no memory beyond its own.
func scanResponse(data []byte) ([]byte, *ServerError) {
	var serr *ServerError
	out := data[:0] // never longer than what has been read, so never ahead of it
	for rest := data; len(rest) > 0; {
		l := rest
		if i := bytes.IndexByte(rest, '\n'); i >= 0 {
			l = rest[:i+1]
		}
		rest = rest[len(l):]
		if l[0] != '%' {
			out = append(out, l...)
			continue
		}
		if msg, ok := bytes.CutPrefix(l, []byte("%ERROR:")); ok && serr == nil {
			codeText, text, _ := bytes.Cut(msg, []byte(":"))
			if code, err := strconv.Atoi(string(codeText)); err == nil && code != 101 {
				serr = &ServerError{Code: code, Message: strings.TrimSpace(string(text))}
			}
		}
		if msg, ok := bytes.CutPrefix(l, []byte("%% ERROR:")); ok && serr == nil {
			serr = &ServerError{Message: strings.TrimSpace(string(msg))}
		}
		out = append(out, '\n')
	}
	return out, serr
}

// validSourceName reports whether n is a plain IRR source name: letters,
// digits, '-' and '_' only, so it cannot carry a flag or another query line.
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

func afiMatches(afi types.AFI, p netip.Prefix) bool {
	switch afi {
	case types.AFIv4:
		return p.Addr().Is4()
	case types.AFIv6:
		return p.Addr().Is6()
	default:
		return true
	}
}
