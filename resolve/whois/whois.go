// Package whois implements a resolve.Source over the RIPE-DB style plain
// WHOIS query protocol (TCP/43), distinct from the IRRd "!" protocol. It fetches
// raw RPSL objects and reuses the library's own parser/decoder, so it resolves
// indirect (mbrs-by-ref) membership itself via inverse queries — unlike the IRRd
// backend, which relies on server-side "!i" expansion. Network access is
// confined to this sub-package; the core resolve engine stays pure.
package whois

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
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
// deadline passing, aborts a pending read at once. A server error other than
// "no entries" (%ERROR:101) is returned as ErrServer, never as an empty result.
type Source struct {
	Addr        string                                      // "whois.ripe.net:43"
	Sources     string                                      // optional "-s SOURCE" filter
	Timeout     time.Duration                               // per-query dial+I/O deadline; 0 = DefaultTimeout, < 0 = none (ctx only)
	MaxResponse int64                                       // per-call response byte cap; 0 = default (maxResponse)
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

// ErrServer is a WHOIS server error reply, e.g. "%ERROR:201: access denied"
// (RIPE's rate limiting). "%ERROR:101: no entries found" is not an error: it
// becomes resolve.ErrNotFound or an empty result.
type ErrServer struct {
	Code    int
	Message string
}

func (e ErrServer) Error() string {
	return fmt.Sprintf("whois: server error %d: %s", e.Code, e.Message)
}

// maxResponse caps a single WHOIS response. A hostile or wedged server could
// otherwise stream unbounded data into io.ReadAll and exhaust memory; we treat
// hitting the cap as an error. 256 MiB dwarfs any real object set.
const maxResponse = 256 << 20

func (s *Source) maxResponse() int64 {
	if s.MaxResponse > 0 {
		return s.MaxResponse
	}
	return maxResponse
}

// GetSet fetches an as-set or route-set object by name.
func (s *Source) GetSet(ctx context.Context, name types.SetName) (object.Set, error) {
	if name.IsZero() {
		return nil, errors.New("whois: empty set name")
	}
	objs, err := s.queryObjects(ctx, "-r -T as-set,route-set "+name.String())
	if err != nil {
		return nil, err
	}
	want := name.Canonical()
	for _, o := range objs {
		if set, ok := o.(object.Set); ok && set.SetName().Canonical() == want {
			return set, nil
		}
	}
	return nil, resolve.ErrNotFound
}

// OriginatedRoutes returns prefixes originated by as, via the inverse "origin"
// query, filtered to afi.
func (s *Source) OriginatedRoutes(ctx context.Context, as types.ASN, afi types.AFI) ([]netip.Prefix, error) {
	objs, err := s.queryObjects(ctx, "-r -i origin -T route,route6 "+as.String())
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

// MembersByRef returns objects that claim member-of set and are maintained by
// one of mntners (or any, if "ANY" is listed), via the inverse "member-of"
// query plus resolve.ClaimAllowed — real indirect-membership resolution.
func (s *Source) MembersByRef(ctx context.Context, set types.SetName, mntners []string) ([]object.Object, error) {
	if set.IsZero() {
		return nil, errors.New("whois: empty set name")
	}
	objs, err := s.queryObjects(ctx, "-r -i member-of -T route,route6,aut-num,as-set "+set.String())
	if err != nil {
		return nil, err
	}
	var out []object.Object
	for _, o := range objs {
		if resolve.ClaimAllowed(o, set, mntners) {
			out = append(out, o)
		}
	}
	return out, nil
}

// queryObjects runs one WHOIS query and decodes every object in the response.
func (s *Source) queryObjects(ctx context.Context, q string) ([]object.Object, error) {
	if s.Sources != "" {
		q = "-s " + sanitizeLine(s.Sources) + " " + q
	}
	data, err := s.query(ctx, q)
	if err != nil {
		return nil, err
	}
	text, serr := scanResponse(data)
	if serr != nil {
		return nil, *serr
	}
	var out []object.Object
	for raw := range rpsl.Parse(bytes.NewReader(text)) {
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
	conn, err := s.dial(ctx)
	if err != nil {
		return nil, netconn.Err(ctx, err)
	}
	defer conn.Close()
	release := netconn.Bind(ctx, conn, s.timeout())
	defer release()
	if _, err := io.WriteString(conn, q+"\n"); err != nil {
		return nil, netconn.Err(ctx, err)
	}
	// Bound the read: read up to max+1 and reject if the server tried to send
	// more, rather than letting io.ReadAll grow without limit.
	max := s.maxResponse()
	data, err := io.ReadAll(io.LimitReader(conn, max+1))
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
	d := net.Dialer{Timeout: s.timeout()}
	return d.DialContext(ctx, "tcp", s.Addr)
}

// scanResponse blanks out the RIPE-style "%" server-comment lines of a WHOIS
// response — they are not RPSL, and one glued to an object ("%ERROR:101: …"
// has colons) would otherwise parse as its first attribute — and returns the
// first %ERROR other than 101 ("no entries found"), if any.
func scanResponse(data []byte) ([]byte, *ErrServer) {
	var serr *ErrServer
	lines := bytes.SplitAfter(data, []byte("\n"))
	for i, l := range lines {
		if len(l) == 0 || l[0] != '%' {
			continue
		}
		if rest, ok := bytes.CutPrefix(l, []byte("%ERROR:")); ok && serr == nil {
			codeText, msg, _ := bytes.Cut(rest, []byte(":"))
			if code, err := strconv.Atoi(string(codeText)); err == nil && code != 101 {
				serr = &ErrServer{Code: code, Message: strings.TrimSpace(string(msg))}
			}
		}
		lines[i] = []byte("\n")
	}
	return bytes.Join(lines, nil), serr
}

// sanitizeLine strips control characters from a value interpolated into the
// single-line WHOIS query, so a stray newline in caller-supplied config (e.g.
// Sources) cannot inject an extra query line.
func sanitizeLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r < ' ' {
			return -1
		}
		return r
	}, s)
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
