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
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	rpsl "github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

// Source is a resolve.Source backed by a plain WHOIS server (whois.ripe.net,
// whois.radb.net, …). Each query uses one connection: the query is sent, the
// full response is read until the server closes, and objects are parsed with the
// library's own stack.
type Source struct {
	Addr        string                                      // "whois.ripe.net:43"
	Sources     string                                      // optional "-s SOURCE" filter
	Timeout     time.Duration                               // per-call dial+I/O deadline; 0 = none
	MaxResponse int64                                       // per-call response byte cap; 0 = default (maxResponse)
	Dial        func(ctx context.Context) (net.Conn, error) // override transport in tests; nil = net.Dialer
}

var _ resolve.Source = (*Source)(nil)

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
// query plus the mntner check — real indirect-membership resolution.
func (s *Source) MembersByRef(ctx context.Context, set types.SetName, mntners []string) ([]object.Object, error) {
	objs, err := s.queryObjects(ctx, "-r -i member-of -T route,route6,aut-num,as-set "+set.String())
	if err != nil {
		return nil, err
	}
	allow := make(map[string]bool, len(mntners))
	any := false
	for _, m := range mntners {
		m = strings.ToLower(strings.TrimSpace(m))
		if m == "any" {
			any = true
		}
		allow[m] = true
	}
	var out []object.Object
	for _, o := range objs {
		if any || maintainedBy(o, allow) {
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
	var out []object.Object
	for raw := range rpsl.Parse(bytes.NewReader(data)) {
		// Decode diagnostics are intentionally dropped: a server object we can't
		// fully decode yields a zero/partial object that simply fails the callers'
		// type switches, which is the desired graceful degradation here.
		o, _ := object.Decode(raw)
		out = append(out, o)
	}
	return out, nil
}

// query sends one query line and reads the full response until the server closes.
func (s *Source) query(ctx context.Context, q string) ([]byte, error) {
	conn, err := s.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if s.Timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(s.Timeout))
	}
	if _, err := io.WriteString(conn, q+"\n"); err != nil {
		return nil, err
	}
	// Bound the read: read up to max+1 and reject if the server tried to send
	// more, rather than letting io.ReadAll grow without limit.
	max := s.maxResponse()
	data, err := io.ReadAll(io.LimitReader(conn, max+1))
	if err != nil {
		return nil, err
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
	d := net.Dialer{Timeout: s.Timeout}
	return d.DialContext(ctx, "tcp", s.Addr)
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

// maintainedBy reports whether any of the object's mnt-by values is allowed.
func maintainedBy(o object.Object, allow map[string]bool) bool {
	for _, a := range o.Raw().GetAll("mnt-by") {
		if allow[strings.ToLower(strings.TrimSpace(a.Value))] {
			return true
		}
	}
	return false
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
