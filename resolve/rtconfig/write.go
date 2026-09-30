package rtconfig

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"

	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/types"
)

// vendorWriter renders plans in one vendor's syntax. Its methods write to a
// buffer that is copied to the caller's writer only once everything has
// compiled.
type vendorWriter interface {
	policy(g *Generator, b *strings.Builder, name string, pl plan)
	attach(g *Generator, b *strings.Builder, name string, s peval.Session, export bool)
	prefixList(g *Generator, b *strings.Builder, afi types.AFI, pc prefixCond) string
	pathList(g *Generator, b *strings.Builder, pc pathCond) string
	defaults(g *Generator, b *strings.Builder, s peval.Session, d peval.Defaults) error
	networks(g *Generator, b *strings.Builder, prefixes []netip.Prefix) error
}

var errNoVendor = errors.New("rtconfig: Generator.Vendor is not set")

func (g *Generator) writer() (vendorWriter, error) {
	switch g.Vendor {
	case IOS:
		return iosWriter{}, nil
	case Junos:
		return junosWriter{}, nil
	case IOSXR:
		return xrWriter{}, nil
	case BIRD2:
		return birdWriter{}, nil
	}
	if g.Vendor == 0 {
		return nil, errNoVendor
	}
	return nil, fmt.Errorf("rtconfig: no writer for %v yet", g.Vendor)
}

// WriteImport writes the import policy p evaluates for session s — a
// route-map, policy-statement, route-policy or filter, with the lists it
// uses — and, when s names the peer's router, attaches it to that neighbour.
// A construct the vendor cannot express is an *UnsupportedError, and then
// nothing is written.
func (g *Generator) WriteImport(w io.Writer, s peval.Session, p peval.Policy) error {
	return g.writeSession(w, s, p, false)
}

// WriteExport writes the export policy p evaluates for session s, as
// WriteImport does.
func (g *Generator) WriteExport(w io.Writer, s peval.Session, p peval.Policy) error {
	return g.writeSession(w, s, p, true)
}

func (g *Generator) writeSession(w io.Writer, s peval.Session, p peval.Policy, export bool) error {
	vw, err := g.writer()
	if err != nil {
		return err
	}
	pl, err := g.compile(s, p)
	if err != nil {
		return err
	}
	lists := 0
	for _, e := range pl.entries {
		if len(e.paths) > 0 {
			lists++
		}
	}
	if err := g.checkPathLists(lists); err != nil {
		return err
	}
	name, err := g.nextMapName(s.Peer)
	if err != nil {
		return err
	}
	var b strings.Builder
	vw.policy(g, &b, name, pl)
	if s.PeerRtr.IsValid() {
		vw.attach(g, &b, name, s, export)
	}
	_, err = io.WriteString(w, b.String())
	return err
}

// nextMapName names the next route-map or policy: the vendor's pattern with
// the peer AS and the count of maps written. A name already written is an
// error (ruling R22): a pattern with fewer than two %d names two maps alike —
// import and export for one peer, or two sessions — and the second would
// replace the first, IOS's "no route-map" before it included, so the first
// neighbour would silently take the second's policy.
func (g *Generator) nextMapName(peer types.ASN) (string, error) {
	n := g.names()
	pattern := n.MapName
	if g.Vendor == Junos {
		pattern = n.JunosPolicyName
	}
	name := expand(pattern, int(peer), g.maps+1)
	if g.mapNames[name] {
		return "", fmt.Errorf("rtconfig: a map named %q is already written (name pattern %q)", name, pattern)
	}
	if g.mapNames == nil {
		g.mapNames = map[string]bool{}
	}
	g.maps++
	g.mapNames[name] = true
	return name, nil
}

// maxIOSPathList is the highest number an IOS as-path access-list takes.
const maxIOSPathList = 500

// checkPathLists refuses, before anything is written, a write that would
// number n more as-path access-lists past the ones IOS has (ruling R22): IOS
// rejects "ip as-path access-list 501" on load. The other vendors name their
// AS-path lists and have no such limit.
func (g *Generator) checkPathLists(n int) error {
	if g.Vendor != IOS || n == 0 {
		return nil
	}
	first := g.names().ASPathACLNo + g.pathLists
	if first < 1 || first+n-1 > maxIOSPathList {
		return fmt.Errorf("rtconfig: cisco numbers as-path access-lists 1 to %d; this needs %d to %d (aspath_acl_no %d)",
			maxIOSPathList, first, first+n-1, g.names().ASPathACLNo)
	}
	return nil
}

// WriteDefault writes the default routes the defaults d evaluates for s, as
// rtconfig's "default" command does; see the capability table for vendors.
func (g *Generator) WriteDefault(w io.Writer, s peval.Session, d peval.Defaults) error {
	vw, err := g.writer()
	if err != nil {
		return err
	}
	var b strings.Builder
	if err := vw.defaults(g, &b, s, d); err != nil {
		return err
	}
	_, err = io.WriteString(w, b.String())
	return err
}

// WritePrefixList writes a prefix list of afi for f, rtconfig's access_list:
// f must be one conjunct of prefix ranges (with negated ones), or none.
func (g *Generator) WritePrefixList(w io.Writer, f resolve.NormalFilter, afi types.AFI) error {
	vw, err := g.writer()
	if err != nil {
		return err
	}
	var pc prefixCond
	switch len(f.Conjuncts) {
	case 0:
	case 1:
		c := f.Conjuncts[0]
		if len(c.Paths) > 0 || len(c.Communities) > 0 {
			return unsupported(g.Vendor, CauseListShape, f.String())
		}
		pc = prefixCond{deny: c.NotPrefixes.List(), any: c.AnyPrefix()}
		if !pc.any {
			pc.permit = c.Prefixes.List()
		}
		for _, r := range append(append([]types.PrefixRange(nil), pc.deny...), pc.permit...) {
			if r.Prefix().Addr().Is4() != (afi == types.AFIv4) {
				return unsupported(g.Vendor, CauseListShape, f.String())
			}
		}
	default:
		return unsupported(g.Vendor, CauseListShape, f.String())
	}
	var b strings.Builder
	vw.prefixList(g, &b, afi, pc)
	_, err = io.WriteString(w, b.String())
	return err
}

// WriteASPathList writes an AS-path list for m, rtconfig's aspath_access_list.
func (g *Generator) WriteASPathList(w io.Writer, m resolve.PathMatch) error {
	vw, err := g.writer()
	if err != nil {
		return err
	}
	re, err := g.translatePath(m, m.RE.String())
	if err != nil {
		return err
	}
	if err := g.checkPathLists(1); err != nil {
		return err
	}
	var b strings.Builder
	vw.pathList(g, &b, pathCond{negated: m.Negated, re: re})
	_, err = io.WriteString(w, b.String())
	return err
}

// WriteNetworks writes the network statements that originate prefixes, as
// rtconfig's networks and v6networks commands do. See the capability table
// for vendors; a vendor's networks method decides whether it can express
// them, as its defaults method decides for WriteDefault.
func (g *Generator) WriteNetworks(w io.Writer, prefixes []netip.Prefix) error {
	vw, err := g.writer()
	if err != nil {
		return err
	}
	var b strings.Builder
	if err := vw.networks(g, &b, prefixes); err != nil {
		return err
	}
	_, err = io.WriteString(w, b.String())
	return err
}

// sessionWriter is a vendorWriter whose attachments are collected and written
// together, by WriteSessions: BIRD 2's.
type sessionWriter interface {
	sessions(g *Generator, b *strings.Builder)
}

// WriteSessions writes the BGP sessions that WriteImport and WriteExport
// attached policies to, for a vendor whose configuration names a neighbour's
// policies in one place: BIRD 2, whose configuration does not merge two
// blocks for one protocol, gets one "protocol bgp" per neighbour naming its
// import and export filters. A caller writing a whole configuration calls it
// last. For the other vendors each Write call has already written its
// attachment, and WriteSessions writes nothing.
func (g *Generator) WriteSessions(w io.Writer) error {
	vw, err := g.writer()
	if err != nil {
		return err
	}
	sw, ok := vw.(sessionWriter)
	if !ok {
		return nil
	}
	var b strings.Builder
	sw.sessions(g, &b)
	_, err = io.WriteString(w, b.String())
	return err
}
