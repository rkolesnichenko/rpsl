// Package backend opens the Source a command line describes — an IRRd
// server, a whois server, or dump files — for rpslq and rpslconf.
package backend

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/irrd"
	"github.com/rkolesnichenko/rpsl/resolve/rpki"
	"github.com/rkolesnichenko/rpsl/resolve/whois"
)

// Options describes the backend a command line asks for: a live server (Host,
// with Whois choosing its protocol) or offline Dumps, never both.
type Options struct {
	Host       string     // host or host:port; port 43 when absent
	Sources    string     // comma-separated registries, in precedence order
	Whois      bool       // query Host over whois rather than IRRd's protocol
	Dumps      []string   // dump files, read in order (gzip or plain)
	Conns      int        // IRRd queries in flight on one connection
	SrcMembers bool       // over an IRRd server, also fetch each set whole for its src-members:
	VRPs       *rpki.VRPs // with Dumps, held as pseudo route objects of the registry RPKI
	KeepPolicy bool       // dumps: keep aut-nums and inet-rtrs, so Src serves policy too
}

// Backend is the source Options describes: the default one, by Options'
// Sources precedence, and the same backend restricted to one registry, for
// bgpq4's SOURCE::OBJECT.
type Backend struct {
	// Src is the source across every registry in Options.Sources' precedence
	// (or, for a dump with none given, every registry the dumps held).
	Src resolve.PolicySource

	// Restrict returns Src scoped to one registry alone, as SOURCE::OBJECT asks.
	Restrict func(registry string) resolve.PolicySource

	// Close releases the backend's connections, if any; dumps need none.
	Close func()
}

// Open builds the Backend o describes. With Dumps and VRPs both set, the dump
// backend also holds VRPs' pseudo route objects, as the registry RPKI.
// SrcMembers sets irrd.Source.SrcMembers on every IRRd connection Open opens.
func Open(o Options) (*Backend, error) {
	var prio []string
	for _, s := range strings.Split(o.Sources, ",") {
		if s = strings.TrimSpace(s); s != "" {
			prio = append(prio, strings.ToUpper(s))
		}
	}
	if len(o.Dumps) > 0 {
		l := &resolve.DumpLoader{Sources: prio, KeepPolicy: o.KeepPolicy}
		for _, name := range o.Dumps {
			if err := ReadInput(name, l.Read); err != nil {
				return nil, err
			}
		}
		if o.VRPs != nil {
			o.VRPs.AddTo(l.Corpus())
		}
		// Sources chooses the registries, as it does for a server ("!s"): only
		// those, in that order; without it, every registry in the dumps.
		var all *resolve.MemSource
		if len(prio) > 0 {
			all = l.SourceOf(prio...)
		} else {
			all = l.Source()
		}
		return &Backend{
			Src:      all,
			Restrict: func(reg string) resolve.PolicySource { return l.SourceOf(reg) },
			Close:    func() {},
		}, nil
	}
	host := o.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "43")
	}
	if o.Whois {
		return &Backend{
			Src:      &whois.Source{Addr: host, Sources: prio},
			Restrict: func(reg string) resolve.PolicySource { return &whois.Source{Addr: host, Sources: []string{reg}} },
			Close:    func() {},
		}, nil
	}
	// One connection, its queries pipelined, as bgpq4 queries an IRRd; a
	// registry-restricted source is a connection of its own.
	all := []*irrd.Source{{Addr: host, Sources: prio, Pipeline: o.Conns, MaxConns: 1, SrcMembers: o.SrcMembers}}
	return &Backend{
		Src: all[0],
		Restrict: func(reg string) resolve.PolicySource {
			s := &irrd.Source{Addr: host, Sources: []string{reg}, Pipeline: o.Conns, MaxConns: 1, SrcMembers: o.SrcMembers}
			all = append(all, s)
			return s
		},
		Close: func() {
			for _, s := range all {
				s.Close()
			}
		},
	}, nil
}

// ReadInput reads a file named on the command line — a dump, VRPs, SLURM —
// through gzip when it is gzipped, naming it in any error but opening's.
func ReadInput(name string, fn func(io.Reader) error) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	r, err := maybeGzip(f)
	if err == nil {
		err = fn(r)
	}
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

// maybeGzip reads r through gzip when it starts with gzip's magic bytes.
func maybeGzip(r io.Reader) (io.Reader, error) {
	br := bufio.NewReader(r)
	if magic, err := br.Peek(2); err == nil && magic[0] == 0x1f && magic[1] == 0x8b {
		return gzip.NewReader(br)
	}
	return br, nil
}
