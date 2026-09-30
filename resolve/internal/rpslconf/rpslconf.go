// Package rpslconf is the rpslconf command: router configuration from the
// routing policy in IRR data, as IRRToolSet's rtconfig writes it, on the
// rpsl engine. This release has its peval mode (-e): a filter evaluated to
// its normal form. Template mode, reading rtconfig's @RtConfig commands,
// arrives with the configuration printers.
package rpslconf

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/internal/backend"
	"github.com/rkolesnichenko/rpsl/types"
)

// listFlag is a repeatable string flag.
type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(s string) error { *l = append(*l, s); return nil }

// Run runs rpslconf with the given arguments and returns its exit code: 0 on
// success, 1 when the evaluation fails, 2 for a command line it cannot use.
func Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rpslconf", flag.ContinueOnError)
	fs.SetOutput(stderr)
	host := fs.String("h", "whois.radb.net", "IRR server `host`")
	port := fs.String("p", "43", "IRR server `port`")
	sources := fs.String("s", "", "registries to query, comma-separated, in precedence order (default: the server's)")
	useWhois := fs.Bool("whois", false, "query with the whois protocol instead of IRRd's")
	var dumps listFlag
	fs.Var(&dumps, "dump", "read objects from a dump `file` instead of a server (repeatable; gzip is read too)")
	expr := fs.String("e", "", "peval mode: print the normal form of this (mp-)`filter`")
	peerFlag := fs.String("peer", "", "peval mode: the `AS` PeerAS denotes")
	timeout := fs.Duration("timeout", 60*time.Second, "give up after this long")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *expr == "" {
		fmt.Fprintln(stderr, "rpslconf: template mode arrives with the configuration printers; use -e <filter> for peval mode")
		return 2
	}
	var peer types.ASN
	if *peerFlag != "" {
		a, err := types.ParseASN(*peerFlag)
		if err != nil {
			fmt.Fprintf(stderr, "rpslconf: -peer: %v\n", err)
			return 2
		}
		peer = a
	}
	afis, f, diags := policy.ParseMPFilter(*expr)
	failed := false
	for _, d := range diags {
		fmt.Fprintf(stderr, "rpslconf: %v\n", d)
		failed = failed || d.Severity >= ast.Error
	}
	if failed {
		return 1
	}
	b, err := backend.Open(backend.Options{Host: net.JoinHostPort(*host, *port), Sources: *sources,
		Whois: *useWhois, Dumps: dumps, Conns: 8})
	if err != nil {
		fmt.Fprintf(stderr, "rpslconf: %v\n", err)
		return 1
	}
	defer b.Close()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	e := resolve.Expander{Src: b.Src, AFI: afiOf(afis), Peer: peer}
	nf, err := e.NormalizeFilter(ctx, f)
	if err != nil {
		if errors.Is(err, resolve.ErrUnboundPeer) {
			err = fmt.Errorf("%w (name the peer with -peer)", err)
		}
		fmt.Fprintf(stderr, "rpslconf: %v\n", err)
		return 1
	}
	for _, m := range nf.Missing() {
		fmt.Fprintf(stderr, "rpslconf: warning: %s not found\n", m)
	}
	fmt.Fprintln(stdout, nf.String())
	return 0
}

// afiOf is the address family an afi list constrains a filter to: IPv4 or
// IPv6 when it names only that one, both otherwise. A SAFI does not
// constrain prefixes (spec §2), so ipv4.multicast is IPv4.
func afiOf(afis []types.AddrFamily) types.AFI {
	v4, v6 := false, false
	for _, a := range afis {
		switch a.AFI {
		case types.AFIv4:
			v4 = true
		case types.AFIv6:
			v6 = true
		default:
			v4, v6 = true, true
		}
	}
	switch {
	case v4 && !v6:
		return types.AFIv4
	case v6 && !v4:
		return types.AFIv6
	}
	return types.AFIAny
}
