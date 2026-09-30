// Package rpslconf is the rpslconf command: router configuration from the
// routing policy in IRR data, as IRRToolSet's rtconfig writes it, on the
// rpsl engine. It has two modes: peval mode (-e), which prints the normal
// form of one filter, and template mode (the default), which reads an
// rtconfig-style template from stdin and copies it to stdout with each
// @RtConfig command replaced by the router configuration it asks for.
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
	"github.com/rkolesnichenko/rpsl/resolve/rtconfig"
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
	host := fs.String("h", "whois.radb.net", "IRR server `host`, or host:port")
	port := fs.String("p", "43", "IRR server `port`, when -h names none")
	sources := fs.String("s", "", "registries to query, comma-separated, in precedence order (default: the server's)")
	useWhois := fs.Bool("whois", false, "query with the whois protocol instead of IRRd's")
	var dumps listFlag
	fs.Var(&dumps, "dump", "read objects from a dump `file` instead of a server (repeatable; gzip is read too)")
	expr := fs.String("e", "", "peval mode: print the normal form of this (mp-)`filter`")
	peerFlag := fs.String("peer", "", "peval mode: the `AS` PeerAS denotes")
	config := fs.String("config", "cisco", "template mode: the configuration `format`: cisco, junos, ciscoxr or bird")
	timeout := fs.Duration("timeout", 60*time.Second, "give up after this long")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "rpslconf: unexpected argument %q (the template is read from stdin)\n", fs.Arg(0))
		return 2
	}
	vendor, err := rtconfig.ParseVendor(*config)
	if err != nil {
		fmt.Fprintf(stderr, "rpslconf: -config: %v\n", err)
		return 2
	}
	opts := backend.Options{Host: hostPort(*host, *port), Sources: *sources, Whois: *useWhois, Dumps: dumps, Conns: 8}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	if *expr != "" {
		return pevalMode(ctx, opts, *expr, *peerFlag, stdout, stderr)
	}
	if *peerFlag != "" {
		fmt.Fprintln(stderr, "rpslconf: -peer belongs to peval mode (-e)")
		return 2
	}
	opts.KeepPolicy = true // dumps: keep the aut-nums and inet-rtrs templates read
	t := &tmpl{ctx: ctx, opts: opts, g: &rtconfig.Generator{Vendor: vendor}, out: stdout, errw: stderr}
	return t.run(stdin)
}

// pevalMode prints the normal form of expr: -e.
func pevalMode(ctx context.Context, opts backend.Options, expr, peerFlag string, stdout, stderr io.Writer) int {
	var peer types.ASN
	if peerFlag != "" {
		a, err := types.ParseASN(peerFlag)
		if err != nil {
			fmt.Fprintf(stderr, "rpslconf: -peer: %v\n", err)
			return 2
		}
		peer = a
	}
	afis, f, diags := policy.ParseMPFilter(expr)
	failed := false
	for _, d := range diags {
		fmt.Fprintf(stderr, "rpslconf: %v\n", d)
		failed = failed || d.Severity >= ast.Error
	}
	if failed {
		return 1
	}
	b, err := backend.Open(opts)
	if err != nil {
		fmt.Fprintf(stderr, "rpslconf: %v\n", err)
		return 1
	}
	defer b.Close()
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

// hostPort is the server address: host as given when it carries a port of
// its own (host:port, [v6]:port), else host joined with port.
func hostPort(host, port string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, port)
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
