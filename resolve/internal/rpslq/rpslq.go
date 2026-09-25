// Package rpslq is the rpslq command: bgpq4's job — a prefix or AS list for a
// router, from IRR data — done by this library's expansion engine. It lives
// apart from its main package so the tests that hold it to bgpq4's output can
// run it in process.
package rpslq

import (
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/internal/filtergen"
	"github.com/rkolesnichenko/rpsl/resolve/irrd"
	"github.com/rkolesnichenko/rpsl/resolve/whois"
	"github.com/rkolesnichenko/rpsl/types"
)

// Exit codes: 0 a list was written, 1 the expansion failed (a set not found,
// a limit, a server), 2 the request cannot be served as asked.
const (
	exitOK    = 0
	exitFail  = 1
	exitUsage = 2
)

const usage = `usage: rpslq [flags] OBJECT ...

Writes a router prefix list (or, with -t, an AS list) for the as-sets,
route-sets and AS numbers given, expanding them with the rpsl engine. Flags
follow bgpq4's where they mean the same, and the output is bgpq4's, line for
line.

Source (IRRd by default):
  -h host[:port]  IRRd server (default rr.ntt.net:43)
  -S sources      IRR source priority, comma separated (e.g. RADB,RIPE)
  -whois          query the server over whois rather than IRRd's protocol
  -dump file      expand offline from an IRR dump (gzip or plain); repeatable

What:
  -4 / -6         IPv4 (default) or IPv6 prefixes
  -t              AS numbers instead of prefixes (JSON, BIRD or plain)
  -m len          drop prefixes longer than len
  -p              keep special-purpose AS numbers (bgpq4 drops 23456,
                  64496-65551 and 4200000000 and above unless -p)
  -ranges         write RPSL ranges (le/ge) rather than every prefix they hold
  -a              let the IRRd server expand as-sets (IRRd 4's !a), as plain
                  bgpq4 does: one query rather than one per AS, but the
                  server's rules rather than the engine's (its recursion, no
                  -L, special AS numbers kept)

Format (Cisco IOS by default):
  -j JSON  -b BIRD  -J Junos  -P plain (RPSL notation, one per line)
  -l name         list name (default NN)

Limits:
  -L depth        nesting depth (default 32)
  -c n            queries in flight (default 1024): pipelined on one IRRd
                  connection, as bgpq4 does; at most 4 connections over whois
  -timeout d      give up after d (default 5m)
`

// dumps collects -dump flags.
type dumps []string

func (d *dumps) String() string     { return strings.Join(*d, ",") }
func (d *dumps) Set(v string) error { *d = append(*d, v); return nil }

// Run runs rpslq with args, writing the list to stdout and warnings and errors
// to stderr, and returns the exit code.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rpslq", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	host := fs.String("h", "rr.ntt.net:43", "")
	sources := fs.String("S", "", "")
	useWhois := fs.Bool("whois", false, "")
	var files dumps
	fs.Var(&files, "dump", "")
	fs.Bool("4", false, "")
	v6 := fs.Bool("6", false, "")
	asList := fs.Bool("t", false, "")
	maxLen := fs.Int("m", 0, "")
	special := fs.Bool("p", false, "")
	asRanges := fs.Bool("ranges", false, "")
	serverSide := fs.Bool("a", false, "")
	jsonOut := fs.Bool("j", false, "")
	birdOut := fs.Bool("b", false, "")
	junosOut := fs.Bool("J", false, "")
	plainOut := fs.Bool("P", false, "")
	name := fs.String("l", "NN", "")
	depth := fs.Int("L", 0, "")
	conc := fs.Int("c", 1024, "")
	timeout := fs.Duration("timeout", 5*time.Minute, "")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return exitUsage
	}
	format := filtergen.Cisco
	chosen := 0
	for _, f := range []struct {
		on  bool
		fmt filtergen.Format
	}{{*jsonOut, filtergen.JSON}, {*birdOut, filtergen.BIRD}, {*junosOut, filtergen.Junos}, {*plainOut, filtergen.Plain}} {
		if f.on {
			format, chosen = f.fmt, chosen+1
		}
	}
	if chosen > 1 {
		fmt.Fprintln(stderr, "rpslq: choose one of -j, -b, -J and -P")
		return exitUsage
	}
	if *asList && format != filtergen.JSON && format != filtergen.BIRD && format != filtergen.Plain {
		fmt.Fprintf(stderr, "rpslq: -t writes an AS list in JSON (-j), BIRD (-b) or plain (-P), not %s\n", format)
		return exitUsage
	}

	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	if *conc < 1 {
		*conc = 1
	}
	if *serverSide && (*useWhois || len(files) > 0) {
		fmt.Fprintln(stderr, "rpslq: -a asks an IRRd server to expand as-sets, so it needs IRRd, not -whois or -dump")
		return exitUsage
	}
	src, closeSrc, err := source(*host, *sources, *useWhois, files, *conc)
	if err != nil {
		fmt.Fprintln(stderr, "rpslq:", err)
		return exitFail
	}
	defer closeSrc()
	if *useWhois && *conc > maxWhoisConns {
		*conc = maxWhoisConns // whois opens a connection per query
	}

	afi := types.AFIv4
	if *v6 {
		afi = types.AFIv6
	}
	var aset func(context.Context, types.SetName, types.AFI) ([]netip.Prefix, error)
	if ir, ok := src.(*irrd.Source); ok && *serverSide {
		ir.MaxResponse = 256 << 20 // IRRd warns "!a" answers reach 10-20 MB
		aset = ir.ASSetPrefixes
	}
	q := query{
		aset:    aset,
		e:       &resolve.Expander{Src: src, AFI: afi, MaxDepth: *depth, Concurrency: *conc},
		src:     src,
		afi:     afi,
		special: *special,
		conc:    *conc,
		stderr:  stderr,
	}
	if *asList {
		asns, code := q.asns(ctx, fs.Args())
		if code != exitOK {
			return code
		}
		if err := filtergen.WriteASList(stdout, format, *name, asns); err != nil {
			fmt.Fprintln(stderr, "rpslq:", err)
			return exitUsage
		}
		return exitOK
	}
	ranges, code := q.prefixes(ctx, fs.Args())
	if code != exitOK {
		return code
	}
	if *maxLen > 0 {
		ranges = filtergen.MaxLen(ranges, *maxLen)
	}
	if !*asRanges {
		if ranges, err = filtergen.Enumerate(ranges, 1<<20); err != nil {
			fmt.Fprintf(stderr, "rpslq: %v; use -ranges for the RPSL ranges themselves\n", err)
			return exitFail
		}
	}
	if err := filtergen.Write(stdout, format, filtergen.List{Name: *name, V6: *v6, Ranges: ranges}); err != nil {
		if errors.Is(err, filtergen.ErrUnsupported) {
			fmt.Fprintf(stderr, "rpslq: %v; drop -ranges, or use -j, -b or the Cisco format\n", err)
			return exitUsage
		}
		fmt.Fprintln(stderr, "rpslq:", err)
		return exitFail
	}
	return exitOK
}

// source builds the Source the flags describe, and a function that releases it.
func source(host, sources string, useWhois bool, files []string, conns int) (resolve.Source, func(), error) {
	var prio []string
	for _, s := range strings.Split(sources, ",") {
		if s = strings.TrimSpace(s); s != "" {
			prio = append(prio, strings.ToUpper(s))
		}
	}
	if len(files) > 0 {
		var rs []io.Reader
		var closers []io.Closer
		closeAll := func() {
			for _, c := range closers {
				c.Close()
			}
		}
		for _, name := range files {
			f, err := os.Open(name)
			if err != nil {
				closeAll()
				return nil, nil, err
			}
			closers = append(closers, f)
			r, err := maybeGzip(f)
			if err != nil {
				closeAll()
				return nil, nil, fmt.Errorf("%s: %w", name, err)
			}
			rs = append(rs, r)
		}
		defer closeAll()
		src, err := resolve.LoadDumps(rs, prio...)
		if err != nil {
			return nil, nil, err
		}
		return src, func() {}, nil
	}
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "43")
	}
	if useWhois {
		return &whois.Source{Addr: host, Sources: prio}, func() {}, nil
	}
	// One connection, its queries pipelined, as bgpq4 queries an IRRd.
	s := &irrd.Source{Addr: host, Sources: prio, Pipeline: conns, MaxConns: 1}
	return s, func() { s.Close() }, nil
}

// maxWhoisConns caps the connections rpslq opens over whois, which has no
// pipelining: each query is a connection of its own.
const maxWhoisConns = 4

// maybeGzip reads r through gzip when it starts with gzip's magic bytes.
func maybeGzip(r io.Reader) (io.Reader, error) {
	br := bufio.NewReader(r)
	if magic, err := br.Peek(2); err == nil && magic[0] == 0x1f && magic[1] == 0x8b {
		return gzip.NewReader(br)
	}
	return br, nil
}

// query expands the objects a command line names.
type query struct {
	aset    func(context.Context, types.SetName, types.AFI) ([]netip.Prefix, error) // -a: the server's expansion
	e       *resolve.Expander
	src     resolve.Source
	afi     types.AFI
	special bool // keep special-purpose AS numbers
	conc    int
	stderr  io.Writer
}

// specialAS reports the AS numbers bgpq4 drops unless given -p: AS_TRANS,
// the documentation and private ranges up to 65551, and 4200000000 and above.
func specialAS(a types.ASN) bool {
	return a == 23456 || a >= 4200000000 || (a >= 64496 && a <= 65551)
}

// object is one command-line object: an AS number or a set name.
type object struct {
	text string
	as   types.ASN
	set  types.SetName
	isAS bool
}

func parseObjects(args []string) ([]object, error) {
	var out []object
	for _, a := range args {
		if as, err := types.ParseASN(a); err == nil {
			out = append(out, object{text: a, as: as, isAS: true})
			continue
		}
		n, err := types.ParseSetName(a)
		if err != nil {
			return nil, fmt.Errorf("%q is neither an AS number nor a set name", a)
		}
		if c := n.Class(); c != types.ClassAsSet && c != types.ClassRouteSet {
			return nil, fmt.Errorf("%s is a %s; rpslq expands as-sets, route-sets and AS numbers", n, c)
		}
		out = append(out, object{text: a, set: n})
	}
	return out, nil
}

// fail reports an expansion error and returns its exit code.
func (q *query) fail(what string, err error) int {
	fmt.Fprintf(q.stderr, "rpslq: %s: %v\n", what, err)
	var anySet *resolve.AnySetError
	if errors.As(err, &anySet) {
		return exitUsage
	}
	return exitFail
}

// warnMissing reports the nested sets an expansion did not find, as bgpq4
// reports what it cannot use.
func (q *query) warnMissing(top string, missing []types.SetName) {
	for _, m := range missing {
		fmt.Fprintf(q.stderr, "rpslq: %s: %s not found, skipped\n", top, m)
	}
}

// asns expands the objects to AS numbers.
func (q *query) asns(ctx context.Context, args []string) ([]types.ASN, int) {
	objs, err := parseObjects(args)
	if err != nil {
		fmt.Fprintln(q.stderr, "rpslq:", err)
		return nil, exitUsage
	}
	set := map[types.ASN]bool{}
	for _, o := range objs {
		if o.isAS {
			set[o.as] = true
			continue
		}
		if o.set.Class() != types.ClassAsSet {
			fmt.Fprintf(q.stderr, "rpslq: -t takes as-sets and AS numbers, and %s is a route-set\n", o.set)
			return nil, exitUsage
		}
		got, err := q.e.ExpandAS(ctx, o.set)
		if err != nil {
			return nil, q.fail(o.text, err)
		}
		q.warnMissing(o.text, got.Missing())
		for _, a := range got.List() {
			set[a] = true
		}
	}
	var out []types.ASN
	for a := range set {
		if q.special || !specialAS(a) {
			out = append(out, a)
		}
	}
	return out, exitOK
}

// prefixes expands the objects to prefix ranges. A route-set is the engine's
// ExpandPrefixRanges. An as-set, like an AS number, is the routes its AS
// numbers originate, bgpq4's way: its members first, special-purpose ones
// dropped, then each one's routes.
func (q *query) prefixes(ctx context.Context, args []string) ([]types.PrefixRange, int) {
	objs, err := parseObjects(args)
	if err != nil {
		fmt.Fprintln(q.stderr, "rpslq:", err)
		return nil, exitUsage
	}
	out := map[types.PrefixRange]bool{}
	asns := map[types.ASN]bool{}
	for _, o := range objs {
		switch {
		case o.isAS:
			asns[o.as] = true
		case o.set.Class() == types.ClassAsSet && q.aset != nil:
			// The server's expansion, taken as it is: its recursion, and its
			// routes of every member, special-purpose ones included.
			got, err := q.aset(ctx, o.set, q.afi)
			if err != nil {
				if errors.Is(err, irrd.ErrQueryRefused) {
					return nil, q.fail(o.text, fmt.Errorf("%w (the server has no \"!a\"; drop -a)", err))
				}
				return nil, q.fail(o.text, err)
			}
			for _, p := range got {
				p = p.Masked()
				if r, ok := types.NewPrefixRange(p, p.Bits(), p.Bits()); ok {
					out[r] = true
				}
			}
		case o.set.Class() == types.ClassAsSet:
			got, err := q.e.ExpandAS(ctx, o.set)
			if err != nil {
				return nil, q.fail(o.text, err)
			}
			q.warnMissing(o.text, got.Missing())
			for _, a := range got.List() {
				asns[a] = true
			}
		default:
			got, err := q.e.ExpandPrefixRanges(ctx, o.set)
			if err != nil {
				return nil, q.fail(o.text, err)
			}
			q.warnMissing(o.text, got.Missing())
			for _, r := range got.List() {
				out[r] = true
			}
		}
	}
	var order []types.ASN
	for a := range asns {
		if q.special || !specialAS(a) {
			order = append(order, a)
		}
	}
	sort.Slice(order, func(i, j int) bool { return order[i] < order[j] })
	routes, err := q.routes(ctx, order)
	if err != nil {
		return nil, q.fail("routes", err)
	}
	for _, p := range routes {
		if r, ok := types.NewPrefixRange(p, p.Bits(), p.Bits()); ok {
			out[r] = true
		}
	}
	list := make([]types.PrefixRange, 0, len(out))
	for r := range out {
		if r.Prefix().Addr().Is6() == (q.afi == types.AFIv6) {
			list = append(list, r)
		}
	}
	return list, exitOK
}

// routes fetches the routes the ASes originate, up to conc at a time.
func (q *query) routes(ctx context.Context, asns []types.ASN) ([]netip.Prefix, error) {
	n := q.conc
	if n < 1 {
		n = 1
	}
	results := make([][]netip.Prefix, len(asns))
	errs := make([]error, len(asns))
	sem := make(chan struct{}, n)
	var wg sync.WaitGroup
	for i, a := range asns {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, a types.ASN) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i], errs[i] = q.src.OriginatedRoutes(ctx, a, q.afi)
		}(i, a)
	}
	wg.Wait()
	var out []netip.Prefix
	for i := range asns {
		if errs[i] != nil {
			return nil, fmt.Errorf("%s: %w", asns[i], errs[i])
		}
		for _, p := range results[i] {
			out = append(out, p.Masked())
		}
	}
	return out, nil
}
