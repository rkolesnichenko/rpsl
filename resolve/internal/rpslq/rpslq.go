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
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime/debug"
	"slices"
	"sort"
	"strconv"
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
// a limit, a server, a prefix bgpq4 also refuses), 2 the request cannot be
// served as asked.
const (
	exitOK    = 0
	exitFail  = 1
	exitUsage = 2
)

const usage = `usage: rpslq [options] OBJECT ... [EXCEPT OBJECT ...]

Writes a router filter — a prefix list, route-filter, as-path list or AS set —
for the as-sets, route-sets, AS numbers and prefixes given, expanding them with
the rpsl engine. The options are bgpq4's, read as bgpq4 reads them (-6Ab,
-lNAME), and so is the output, line for line. After EXCEPT come as-sets,
route-sets and AS numbers every expansion leaves out, route-sets included.
An object written SOURCE::OBJECT (RIPE::AS-FOO) is looked up in that registry
alone, and what it reaches in the default sources (-S), as bgpq4 does.

Vendors (Cisco IOS by default):
  -X Cisco IOS XR   -j JSON        -J Junos           -K MikroTik v6  -K7 v7
  -b BIRD           -B OpenBGPD    -e Arista EOS      -N Nokia SR OS
  -n Nokia MD-CLI   -n2 SR Linux   -U Huawei          -u Huawei XPL
  -F fmt  user format: %n/%r address, %l length, %a/%A lengths allowed,
          %m/%i netmask and inverse, %N list name
  -P      plain: RPSL notation, one entry per line (rpslq's own)

What (a prefix list by default):
  -4 / -6         IPv4 (default) or IPv6
  -E              route-filter (Junos), extended access-list (Cisco, Arista),
                  prefix-set (OpenBGPD), ip-prefix-list (Nokia)
  -z              Junos route-filter-list
  -f AS / -G AS   input / output as-path list for the neighbour AS
  -H AS           Junos as-list
  -t              the AS numbers (JSON, BIRD, OpenBGPD, plain)
  -a AS           OpenBGPD: write "deny from AS" for an empty list

Shape:
  -A              aggregate           -R len  allow more-specifics up to len
  -r len          allow more-specifics from len
  -m len          drop prefixes longer than len
  -l name         list name (default NN)          -s  sequence numbers (IOS)
  -M match        extra Junos route-filter match conditions
  -W n            AS numbers per as-path line (0: unlimited)
  -p              keep special-purpose AS numbers (23456, 64496-65551,
                  4200000000 and above)
  -w              as-path lists: only AS numbers that have routes
  -L depth        levels of sets, the top one counted, as bgpq4 counts them
                  (default 33); where sets nest deeper, bgpq4 leaves the
                  deeper ones out and rpslq fails rather than do so

Source (IRRd by default):
  -h host[:port]  IRRd server (default rr.ntt.net:43)
  -S sources      IRR source priority, comma separated (default $IRRD_SOURCES)
  -T              one query at a time instead of pipelining
  -c n            queries in flight (default 1024)
  --whois         query the server over whois rather than IRRd's protocol
  --dump file     expand offline from an IRR dump (gzip or plain); repeatable
  --server-expand let the IRRd server expand as-sets (IRRd 4's !a), as plain
                  bgpq4 does: one query rather than one per AS, but the
                  server's rules rather than the engine's

Other:
  --ranges        write RPSL ranges as they are rather than every prefix
  --timeout d     give up after d (default 5m)
  -d              trace each question asked of the source, and its answer,
                  to stderr
  -3              accepted for bgpq4's sake (32-bit AS numbers are assumed)
  -v              print the version
`

// config is a command line, read.
type config struct {
	o                 filtergen.Options
	vendorSet         bool
	kindSet           bool
	widthSet          bool
	v4                bool
	aggregate         bool
	refine, refineLow int
	maxLen            int
	host, sources     string
	whois             bool
	dumps             []string
	ranges            bool
	serverSide        bool
	special           bool
	validate          bool
	debug             bool
	depth             int
	conc              int
	pipeline          bool
	timeout           time.Duration
	objects, except   []string
}

// number reads a decimal option argument, as bgpq4's strtoul does, but
// refusing what is not a number rather than reading it as 0.
func number(name, v string) (int, error) {
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0, usagef("-%s wants a number, not %q", name, v)
	}
	return n, nil
}

// asNumber reads an -a, -f, -G or -H argument: an AS number in asplain or
// asdot, as bgpq4's parseasnumber does, with or without "AS".
func asNumber(name, v string) (types.ASN, error) {
	if !strings.HasPrefix(strings.ToUpper(v), "AS") {
		v = "AS" + v
	}
	a, err := types.ParseASN(v)
	if err != nil || a == 0 {
		hint := ""
		if name == "a" {
			hint = " (rpslq's former -a, the server's expansion, is --server-expand)"
		}
		return 0, usagef("-%s wants an AS number, not %q%s", name, strings.TrimPrefix(v, "AS"), hint)
	}
	return a, nil
}

// parse reads a command line into a config, applying bgpq4's rules for what
// goes together.
func parse(args []string) (*config, bool, error) {
	opts, operands, err := getopt(args)
	if err != nil {
		return nil, false, err
	}
	c := &config{host: "rr.ntt.net:43", sources: os.Getenv("IRRD_SOURCES"), conc: 1024, pipeline: true, timeout: 5 * time.Minute}
	c.o.Name = "NN"
	vendor := func(v filtergen.Vendor) error {
		if c.vendorSet {
			return usagef("choose one vendor: -b, -B, -e, -F, -j, -J, -K, -n, -N, -P, -u, -U, -X")
		}
		c.o.Vendor, c.vendorSet = v, true
		return nil
	}
	kind := func(k filtergen.Kind) error {
		if c.kindSet {
			return usagef("-E, -f, -G, -H, -t and -z are mutually exclusive")
		}
		c.o.Kind, c.kindSet = k, true
		return nil
	}
	for _, op := range opts {
		var err error
		switch op.name {
		case "help":
			return nil, true, nil
		case "v":
			return c, false, errVersion
		case "2":
			if !c.vendorSet || c.o.Vendor != filtergen.NokiaMD {
				return nil, false, usagef("-2 can only be used after -n")
			}
			c.o.Vendor = filtergen.NokiaSRL
		case "7":
			if !c.vendorSet || c.o.Vendor != filtergen.MikroTik6 {
				return nil, false, usagef("-7 can only be used after -K")
			}
			c.o.Vendor = filtergen.MikroTik7
		case "d":
			c.debug = true
		case "3":
		case "4":
			if c.o.V6 {
				return nil, false, usagef("-4 and -6 are mutually exclusive")
			}
			c.v4 = true
		case "6":
			if c.v4 {
				return nil, false, usagef("-4 and -6 are mutually exclusive")
			}
			c.o.V6 = true
		case "a":
			c.o.AS, err = asNumber("a", op.arg)
		case "A":
			c.aggregate = true
		case "b":
			err = vendor(filtergen.BIRD)
		case "B":
			err = vendor(filtergen.OpenBGPD)
		case "e":
			err = vendor(filtergen.Arista)
			c.o.Sequence = true
		case "F":
			err = vendor(filtergen.UserFormat)
			c.o.Format = op.arg
		case "j":
			err = vendor(filtergen.JSON)
		case "J":
			err = vendor(filtergen.Junos)
		case "K":
			err = vendor(filtergen.MikroTik6)
		case "N":
			err = vendor(filtergen.Nokia)
		case "n":
			err = vendor(filtergen.NokiaMD)
		case "P":
			err = vendor(filtergen.Plain)
		case "U":
			err = vendor(filtergen.Huawei)
		case "u":
			err = vendor(filtergen.HuaweiXPL)
		case "X":
			err = vendor(filtergen.CiscoXR)
		case "E":
			err = kind(filtergen.RouteFilter)
		case "z":
			err = kind(filtergen.RouteFilterList)
		case "t":
			err = kind(filtergen.ASSet)
		case "f", "G", "H":
			err = kind(map[string]filtergen.Kind{"f": filtergen.ASPath, "G": filtergen.OriginASPath, "H": filtergen.ASList}[op.name])
			if err == nil {
				c.o.AS, err = asNumber(op.name, op.arg)
			}
		case "h":
			c.host = op.arg
		case "S":
			c.sources = op.arg
		case "l":
			c.o.Name = op.arg
		case "L":
			switch c.depth, err = number("L", op.arg); {
			case err != nil:
			case c.depth < 1:
				err = usagef("-L wants a depth of at least 1")
			case c.depth == 1:
				// bgpq4 -L 1 expands the named sets alone, leaving every
				// nested set out without a word; the engine drops nothing
				// silently.
				err = usagef("-L 1 leaves every nested set out, which rpslq does not do silently; -L 2 allows one level of nesting")
			}
		case "m", "R", "r":
			var n int
			if n, err = number(op.name, op.arg); err == nil && n == 0 {
				err = usagef("-%s wants a length of at least 1", op.name)
			}
			switch op.name {
			case "m":
				c.maxLen = n
			case "R":
				c.refine = n
			case "r":
				c.refineLow = n
			}
		case "M":
			c.o.Match, err = matchEscapes(op.arg)
		case "p":
			c.special = true
		case "s":
			c.o.Sequence = true
		case "T":
			c.pipeline = false
		case "W":
			c.o.Width, err = number("W", op.arg)
			c.widthSet = true
		case "w":
			c.validate = true
		case "c":
			c.conc, err = number("c", op.arg)
		case "whois":
			c.whois = true
		case "dump":
			c.dumps = append(c.dumps, op.arg)
		case "ranges":
			c.ranges = true
		case "server-expand":
			c.serverSide = true
		case "timeout":
			if c.timeout, err = time.ParseDuration(op.arg); err != nil {
				err = usagef("--timeout wants a duration such as 30s, not %q", op.arg)
			}
		case "D":
			err = usagef("unknown option -D")
		}
		if err != nil {
			return nil, false, err
		}
	}
	if !c.widthSet {
		c.o.Width = filtergen.DefaultWidth(c.o.Vendor, c.o.Kind)
	}
	return c, false, c.check(operands)
}

// errVersion asks for the version rather than a list.
var errVersion = errors.New("version")

// check applies bgpq4's rules on what goes together, and splits the operands
// into objects and what follows EXCEPT.
func (c *config) check(operands []string) error {
	if err := c.o.Check(c.aggregate, c.refine, c.refineLow); err != nil {
		return usagef("%s", strings.TrimPrefix(err.Error(), "filtergen: not supported: "))
	}
	full := 32
	if c.o.V6 {
		full = 128
	}
	if c.refineLow > 0 && c.refine == 0 {
		c.refine = full // bgpq4: -r alone allows more-specifics up to the full length
	}
	asKinds := c.o.Kind == filtergen.ASPath || c.o.Kind == filtergen.OriginASPath || c.o.Kind == filtergen.ASList
	switch {
	case c.refineLow > c.refine:
		return usagef("-r %d is longer than -R %d", c.refineLow, c.refine)
	case c.refine > full:
		return usagef("-R %d is longer than an address (%d)", c.refine, full)
	case c.maxLen > full:
		return usagef("-m %d is longer than an address (%d)", c.maxLen, full)
	case asKinds && c.o.V6 && !c.validate:
		return usagef("-6 makes no sense with as-path (-f, -G) or as-list (-H) generation")
	case c.validate && !asKinds:
		return usagef("-w is for as-path (-f, -G) and as-list (-H) generation")
	case c.ranges && (c.aggregate || c.refine > 0):
		return usagef("--ranges writes the RPSL ranges as they are; -A, -R and -r work on the prefixes they hold")
	case c.serverSide && (c.whois || len(c.dumps) > 0):
		return usagef("--server-expand asks an IRRd server to expand as-sets, so it needs IRRd, not --whois or --dump")
	}
	for i, a := range operands {
		if a == "EXCEPT" {
			c.objects, c.except = operands[:i], operands[i+1:]
			break
		}
	}
	if c.objects == nil && c.except == nil {
		c.objects = operands
	}
	if len(c.objects) == 0 {
		return usagef("no objects to expand")
	}
	if c.serverSide && len(c.except) > 0 {
		return usagef("--server-expand lets the server expand as-sets, and it cannot leave out what follows EXCEPT")
	}
	if c.conc < 1 || !c.pipeline {
		c.conc = 1
	}
	return nil
}

// matchEscapes decodes -M's escapes as bgpq4 does: a backslash before a line
// break, r, t or another backslash. (bgpq4 means \n but tests for a real line
// break, so \n is refused, as it is there.)
func matchEscapes(v string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		if v[i] != '\\' {
			b.WriteByte(v[i])
			continue
		}
		if i+1 == len(v) {
			return "", usagef("-M ends in a lone backslash")
		}
		i++
		switch v[i] {
		case '\n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case '\\':
			b.WriteByte('\\')
		default:
			return "", usagef("unsupported escape \\%c in -M", v[i])
		}
	}
	return b.String(), nil
}

// Run runs rpslq with args, writing the list to stdout and warnings and errors
// to stderr, and returns the exit code.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	c, help, err := parse(args)
	switch {
	case help || len(args) == 0:
		fmt.Fprint(stderr, usage)
		return exitUsage
	case errors.Is(err, errVersion):
		fmt.Fprintf(stdout, "rpslq %s\n", version())
		return exitOK
	case err != nil:
		fmt.Fprintln(stderr, "rpslq:", err)
		return exitUsage
	}
	if c.depth == 0 {
		c.depth = 1 + 32 // the engine's default MaxDepth, as bgpq4 counts it
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	be, err := source(c.host, c.sources, c.whois, c.dumps, c.conc)
	if err != nil {
		fmt.Fprintln(stderr, "rpslq:", err)
		return exitFail
	}
	defer be.close()
	var trace *tracer
	src := be.src
	if c.debug {
		trace = newTracer(stderr)
		defer trace.summary()
		src = &traceSource{src: src, t: trace}
	}
	if c.whois && c.conc > maxWhoisConns {
		c.conc = maxWhoisConns // whois opens a connection per query
	}
	afi := types.AFIv4
	if c.o.V6 {
		afi = types.AFIv6
	}
	var aset func(context.Context, types.SetName, types.AFI) ([]netip.Prefix, error)
	if ir, ok := be.src.(*irrd.Source); ok && c.serverSide {
		ir.MaxResponse = 256 << 20 // IRRd warns "!a" answers reach 10-20 MB
		aset = ir.ASSetPrefixes
		if trace != nil {
			aset = trace.traceASet(aset)
		}
	}
	exclude, err := parseExcept(c.except)
	if err != nil {
		fmt.Fprintln(stderr, "rpslq:", err)
		return exitUsage
	}
	q := query{
		aset:    aset,
		e:       &resolve.Expander{Src: src, AFI: afi, MaxDepth: c.depth - 1, Concurrency: c.conc, Exclude: exclude},
		src:     src,
		afi:     afi,
		special: c.special,
		maxLen:  c.maxLen,
		conc:    c.conc,
		stderr:  stderr,
		levels:  c.depth,
		be:      be,
		trace:   trace,
	}
	switch c.o.Kind {
	case filtergen.ASSet, filtergen.ASPath, filtergen.OriginASPath, filtergen.ASList:
		asns, code := q.asns(ctx, c.objects)
		if code != exitOK {
			return code
		}
		if c.validate {
			if asns, err = q.withRoutes(ctx, asns); err != nil {
				return q.fail("routes", err)
			}
		}
		if err := filtergen.WriteASNs(stdout, c.o, asns); err != nil {
			fmt.Fprintln(stderr, "rpslq:", err)
			return exitFail
		}
		return exitOK
	}
	ranges, code := q.prefixes(ctx, c.objects)
	if code != exitOK {
		return code
	}
	var entries []filtergen.Entry
	if c.ranges {
		entries = rangeEntries(ranges, c.maxLen)
	} else {
		t := filtergen.NewTree(c.o.V6, c.maxLen, maxPrefixes)
		for _, r := range ranges {
			if err := t.Add(r); err != nil {
				fmt.Fprintf(stderr, "rpslq: %v; use --ranges for the RPSL ranges themselves\n", err)
				return exitFail
			}
		}
		if c.refine > 0 {
			t.Refine(c.refine)
		}
		if c.refineLow > 0 {
			t.RefineLow(c.refineLow)
		}
		if c.aggregate {
			t.Aggregate()
		}
		entries = t.Entries()
	}
	if err := filtergen.WritePrefixes(stdout, c.o, entries); err != nil {
		if errors.Is(err, filtergen.ErrUnsupported) {
			fmt.Fprintf(stderr, "rpslq: %v; drop --ranges\n", err)
			return exitUsage
		}
		fmt.Fprintln(stderr, "rpslq:", err)
		return exitFail
	}
	return exitOK
}

// maxPrefixes caps the prefixes a list may hold: bgpq4 lists every prefix a
// range holds, and a /8^+ holds 33 million. The largest real sets hold over a
// million (AS-HURRICANE, 1.16 million IPv4 prefixes in 2026), so the cap is
// eight times that, the tree then at most about 1.5 GB.
const maxPrefixes = 1 << 23

// rangeEntries turns RPSL ranges into entries as they are (--ranges), with
// -m applied as bgpq4 applies it to a range: a longer prefix is dropped and a
// range reaching past the length stops there.
func rangeEntries(rs []types.PrefixRange, maxLen int) []filtergen.Entry {
	var out []filtergen.Entry
	for _, r := range rs {
		p, lo, hi := r.Prefix(), int(r.Lo()), int(r.Hi())
		if maxLen > 0 {
			if p.Bits() > maxLen || lo > maxLen {
				continue
			}
			hi = min(hi, maxLen)
		}
		exact := lo == p.Bits() && hi == lo
		out = append(out, filtergen.Entry{Prefix: p, Aggregate: !exact, Lo: lo, Hi: hi})
	}
	filtergen.Sort(out)
	return out
}

// parseExcept reads what follows EXCEPT: as-sets, route-sets and AS numbers.
func parseExcept(args []string) (resolve.Exclusion, error) {
	var ex resolve.Exclusion
	for _, a := range args {
		if as, err := types.ParseASN(a); err == nil {
			ex.ASNs = append(ex.ASNs, as)
			continue
		}
		if strings.Contains(a, "::") {
			return ex, usagef("EXCEPT leaves a set out wherever it is met, so it takes no SOURCE::, as in %q", a)
		}
		n, err := types.ParseSetName(a)
		if err != nil || (n.Class() != types.ClassAsSet && n.Class() != types.ClassRouteSet) {
			return ex, usagef("EXCEPT takes as-sets, route-sets and AS numbers, not %q", a)
		}
		ex.Sets = append(ex.Sets, n)
	}
	return ex, nil
}

// version is the rpsl module rpslq was built from.
func version() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		if bi.Main.Path == "github.com/rkolesnichenko/rpsl/resolve" && bi.Main.Version != "" {
			return bi.Main.Version
		}
		for _, d := range bi.Deps {
			if d.Path == "github.com/rkolesnichenko/rpsl/resolve" {
				return d.Version
			}
		}
	}
	return "(devel)"
}

// backend is the source the flags describe: the default one, and the same
// backend restricted to one registry, for bgpq4's SOURCE::OBJECT.
type backend struct {
	src      resolve.Source
	restrict func(registry string) resolve.Source
	close    func()
}

// source builds the backend the flags describe.
func source(host, sources string, useWhois bool, files []string, conns int) (*backend, error) {
	var prio []string
	for _, s := range strings.Split(sources, ",") {
		if s = strings.TrimSpace(s); s != "" {
			prio = append(prio, strings.ToUpper(s))
		}
	}
	if len(files) > 0 {
		var closers []io.Closer
		closeAll := func() {
			for _, c := range closers {
				c.Close()
			}
		}
		defer closeAll()
		l := &resolve.DumpLoader{Sources: prio}
		for _, name := range files {
			f, err := os.Open(name)
			if err != nil {
				return nil, err
			}
			closers = append(closers, f)
			r, err := maybeGzip(f)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			if err := l.Read(r); err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
		}
		// -S chooses the registries, as it does for a server ("!s"): only
		// those, in that order; without it, every registry in the dumps.
		all := l.Source()
		if len(prio) > 0 {
			all = l.SourceOf(prio...)
		}
		return &backend{
			src:      all,
			restrict: func(reg string) resolve.Source { return l.SourceOf(reg) },
			close:    func() {},
		}, nil
	}
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "43")
	}
	if useWhois {
		return &backend{
			src:      &whois.Source{Addr: host, Sources: prio},
			restrict: func(reg string) resolve.Source { return &whois.Source{Addr: host, Sources: []string{reg}} },
			close:    func() {},
		}, nil
	}
	// One connection, its queries pipelined, as bgpq4 queries an IRRd; a
	// registry-restricted source is a connection of its own.
	all := []*irrd.Source{{Addr: host, Sources: prio, Pipeline: conns, MaxConns: 1}}
	return &backend{
		src: all[0],
		restrict: func(reg string) resolve.Source {
			s := &irrd.Source{Addr: host, Sources: []string{reg}, Pipeline: conns, MaxConns: 1}
			all = append(all, s)
			return s
		},
		close: func() {
			for _, s := range all {
				s.Close()
			}
		},
	}, nil
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
	aset    func(context.Context, types.SetName, types.AFI) ([]netip.Prefix, error) // --server-expand: the server's expansion
	e       *resolve.Expander
	src     resolve.Source
	afi     types.AFI
	special bool // keep special-purpose AS numbers
	maxLen  int  // -m: 0, or the longest prefix a list holds
	levels  int  // -L, as bgpq4 counts: the top set and levels-1 below it
	be      *backend
	trace   *tracer                   // -d, or nil
	own     map[string]resolve.Source // registry -> the backend restricted to it
	conc    int
	stderr  io.Writer
}

// specialAS reports the AS numbers bgpq4 drops unless given -p: AS_TRANS,
// the documentation and private ranges up to 65551, and 4200000000 and above.
func specialAS(a types.ASN) bool {
	return a == 23456 || a >= 4200000000 || (a >= 64496 && a <= 65551)
}

// object is one command-line object: an AS number, a set name, or a prefix
// or prefix range, which bgpq4 takes as it is.
type object struct {
	text     string
	registry string // SOURCE:: — the registry the object is looked up in, or ""
	as    types.ASN
	set   types.SetName
	pfx   types.PrefixRange
	isAS  bool
	isPfx bool
}

func parseObjects(args []string) ([]object, error) {
	var out []object
	for _, text := range args {
		if r, ok := parsePrefix(text); ok { // before SOURCE::, which "2001::/16" also looks like
			out = append(out, object{text: text, pfx: r, isPfx: true})
			continue
		}
		a, registry := text, ""
		if reg, name, ok := strings.Cut(text, "::"); ok {
			if !validRegistry(reg) {
				return nil, fmt.Errorf("%q: %q is not a registry's name", text, reg)
			}
			a, registry = name, strings.ToUpper(reg)
		}
		if as, err := types.ParseASN(a); err == nil {
			out = append(out, object{text: text, registry: registry, as: as, isAS: true})
			continue
		}
		n, err := types.ParseSetName(a)
		if err != nil {
			if _, ok := parsePrefix(a); ok && registry != "" {
				return nil, fmt.Errorf("%s: SOURCE:: names a set or an AS number, and a prefix is not looked up", text)
			}
			return nil, fmt.Errorf("%q is not an AS number, a set name or a prefix", text)
		}
		if c := n.Class(); c != types.ClassAsSet && c != types.ClassRouteSet {
			return nil, fmt.Errorf("%s is a %s; rpslq expands as-sets, route-sets and AS numbers", n, c)
		}
		out = append(out, object{text: text, registry: registry, set: n})
	}
	return out, nil
}

// validRegistry reports whether s can name an IRR source, as IRRd's "!s"
// takes one: letters, digits, hyphens and underscores.
func validRegistry(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// restricted is the backend restricted to one registry, built once and, with
// -d, traced.
func (q *query) restricted(registry string) resolve.Source {
	if s, ok := q.own[registry]; ok {
		return s
	}
	s := q.be.restrict(registry)
	if q.trace != nil {
		s = &traceSource{src: s, label: " [" + registry + "]", t: q.trace}
	}
	if q.own == nil {
		q.own = map[string]resolve.Source{}
	}
	q.own[registry] = s
	return s
}

// expander is the expander for one object: the query's own, or for
// SOURCE::SET one that looks that set up in its registry.
func (q *query) expander(o object) *resolve.Expander {
	if o.registry == "" {
		return q.e
	}
	e := *q.e
	e.Src = &topSource{Source: q.e.Src, top: o.set, own: q.restricted(o.registry)}
	return &e
}

// parsePrefix reads a prefix or prefix range object; an address alone is
// its host prefix, as bgpq4 reads it.
func parsePrefix(s string) (types.PrefixRange, bool) {
	if r, err := types.ParsePrefixRange(s); err == nil {
		return r, true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		r, ok := types.NewPrefixRange(netip.PrefixFrom(a, a.BitLen()), a.BitLen(), a.BitLen())
		return r, ok
	}
	return types.PrefixRange{}, false
}

// fail reports an expansion error and returns its exit code.
func (q *query) fail(what string, err error) int {
	var tooDeep *resolve.SetTooLargeError
	if errors.As(err, &tooDeep) && tooDeep.Limit == resolve.LimitDepth {
		fmt.Fprintf(q.stderr, "rpslq: %s: sets nest deeper than -L %d allows; bgpq4 would leave the deeper ones out, rpslq does not (raise -L)\n", what, q.levels)
		return exitFail
	}
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
		if o.isPfx || o.set.Class() != types.ClassAsSet {
			fmt.Fprintf(q.stderr, "rpslq: an AS list or as-path filter takes as-sets and AS numbers, not %s\n", o.text)
			return nil, exitUsage
		}
		got, err := q.expander(o).ExpandAS(ctx, o.set)
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
	own := map[string][]types.ASN{} // SOURCE::AS: the ASes whose routes come from one registry
	for _, o := range objs {
		switch {
		case o.isPfx:
			// bgpq4 refuses a prefix of the other family, or longer than -m.
			p := o.pfx.Prefix()
			if p.Addr().Is6() != (q.afi == types.AFIv6) || q.maxLen > 0 && p.Bits() > q.maxLen {
				fmt.Fprintf(q.stderr, "rpslq: %s: not an %s prefix of at most /%d\n", o.text, familyName(q.afi), q.fullOr(q.maxLen))
				return nil, exitFail
			}
			out[o.pfx] = true
		case o.isAS && o.registry != "":
			if q.special || !specialAS(o.as) {
				own[o.registry] = append(own[o.registry], o.as)
			}
		case o.isAS:
			asns[o.as] = true
		case o.set.Class() == types.ClassAsSet && q.aset != nil && o.registry != "":
			fmt.Fprintf(q.stderr, "rpslq: %s: --server-expand has the server expand the whole set within one registry, which is not what SOURCE:: means; drop one of them\n", o.text)
			return nil, exitUsage
		case o.set.Class() == types.ClassAsSet && q.aset != nil:
			// The server's expansion, taken as it is: its recursion, and its
			// routes of every member, special-purpose ones included.
			got, err := q.aset(ctx, o.set, q.afi)
			if err != nil {
				if errors.Is(err, irrd.ErrQueryRefused) {
					return nil, q.fail(o.text, fmt.Errorf("%w (the server has no \"!a\"; drop --server-expand)", err))
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
			got, err := q.expander(o).ExpandAS(ctx, o.set)
			if err != nil {
				return nil, q.fail(o.text, err)
			}
			q.warnMissing(o.text, got.Missing())
			for _, a := range got.List() {
				asns[a] = true
			}
		default:
			got, err := q.expander(o).ExpandPrefixRanges(ctx, o.set)
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
	routes, err := q.routes(ctx, q.e.Src, order)
	if err != nil {
		return nil, q.fail("routes", err)
	}
	registries := make([]string, 0, len(own))
	for reg := range own {
		registries = append(registries, reg)
	}
	sort.Strings(registries)
	for _, reg := range registries {
		more, err := q.routes(ctx, q.restricted(reg), own[reg])
		if err != nil {
			return nil, q.fail("routes", err)
		}
		routes = append(routes, more...)
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

// routes fetches the routes the ASes originate from src, up to conc at a time.
func (q *query) routes(ctx context.Context, src resolve.Source, asns []types.ASN) ([]netip.Prefix, error) {
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
			results[i], errs[i] = src.OriginatedRoutes(ctx, a, q.afi)
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

func familyName(afi types.AFI) string {
	if afi == types.AFIv6 {
		return "IPv6"
	}
	return "IPv4"
}

// fullOr is n, or the family's full length when n is 0.
func (q *query) fullOr(n int) int {
	switch {
	case n > 0:
		return n
	case q.afi == types.AFIv6:
		return 128
	}
	return 32
}

// withRoutes keeps the AS numbers that originate routes of the family (-w),
// as bgpq4 validates an as-path list's AS numbers.
func (q *query) withRoutes(ctx context.Context, asns []types.ASN) ([]types.ASN, error) {
	slices.Sort(asns)
	results := make([][]netip.Prefix, len(asns))
	errs := make([]error, len(asns))
	sem := make(chan struct{}, max(q.conc, 1))
	var wg sync.WaitGroup
	for i, a := range asns {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			results[i], errs[i] = q.src.OriginatedRoutes(ctx, a, q.afi)
		}()
	}
	wg.Wait()
	var out []types.ASN
	for i, a := range asns {
		if errs[i] != nil {
			return nil, fmt.Errorf("%s: %w", a, errs[i])
		}
		if len(results[i]) > 0 {
			out = append(out, a)
		}
	}
	return out, nil
}
