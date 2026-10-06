// Package rpslcheck is the rpslcheck command: whether neighbouring
// networks' routing policies in IRR data agree, and what is wrong or dead in
// one network's, on the rpsl engine (resolve/consist).
package rpslcheck

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/consist"
	"github.com/rkolesnichenko/rpsl/resolve/internal/backend"
	"github.com/rkolesnichenko/rpsl/resolve/internal/buildinfo"
	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/resolve/rpki"
	"github.com/rkolesnichenko/rpsl/types"
)

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(s string) error { *l = append(*l, s); return nil }

// The exit statuses.
const (
	exitClean   = 0 // no Warning
	exitWarning = 1 // at least one Warning
	exitUsage   = 2 // a command line rpslcheck cannot use
	exitFailed  = 3 // the check could not complete
)

// Run runs rpslcheck with the given arguments and returns its exit status.
func Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rpslcheck", flag.ContinueOnError)
	fs.SetOutput(stderr)
	host := fs.String("h", "whois.radb.net", "IRR server `host`, or host:port")
	port := fs.String("p", "43", "IRR server `port`, when -h names none")
	sources := fs.String("s", "", "registries to query, comma-separated, in precedence order (default: the server's)")
	useWhois := fs.Bool("whois", false, "query with the whois protocol instead of IRRd's")
	var dumps listFlag
	fs.Var(&dumps, "dump", "read objects from a dump `file` instead of a server (repeatable; gzip is read too)")
	afFlag := fs.String("af", "both", "address `families` to check: ipv4, ipv6 or both")
	asJSON := fs.Bool("json", false, "write one JSON object per line")
	sweep := fs.Bool("sweep", false, "audit every aut-num in the dumps (needs -dump)")
	sample := fs.Int("sample", 0, "sweep: a random sample of `N` aut-nums instead of all")
	seed := fs.Uint64("seed", 1, "sweep: the sample's random `seed`")
	conc := fs.Int("c", runtime.GOMAXPROCS(0), "`N` checks at once; the output is the same for any N while no call runs past -check-timeout")
	timeout := fs.Duration("timeout", 10*time.Minute, "give up on the whole run after this long (0: never); a -sweep has no deadline unless this is given")
	checkTimeout := fs.Duration("check-timeout", time.Minute, "sweep: give each aut-num's peer list, its lint, and each pair's check this long, each its own budget, counting the ones that run out (0: no limit)")
	setPeers := fs.Bool("set-peers", false, "also check (and lint toward) the peers named only through as-sets and peering-sets; there can be tens of thousands")
	rpkiFile := fs.String("rpki", "", "a validator's JSON export `file` (rpki-client -j, Routinator json): lint each aut-num against its ASPAs too")
	showVersion := fs.Bool("v", false, "print rpslcheck's version and exit")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *showVersion {
		fmt.Fprintf(stdout, "rpslcheck %s\n", buildinfo.Version())
		return exitClean
	}
	usage := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "rpslcheck: "+format+"\n", a...)
		return exitUsage
	}
	afs, err := families(*afFlag)
	if err != nil {
		return usage("-af: %v", err)
	}
	if *conc < 1 {
		return usage("-c must be at least 1")
	}
	var ases []types.ASN
	for _, a := range fs.Args() {
		as, err := parseAS(a)
		if err != nil {
			return usage("%v", err)
		}
		ases = append(ases, as)
	}
	switch {
	case *sweep && len(dumps) == 0:
		return usage("-sweep reads dumps only (-dump): sweeping a live server would send it hundreds of thousands of queries")
	case *sweep && len(ases) > 0:
		return usage("-sweep takes no AS")
	case !*sweep && *sample != 0:
		return usage("-sample belongs to -sweep")
	case !*sweep && (len(ases) == 0 || len(ases) > 2):
		return usage("give one AS (lint it and check it against its peers) or two (check that pair)")
	case len(ases) == 2 && ases[0] == ases[1]:
		return usage("the two ASes are the same")
	}
	explicit := false
	fs.Visit(func(f *flag.Flag) { explicit = explicit || f.Name == "timeout" })
	if d := runTimeout(*sweep, *timeout, explicit); d > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d)
		defer cancel()
	}
	// The ASPAs are read first: a bad export fails before a long dump load.
	var aspas *rpki.ASPAs
	if *rpkiFile != "" {
		f, err := os.Open(*rpkiFile)
		if err == nil {
			aspas, err = rpki.ReadASPAs(f)
			f.Close()
		}
		if err != nil {
			fmt.Fprintf(stderr, "rpslcheck: -rpki: %v\n", err)
			return exitFailed
		}
	}
	b, err := backend.Open(backend.Options{Host: hostPort(*host, *port), Sources: *sources, Whois: *useWhois,
		Dumps: dumps, Conns: 8, KeepPolicy: true, IndexPeers: len(dumps) > 0})
	if err != nil {
		fmt.Fprintf(stderr, "rpslcheck: %v\n", err)
		return exitFailed
	}
	defer b.Close()
	w := newWriter(stdout, *asJSON)
	src := resolve.NewCache(b.Src, 0)
	if *sweep {
		return runSweep(ctx, src, afs, *sample, *seed, *conc, *checkTimeout, *setPeers, aspas, w, stderr)
	}
	c := &consist.Checker{Eval: peval.Evaluator{Src: src}, SetPeers: *setPeers, ASPAs: aspas}
	r := &runner{ctx: ctx, c: c, src: src, w: w, stderr: stderr, afs: afs}
	if len(ases) == 1 {
		return r.one(ases[0], afs)
	}
	return r.pair(ases[0], ases[1], afs)
}

// runTimeout is the deadline of the whole run: the -timeout flag, except
// that a sweep — a full registry takes most of an hour — has none unless
// -timeout was given explicitly; its checks have their own (-check-timeout).
func runTimeout(sweep bool, timeout time.Duration, explicit bool) time.Duration {
	if sweep && !explicit {
		return 0
	}
	return timeout
}

func hostPort(host, port string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, port)
}

// parseAS reads "AS65001" or "65001".
func parseAS(s string) (types.ASN, error) {
	if !strings.HasPrefix(strings.ToUpper(s), "AS") {
		s = "AS" + s
	}
	as, err := types.ParseASN(s)
	if err != nil {
		return 0, fmt.Errorf("%q is not an AS number", s)
	}
	return as, nil
}

func families(s string) ([]types.AddrFamily, error) {
	v4 := types.AddrFamily{AFI: types.AFIv4, SAFI: types.SAFIUnicast}
	v6 := types.AddrFamily{AFI: types.AFIv6, SAFI: types.SAFIUnicast}
	switch s {
	case "ipv4":
		return []types.AddrFamily{v4}, nil
	case "ipv6":
		return []types.AddrFamily{v6}, nil
	case "both":
		return []types.AddrFamily{v4, v6}, nil
	}
	return nil, fmt.Errorf("%q is not ipv4, ipv6 or both", s)
}

// runner runs the per-AS and per-pair modes.
type runner struct {
	ctx    context.Context
	c      *consist.Checker
	src    resolve.PolicySource
	w      *writer
	stderr io.Writer
	afs    []types.AddrFamily // -af: the lint issues written are of these
	worst  int                // exitClean or exitWarning, from what was written
}

// ofFamilies keeps the lint issues of one of afs, and those of no family
// (Lint always lints both families; -af chooses what is written).
func ofFamilies(issues []consist.Issue, afs []types.AddrFamily) []consist.Issue {
	var out []consist.Issue
	for _, is := range issues {
		if len(is.AFs) == 0 || slices.ContainsFunc(is.AFs, func(af types.AddrFamily) bool { return slices.Contains(afs, af) }) {
			out = append(out, is)
		}
	}
	return out
}

func (r *runner) fail(err error) int {
	fmt.Fprintf(r.stderr, "rpslcheck: %v\n", err)
	return exitFailed
}

// peerNote is the stderr note for a source with no reverse index.
func peerNote(noIndex bool, as string) string {
	if !noIndex {
		return ""
	}
	return fmt.Sprintf("rpslcheck: note: the source keeps no reverse index (only -dump does), so networks that name %s without being named back are not checked\n", as)
}

// setPeersNote is the stderr note for n peers named only through sets and
// left unchecked (no -set-peers).
func setPeersNote(n int) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("rpslcheck: note: %d peers named through sets are not checked; -set-peers checks them\n", n)
}

// one lints as and checks it against every peer, Forward and Reverse — and
// ViaSets with -set-peers.
func (r *runner) one(as types.ASN, afs []types.AddrFamily) int {
	if code := r.lint(as); code != exitClean {
		return code
	}
	pl, err := r.c.Peers(r.ctx, as)
	if err != nil {
		return r.fail(err)
	}
	fmt.Fprint(r.stderr, peerNote(pl.NoIndex, as.String()))
	peers := slices.Concat(pl.Forward, pl.Reverse)
	if r.c.SetPeers {
		peers = append(peers, pl.ViaSets...)
	} else {
		unchecked := 0
		for _, a := range pl.ViaSets {
			if _, ok := slices.BinarySearch(pl.Reverse, a); !ok { // Reverse is ascending
				unchecked++
			}
		}
		fmt.Fprint(r.stderr, setPeersNote(unchecked))
	}
	slices.Sort(peers)
	for _, peer := range slices.Compact(peers) {
		for _, af := range afs {
			if code := r.check(consist.Pair{A: as, B: peer, AF: af}); code != exitClean {
				return code
			}
		}
	}
	return r.worst
}

// pair lints a and b and checks the pair.
func (r *runner) pair(a, b types.ASN, afs []types.AddrFamily) int {
	for _, as := range []types.ASN{a, b} {
		if code := r.lint(as); code != exitClean {
			return code
		}
	}
	for _, af := range afs {
		if code := r.check(consist.Pair{A: a, B: b, AF: af}); code != exitClean {
			return code
		}
	}
	return r.worst
}

// lint writes as's lint; exitFailed when it could not, else exitClean.
func (r *runner) lint(as types.ASN) int {
	issues, err := r.c.Lint(r.ctx, as)
	issues = ofFamilies(issues, r.afs)
	if errors.Is(err, resolve.ErrNotFound) {
		return r.fail(fmt.Errorf("%s: aut-num not found", as))
	}
	if err != nil {
		return r.fail(err)
	}
	an, _ := r.src.AutNum(r.ctx, as, "")
	if r.w.lint(as, an, issues) {
		r.worst = exitWarning
	}
	return exitClean
}

// check writes one pair's report; exitFailed when it could not (a limit or
// a filter that cannot be evaluated included, outside a sweep), else
// exitClean.
func (r *runner) check(p consist.Pair) int {
	rep, err := r.c.Check(r.ctx, p)
	if err != nil {
		return r.fail(fmt.Errorf("%s and %s, %s: %w", p.A, p.B, p.AF, err))
	}
	if r.w.report(r.ctx, r.src, rep) {
		r.worst = exitWarning
	}
	return exitClean
}

// isLimit reports whether err is one of the engine's limits.
func isLimit(err error) bool {
	var tl *resolve.SetTooLargeError
	return errors.As(err, &tl) || errors.Is(err, policy.ErrFlattenTooLarge)
}

// notDecidable reports whether err is a filter that cannot be evaluated for
// a session: it names a set reaching AS-ANY, or has no normal form. A sweep
// counts such a pair with the limits; a single check fails on it.
func notDecidable(err error) bool {
	var anyErr *resolve.AnySetError
	var ne *resolve.NotEnumerableError
	return errors.As(err, &anyErr) || errors.As(err, &ne)
}
