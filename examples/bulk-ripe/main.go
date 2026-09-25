// Command bulk-ripe streams an RPSL bulk dump (e.g. RIPE's split dumps from
// ftp://ftp.ripe.net/ripe/dbase/split/) through the rpsl library and prints a
// throughput + diagnostic-histogram report. It is the integration-test harness
// for the library at GB scale; the test fixture in testdata/ exercises the
// same code path on a tiny synthetic dump so the harness can't rot silently.
//
// Typical use:
//
//	go run ./examples/bulk-ripe ripe.db.route.gz                       # streaming summary
//	go run ./examples/bulk-ripe --json --expand ripe.db.aut-num.gz     # JSON + resolve smoke
//	zcat ripe.db.as-set.gz | go run ./examples/bulk-ripe -             # via stdin
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/rkolesnichenko/rpsl/examples/bulk-ripe/bulk"
)

// stringSliceFlag accumulates repeated --expand-set occurrences, since stdlib
// flag has no equivalent of pflag's StringSliceVar.
type stringSliceFlag []string

func (s *stringSliceFlag) String() string { return strings.Join(*s, ",") }
func (s *stringSliceFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	os.Exit(run())
}

func run() int {
	var (
		validateFlag      string
		jsonOut           bool
		expand            bool
		expandSets        stringSliceFlag
		expandSample      int
		expandTimeout     time.Duration
		maxRetainAutNums  int
		maxRetainAsSets   int
		maxRetainRouteSet int
		maxRetainRoutes   int
	)

	fs := flag.NewFlagSet("bulk-ripe", flag.ContinueOnError)
	fs.StringVar(&validateFlag, "validate", "ripe", "validation profile: ripe|irrd|rfc-strict|off")
	fs.BoolVar(&jsonOut, "json", false, "emit the report as JSON instead of plaintext")
	fs.BoolVar(&expand, "expand", false, "after streaming, smoke-test resolve.Expander against retained sets")
	fs.Var(&expandSets, "expand-set", "explicit set name to expand (repeatable; overrides sampling)")
	fs.IntVar(&expandSample, "expand-sample", 0, fmt.Sprintf("number of largest-by-membership sets per class to sample when -expand-set not given (default %d with -expand)", bulk.DefaultExpandSample))
	fs.DurationVar(&expandTimeout, "expand-timeout", bulk.DefaultExpandTimeout, "per-set expansion timeout")
	fs.IntVar(&maxRetainAutNums, "max-retain-aut-nums", bulk.DefaultMaxRetainAutNums, "retention cap on aut-num objects (only with -expand)")
	fs.IntVar(&maxRetainAsSets, "max-retain-as-sets", bulk.DefaultMaxRetainAsSets, "retention cap on as-set objects (only with -expand)")
	fs.IntVar(&maxRetainRouteSet, "max-retain-route-sets", bulk.DefaultMaxRetainRouteSets, "retention cap on route-set objects (only with -expand)")
	fs.IntVar(&maxRetainRoutes, "max-retain-routes", bulk.DefaultMaxRetainRoutes, "retention cap on route+route6 objects combined (only with -expand)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: bulk-ripe [flags] <file|->")
		fs.PrintDefaults()
	}
	if err := fs.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}

	args := fs.Args()
	if len(args) != 1 {
		fs.Usage()
		return 1
	}
	target := args[0]

	mode, err := bulk.ParseValidateMode(validateFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	var input io.Reader
	if target == "-" {
		input = os.Stdin
	} else {
		f, err := os.Open(target)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		defer f.Close()
		input = f
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	opts := bulk.Options{
		Validate:           mode,
		Expand:             expand,
		ExpandSets:         []string(expandSets),
		ExpandSample:       expandSample,
		ExpandTimeout:      expandTimeout,
		MaxRetainAutNums:   maxRetainAutNums,
		MaxRetainAsSets:    maxRetainAsSets,
		MaxRetainRouteSets: maxRetainRouteSet,
		MaxRetainRoutes:    maxRetainRoutes,
	}

	report, runErr := bulk.Run(ctx, input, opts)
	if report == nil {
		fmt.Fprintln(os.Stderr, runErr)
		return 1
	}

	exit := 0
	if runErr != nil {
		fmt.Fprintf(os.Stderr, "warning: %v (printing partial report)\n", runErr)
		exit = 2
	} else if ctx.Err() != nil {
		fmt.Fprintln(os.Stderr, "interrupted (partial report below)")
		exit = 130
	}

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	} else {
		printPlaintext(os.Stdout, report)
	}
	return exit
}

func printPlaintext(w io.Writer, r *bulk.Report) {
	mbPerSec, parsedPerSec := 0.0, 0.0
	if r.Elapsed > 0 {
		mbPerSec = float64(r.Bytes) / (1 << 20) / r.Elapsed.Seconds()
		parsedPerSec = float64(r.ParsedBytes) / (1 << 20) / r.Elapsed.Seconds()
	}
	objPerSec := 0.0
	if r.Elapsed > 0 {
		objPerSec = float64(r.Objects) / r.Elapsed.Seconds()
	}
	fmt.Fprintf(w, "objects:      %d\n", r.Objects)
	fmt.Fprintf(w, "bytes:        %d on disk, %d parsed\n", r.Bytes, r.ParsedBytes)
	fmt.Fprintf(w, "elapsed:      %s\n", r.Elapsed)
	fmt.Fprintf(w, "throughput:   %.1f MB/s parsed (%.1f MB/s on disk), %.0f obj/s\n", parsedPerSec, mbPerSec, objPerSec)
	fmt.Fprintln(w)

	classes := sortedKeys(r.ClassCounts)
	fmt.Fprintln(w, "by class:")
	for _, c := range classes {
		fmt.Fprintf(w, "  %-14s %d\n", c, r.ClassCounts[c])
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, "diagnostics: %d total\n", r.Diagnostics)
	if r.Diagnostics > 0 {
		sevs := sortedKeys(r.BySeverity)
		for _, s := range sevs {
			fmt.Fprintf(w, "  %-8s %d\n", s, r.BySeverity[s])
		}
		fmt.Fprintln(w, "top rules:")
		max := 20
		if len(r.ByRule) < max {
			max = len(r.ByRule)
		}
		for _, rs := range r.ByRule[:max] {
			fmt.Fprintf(w, "  %8d  %-8s %-40s %s\n", rs.Count, rs.Severity, rs.Rule, rs.FirstSpan)
		}
		if hasLexerMalformed(r.ByRule) {
			fmt.Fprintln(w, "hint: lexer/malformed-line on a canonical RIPE feed is a streaming/boundary regression — re-run with --json | jq '.by_rule[] | select(.rule==\"lexer/malformed-line\")' to retrieve first_span.")
		}
	}

	if len(r.Truncated) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "retention truncated (raise --max-retain-* to capture more for the resolve pass):")
		for _, k := range sortedKeys(r.Truncated) {
			fmt.Fprintf(w, "  %-14s %d\n", k, r.Truncated[k])
		}
	}

	if len(r.ResolveSamples) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "resolve samples:")
		fmt.Fprintf(w, "  %-12s %-32s %8s %10s %s\n", "class", "set", "asns", "prefixes", "note")
		for _, s := range r.ResolveSamples {
			note := ""
			switch {
			case s.Truncated:
				note = "truncated (SetTooLargeError)"
			case s.Err != "":
				note = "err: " + s.Err
			}
			fmt.Fprintf(w, "  %-12s %-32s %8d %10d %s\n", s.Class, s.Set, s.ASNs, s.Prefixes, note)
		}
	}
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func hasLexerMalformed(rules []bulk.RuleStat) bool {
	for _, r := range rules {
		if strings.EqualFold(r.Rule, "lexer/malformed-line") {
			return true
		}
	}
	return false
}
