// Package bulk is the reusable core of the bulk-ripe integration example.
// Run streams a (possibly gzipped) RPSL dump, decodes and optionally validates
// every object, aggregates diagnostics into a Rule × Severity histogram, and —
// when opt-in via Options.Expand — smoke-tests the resolve engine against the
// retained set/route corpus. main.go is a thin CLI wrapper around Run.
package bulk

import (
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/lexer"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

type ruleKey struct {
	rule string
	sev  string
}

// SchemaVersion is the on-the-wire JSON schema version. Bump on incompatible
// shape changes so downstream tooling can detect them.
const SchemaVersion = 1

// Default* are the canonical zero-value replacements applied by
// Options.applyDefaults. main.go uses them as flag defaults so the two stay
// in lock-step.
const (
	DefaultExpandTimeout      = 30 * time.Second
	DefaultExpandSample       = 10
	DefaultMaxRetainAutNums   = 200_000
	DefaultMaxRetainAsSets    = 50_000
	DefaultMaxRetainRouteSets = 50_000
	DefaultMaxRetainRoutes    = 500_000
)

// ValidateMode selects the profile (if any) used for Validate.
type ValidateMode int

const (
	ValidateOff ValidateMode = iota
	ValidateRIPE
	ValidateRFCStrict
	ValidateIRRd
	ValidateARIN
)

func (m ValidateMode) String() string {
	switch m {
	case ValidateOff:
		return "off"
	case ValidateRIPE:
		return "ripe"
	case ValidateRFCStrict:
		return "rfc-strict"
	case ValidateIRRd:
		return "irrd"
	case ValidateARIN:
		return "arin"
	}
	return "unknown"
}

// ParseValidateMode parses --validate flag values.
func ParseValidateMode(s string) (ValidateMode, error) {
	switch s {
	case "off", "none", "":
		return ValidateOff, nil
	case "ripe":
		return ValidateRIPE, nil
	case "rfc-strict", "rfc":
		return ValidateRFCStrict, nil
	case "irrd":
		return ValidateIRRd, nil
	case "arin":
		return ValidateARIN, nil
	}
	return ValidateOff, fmt.Errorf("unknown validate mode %q (want off|ripe|irrd|arin|rfc-strict)", s)
}

// Options configures Run. Zero defaults are applied by applyDefaults at the top
// of Run.
type Options struct {
	Validate ValidateMode

	Expand        bool
	ExpandSample  int
	ExpandSets    []string
	ExpandTimeout time.Duration

	// Retention caps consulted only when Expand is true. They bound memory
	// during streaming; overflows are visible as Truncated counts in the Report.
	MaxRetainAutNums   int
	MaxRetainAsSets    int
	MaxRetainRouteSets int
	MaxRetainRoutes    int // Route + Route6 combined
}

func (o *Options) applyDefaults() {
	if o.ExpandTimeout == 0 {
		o.ExpandTimeout = DefaultExpandTimeout
	}
	if o.Expand && o.ExpandSample == 0 && len(o.ExpandSets) == 0 {
		o.ExpandSample = DefaultExpandSample
	}
	if o.MaxRetainAutNums == 0 {
		o.MaxRetainAutNums = DefaultMaxRetainAutNums
	}
	if o.MaxRetainAsSets == 0 {
		o.MaxRetainAsSets = DefaultMaxRetainAsSets
	}
	if o.MaxRetainRouteSets == 0 {
		o.MaxRetainRouteSets = DefaultMaxRetainRouteSets
	}
	if o.MaxRetainRoutes == 0 {
		o.MaxRetainRoutes = DefaultMaxRetainRoutes
	}
}

// Report is the result of Run. Numeric fields are zero-valued (never absent) so
// downstream JSON consumers can rely on a fixed shape.
type Report struct {
	SchemaVersion  int              `json:"schema_version"`
	Bytes          int64            `json:"bytes"`
	ParsedBytes    int64            `json:"parsed_bytes"` // after decompression
	Elapsed        time.Duration    `json:"elapsed_ns"`
	Objects        int64            `json:"objects"`
	ClassCounts    map[string]int64 `json:"class_counts"`
	Diagnostics    int64            `json:"diagnostics_total"`
	BySeverity     map[string]int64 `json:"diagnostics_by_severity"`
	ByRule         []RuleStat       `json:"by_rule"`
	Truncated      map[string]int64 `json:"retain_truncated,omitempty"`
	ResolveSamples []ResolveSample  `json:"resolve_samples,omitempty"`
}

// RuleStat is one bucket in the diagnostic histogram. FirstSpan is a compact
// "L<line>:C<col>" of the earliest occurrence so a histogram entry is directly
// debuggable: grep the input for that line.
type RuleStat struct {
	Rule      string `json:"rule"`
	Severity  string `json:"severity"`
	Count     int64  `json:"count"`
	FirstSpan string `json:"first_span"`
}

// ResolveSample reports one set-expansion attempt during the opt-in resolve pass.
// Truncated means the expansion hit MaxPrefixes (SetTooLargeError), which is an
// expected outcome on large customer cones, not a failure.
type ResolveSample struct {
	Set       string `json:"set"`
	Class     string `json:"class"`
	ASNs      int    `json:"asns"`
	Prefixes  int    `json:"prefixes"`
	Truncated bool   `json:"truncated,omitempty"`
	Err       string `json:"err,omitempty"`
	ElapsedNS int64  `json:"elapsed_ns"`
}

// Run streams RPSL objects from r, builds the Report, and optionally runs a
// resolve-engine smoke pass. It honors ctx for cancellation: on cancel it
// returns the partial Report with a nil error (so callers can write what they
// have to disk). gzip and stream errors are returned wrapped with the partial
// Report intact.
func Run(ctx context.Context, r io.Reader, opts Options) (*Report, error) {
	opts.applyDefaults()
	start := time.Now()

	report := &Report{
		SchemaVersion: SchemaVersion,
		ClassCounts:   map[string]int64{},
		BySeverity:    map[string]int64{},
	}

	cr := &countingReader{r: r}
	br := bufio.NewReader(cr)

	// gzip auto-sniff by magic bytes; the file suffix is purely a UX nudge for
	// the caller, not a control input here.
	var src io.Reader = br
	if peek, _ := br.Peek(2); len(peek) == 2 && peek[0] == 0x1f && peek[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			report.Bytes = cr.n
			report.Elapsed = time.Since(start)
			return report, fmt.Errorf("gzip: %w", err)
		}
		defer gz.Close()
		src = gz
	}
	parsed := &countingReader{r: src}
	src = parsed

	ruleCounts := map[ruleKey]int64{}
	ruleSpans := map[ruleKey]string{}
	addDiag := func(d ast.Diagnostic) {
		report.Diagnostics++
		sev := severityString(d.Severity)
		report.BySeverity[sev]++
		k := ruleKey{rule: d.Rule, sev: sev}
		ruleCounts[k]++
		if _, ok := ruleSpans[k]; !ok {
			ruleSpans[k] = formatSpan(d.Span)
		}
	}

	var (
		autNums   []object.AutNum
		asSets    []object.AsSet
		routeSets []object.RouteSet
		routes    []object.Object // heterogeneous: Route + Route6
		truncated = map[string]int64{}
	)

	validateProfile := rpsl.RIPE
	switch opts.Validate {
	case ValidateRFCStrict:
		validateProfile = rpsl.RFCStrict
	case ValidateIRRd:
		validateProfile = rpsl.IRRd
	case ValidateARIN:
		validateProfile = rpsl.ARIN
	}

	var iterErr error
	for obj, diags := range rpsl.Parse(src) {
		if err := ctx.Err(); err != nil {
			iterErr = err
			break
		}
		class := ""
		if obj != nil {
			class = obj.Class()
		}
		if class == "" {
			// Trailing trivia (comments/blanks at EOF) parses to an empty
			// object — not a real RPSL object, so don't count it.
			continue
		}
		report.Objects++
		report.ClassCounts[class]++

		for _, d := range diags {
			addDiag(d)
		}
		typed, decDiags := rpsl.Decode(obj)
		for _, d := range decDiags {
			addDiag(d)
		}
		if opts.Validate != ValidateOff {
			for _, d := range rpsl.Validate(obj, validateProfile) {
				addDiag(d)
			}
		}

		if opts.Expand {
			switch t := typed.(type) {
			case object.AutNum:
				if len(autNums) < opts.MaxRetainAutNums {
					autNums = append(autNums, t)
				} else {
					truncated["aut-num"]++
				}
			case object.AsSet:
				if len(asSets) < opts.MaxRetainAsSets {
					asSets = append(asSets, t)
				} else {
					truncated["as-set"]++
				}
			case object.RouteSet:
				if len(routeSets) < opts.MaxRetainRouteSets {
					routeSets = append(routeSets, t)
				} else {
					truncated["route-set"]++
				}
			case object.Route:
				if len(routes) < opts.MaxRetainRoutes {
					routes = append(routes, t)
				} else {
					truncated["route"]++
				}
			case object.Route6:
				if len(routes) < opts.MaxRetainRoutes {
					routes = append(routes, t)
				} else {
					truncated["route6"]++
				}
			}
		}
	}

	report.Bytes = cr.n
	report.ParsedBytes = parsed.n
	report.ByRule = sortedRuleStats(ruleCounts, ruleSpans)
	if len(truncated) > 0 {
		report.Truncated = truncated
	}

	if opts.Expand {
		report.ResolveSamples = runResolvePass(ctx, opts, autNums, asSets, routeSets, routes)
	}

	report.Elapsed = time.Since(start)

	// Context cancellation is "graceful stop" — return the partial Report
	// without an error so callers can persist what they have. Real I/O errors
	// flow through.
	if iterErr != nil && !errors.Is(iterErr, context.Canceled) && !errors.Is(iterErr, context.DeadlineExceeded) {
		return report, iterErr
	}
	return report, nil
}

func severityString(s ast.Severity) string {
	switch s {
	case ast.Info:
		return "info"
	case ast.Warning:
		return "warning"
	case ast.Error:
		return "error"
	}
	return fmt.Sprintf("sev%d", uint8(s))
}

func formatSpan(sp lexer.Span) string {
	return fmt.Sprintf("L%d:C%d", sp.StartLine, sp.StartCol)
}

func sortedRuleStats(counts map[ruleKey]int64, spans map[ruleKey]string) []RuleStat {
	out := make([]RuleStat, 0, len(counts))
	for k, c := range counts {
		out = append(out, RuleStat{
			Rule:      k.rule,
			Severity:  k.sev,
			Count:     c,
			FirstSpan: spans[k],
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		if out[i].Rule != out[j].Rule {
			return out[i].Rule < out[j].Rule
		}
		return out[i].Severity < out[j].Severity
	})
	return out
}

// runResolvePass builds a MemSource over the retained corpus and expands either
// the explicit ExpandSets, or the largest-by-membership sample. "Largest" is
// the right sampler: first-N is biased toward alphabetical garbage, random is
// non-reproducible, and large sets are what actually exercise nested expansion,
// fan-out caps, and mbrs-by-ref joins.
func runResolvePass(ctx context.Context, opts Options, autNums []object.AutNum, asSets []object.AsSet, routeSets []object.RouteSet, routes []object.Object) []ResolveSample {
	corpus := make([]object.Object, 0, len(autNums)+len(asSets)+len(routeSets)+len(routes))
	for _, o := range autNums {
		corpus = append(corpus, o)
	}
	for _, o := range asSets {
		corpus = append(corpus, o)
	}
	for _, o := range routeSets {
		corpus = append(corpus, o)
	}
	corpus = append(corpus, routes...)

	exp := &resolve.Expander{
		Src:         resolve.NewMemSource(corpus),
		MaxDepth:    32,
		MaxPrefixes: 1_000_000,
		AFI:         types.AFIAny,
	}

	type target struct {
		name  types.SetName
		label string // reported set name; the raw input when it failed to parse
		class string
		err   error
	}
	var targets []target
	for _, raw := range opts.ExpandSets {
		sn, err := types.ParseSetName(raw)
		if err != nil {
			// We still emit a sample so the operator sees the bad input.
			targets = append(targets, target{
				label: strings.ToUpper(raw),
				class: types.ClassUnknown.String(),
				err:   err,
			})
			continue
		}
		targets = append(targets, target{name: sn, class: sn.Class().String()})
	}
	if len(opts.ExpandSets) == 0 && opts.ExpandSample > 0 {
		sort.SliceStable(asSets, func(i, j int) bool {
			a, b := asSets[i], asSets[j]
			return len(a.Members)+len(a.MbrsByRef) > len(b.Members)+len(b.MbrsByRef)
		})
		sort.SliceStable(routeSets, func(i, j int) bool {
			a, b := routeSets[i], routeSets[j]
			return len(a.Members)+len(a.MpMembers)+len(a.MbrsByRef) >
				len(b.Members)+len(b.MpMembers)+len(b.MbrsByRef)
		})
		for i := 0; i < opts.ExpandSample && i < len(asSets); i++ {
			targets = append(targets, target{name: asSets[i].Name, class: types.ClassAsSet.String()})
		}
		for i := 0; i < opts.ExpandSample && i < len(routeSets); i++ {
			targets = append(targets, target{name: routeSets[i].Name, class: types.ClassRouteSet.String()})
		}
	}

	var samples []ResolveSample
	for _, t := range targets {
		label := t.label
		if label == "" {
			label = t.name.String()
		}
		sample := ResolveSample{Set: label, Class: t.class}
		if t.err != nil {
			sample.Err = t.err.Error()
			samples = append(samples, sample)
			continue
		}
		t0 := time.Now()
		sctx, cancel := context.WithTimeout(ctx, opts.ExpandTimeout)
		var asResult resolve.ASNSet
		var asErr error
		if t.name.Class() == types.ClassAsSet { // ExpandAS is defined for as-sets only
			asResult, asErr = exp.ExpandAS(sctx, t.name)
		}
		pfxResult, pfxErr := exp.ExpandPrefixes(sctx, t.name)
		cancel()
		sample.ElapsedNS = time.Since(t0).Nanoseconds()
		sample.ASNs = asResult.Len()
		sample.Prefixes = pfxResult.Len()

		// SetTooLargeError is the documented "set blew the cap" sentinel — treat
		// it as a successful-but-truncated expansion, not an error. Both calls
		// are reported on failure so a partial expansion doesn't shadow the other.
		var tooLarge *resolve.SetTooLargeError
		switch {
		case errors.As(pfxErr, &tooLarge), errors.As(asErr, &tooLarge):
			sample.Truncated = true
		case pfxErr != nil || asErr != nil:
			sample.Err = errors.Join(asErr, pfxErr).Error()
		}
		samples = append(samples, sample)
	}

	// Stable, class-then-name order so JSON output is deterministic.
	sort.SliceStable(samples, func(i, j int) bool {
		if samples[i].Class != samples[j].Class {
			return samples[i].Class < samples[j].Class
		}
		return samples[i].Set < samples[j].Set
	})
	return samples
}

// countingReader counts compressed bytes (before any gzip layer). What's on
// disk is what the user has paid for; surfacing decompressed size would
// misrepresent throughput when grading a real run.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}
