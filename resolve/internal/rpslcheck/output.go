package rpslcheck

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/consist"
	"github.com/rkolesnichenko/rpsl/types"
)

// writer writes findings and issues as text or JSON lines.
type writer struct {
	out  io.Writer
	json bool
	only ast.Severity // the least severity written (the sweep's text writes Warnings only)
}

func newWriter(out io.Writer, asJSON bool) *writer {
	return &writer{out: out, json: asJSON, only: ast.Info}
}

func sev(s ast.Severity) string { return strings.ToLower(s.String()) }

func (w *writer) emit(v any) {
	b, _ := json.Marshal(v) // every value written is plain data: Marshal cannot fail
	fmt.Fprintf(w.out, "%s\n", b)
}

// attrLines maps an aut-num's attribute positions to their line numbers in
// its text: kind "import" (import:, mp-import:), "export" or "default".
func attrLines(an object.AutNum, kind string) []int {
	raw := an.Raw()
	if raw == nil {
		return nil
	}
	var out []int
	for _, a := range raw.Attributes() {
		if a.Name == kind || a.Name == "mp-"+kind {
			out = append(out, a.Span.StartLine)
		}
	}
	return out
}

// linesOf returns the lines of the given attribute indexes.
func linesOf(all []int, idx []int) []int {
	var out []int
	for _, i := range idx {
		if i >= 0 && i < len(all) {
			out = append(out, all[i])
		}
	}
	return out
}

func lineText(lines []int) string {
	switch len(lines) {
	case 0:
		return ""
	case 1:
		return fmt.Sprintf(" (line %d)", lines[0])
	}
	var parts []string
	for _, l := range lines {
		parts = append(parts, fmt.Sprint(l))
	}
	return " (lines " + strings.Join(parts, ", ") + ")"
}

func rangesText(f consist.Finding) string {
	var parts []string
	for i, r := range f.Ranges {
		if i == 3 {
			break
		}
		parts = append(parts, r.String())
	}
	s := strings.Join(parts, ", ")
	more := ""
	if len(f.Ranges) > 3 || f.Truncated {
		n := fmt.Sprint(len(f.Ranges))
		if f.Truncated {
			n += "+"
		}
		s += ", …"
		more = n + " ranges; "
	}
	if f.Example.IsValid() {
		return fmt.Sprintf("%s (%se.g. %s)", s, more, f.Example)
	}
	return s
}

func afText(afs []types.AddrFamily) []string {
	var out []string
	for _, af := range afs {
		out = append(out, af.String())
	}
	return out
}

func asText(ases []types.ASN) []string {
	var out []string
	for _, a := range ases {
		out = append(out, a.String())
	}
	return out
}

// lint writes as's issues; it reports whether any is a Warning.
func (w *writer) lint(as types.ASN, an object.AutNum, issues []consist.Issue) (warned bool) {
	lines := map[string][]int{"import": attrLines(an, "import"), "export": attrLines(an, "export"), "default": attrLines(an, "default")}
	header := false
	for _, is := range issues {
		warned = warned || is.Severity >= ast.Warning
		if is.Severity < w.only {
			continue
		}
		line := 0
		if is.Index >= 0 {
			kind := strings.TrimPrefix(is.Attr, "mp-")
			if l := linesOf(lines[kind], []int{is.Index}); len(l) == 1 {
				line = l[0]
			}
		}
		if w.json {
			w.emit(struct {
				Type     string   `json:"type"`
				AS       string   `json:"as"`
				Rule     string   `json:"rule"`
				Severity string   `json:"severity"`
				Message  string   `json:"message"`
				Attr     string   `json:"attr,omitempty"`
				Index    int      `json:"index"`
				Line     int      `json:"line,omitempty"`
				Peers    []string `json:"peers,omitempty"`
				AFs      []string `json:"afs,omitempty"`
			}{"issue", as.String(), is.Rule, sev(is.Severity), is.Message, is.Attr, is.Index, line, asText(is.Peers), afText(is.AFs)})
			continue
		}
		if w.only > ast.Info { // the sweep: one self-contained line per Warning
			fmt.Fprintf(w.out, "%s %s\n", as, issueText(is, line))
			continue
		}
		if !header {
			fmt.Fprintf(w.out, "%s lint\n", as)
			header = true
		}
		fmt.Fprintf(w.out, "  %s\n", issueText(is, line))
	}
	return warned
}

func issueText(is consist.Issue, line int) string {
	s := sev(is.Severity) + " " + is.Rule
	if is.Index >= 0 {
		s += " " + is.Attr
		if line > 0 {
			s += fmt.Sprintf(" (line %d)", line)
		}
	}
	s += ": " + is.Message
	if len(is.Peers) > 0 {
		s += " [" + strings.Join(asText(is.Peers), ", ")
		if len(is.AFs) > 0 {
			s += "; " + strings.Join(afText(is.AFs), ", ")
		}
		s += "]"
	}
	return s
}

// report writes both directions of a pair; it reports whether any finding
// is a Warning.
func (w *writer) report(ctx context.Context, src resolve.PolicySource, rep consist.Report) (warned bool) {
	for _, d := range []consist.Direction{rep.AtoB, rep.BtoA} {
		if w.direction(ctx, src, d, rep.Pair.AF) {
			warned = true
		}
	}
	return warned
}

func (w *writer) direction(ctx context.Context, src resolve.PolicySource, d consist.Direction, af types.AddrFamily) (warned bool) {
	from, _ := src.AutNum(ctx, d.From, "")
	to, _ := src.AutNum(ctx, d.To, "")
	expLines, impLines := attrLines(from, "export"), attrLines(to, "import")
	head := fmt.Sprintf("%s -> %s %s", d.From, d.To, af)
	if w.json {
		w.emit(struct {
			Type     string `json:"type"`
			From     string `json:"from"`
			To       string `json:"to"`
			AF       string `json:"af"`
			Findings int    `json:"findings"`
			NoPolicy bool   `json:"no_policy,omitempty"`
		}{"direction", d.From.String(), d.To.String(), af.String(), len(d.Findings), d.NoPolicy})
	} else if d.NoPolicy && w.only == ast.Info {
		fmt.Fprintf(w.out, "%s: no policy either way\n", head)
	} else if len(d.Findings) == 0 && w.only == ast.Info {
		fmt.Fprintf(w.out, "%s: consistent\n", head)
	} else if w.only == ast.Info {
		fmt.Fprintln(w.out, head)
	}
	for _, f := range d.Findings {
		warned = warned || f.Severity >= ast.Warning
		if f.Severity < w.only {
			continue
		}
		el, il := linesOf(expLines, f.Export), linesOf(impLines, f.Import)
		if w.json {
			var ranges []string
			for _, r := range f.Ranges {
				ranges = append(ranges, r.String())
			}
			ex := ""
			if f.Example.IsValid() {
				ex = f.Example.String()
			}
			of, as := "", ""
			if f.Kind == consist.Undecided {
				of = f.Of.String()
			}
			if f.Kind == consist.NoAutNum {
				as = f.AS.String()
			}
			w.emit(struct {
				Type        string   `json:"type"`
				From        string   `json:"from"`
				To          string   `json:"to"`
				AF          string   `json:"af"`
				Kind        string   `json:"kind"`
				Of          string   `json:"of,omitempty"`
				Severity    string   `json:"severity"`
				AS          string   `json:"as,omitempty"`
				Example     string   `json:"example,omitempty"`
				Ranges      []string `json:"ranges,omitempty"`
				Truncated   bool     `json:"truncated,omitempty"`
				Given       []string `json:"given,omitempty"`
				ExportLines []int    `json:"export_lines,omitempty"`
				ImportLines []int    `json:"import_lines,omitempty"`
				Why         string   `json:"why,omitempty"`
			}{"finding", d.From.String(), d.To.String(), af.String(), f.Kind.String(), of, sev(f.Severity), as, ex,
				ranges, f.Truncated, f.Given, el, il, f.Why})
			continue
		}
		text := findingText(d, f, el, il)
		if w.only > ast.Info {
			if len(f.Given) > 0 {
				text += " [given: " + strings.Join(f.Given, " AND ") + "]"
			}
			fmt.Fprintf(w.out, "%s %s\n", head, text)
			continue
		}
		fmt.Fprintf(w.out, "  %s\n", text)
		if len(f.Given) > 0 {
			fmt.Fprintf(w.out, "    given: %s\n", strings.Join(f.Given, " AND "))
		}
	}
	return warned
}

func findingText(d consist.Direction, f consist.Finding, el, il []int) string {
	s := sev(f.Severity) + " " + f.Kind.String() + ": "
	switch f.Kind {
	case consist.NotImported:
		s += fmt.Sprintf("%s's export%s permits announcing routes %s's import%s refuses: %s", d.From, lineText(el), d.To, lineText(il), rangesText(f))
	case consist.NotExported:
		s += fmt.Sprintf("%s's import%s accepts routes %s's export%s does not permit announcing: %s", d.To, lineText(il), d.From, lineText(el), rangesText(f))
	case consist.NoImport:
		s += fmt.Sprintf("%s exports to %s, and %s's import has nothing from %s", d.From, d.To, d.To, d.From)
	case consist.NoExport:
		s += fmt.Sprintf("%s imports from %s, and %s's export has nothing toward %s", d.To, d.From, d.From, d.To)
	case consist.NoAutNum:
		s += fmt.Sprintf("%s's aut-num is not in the source", f.AS)
	case consist.Undecided:
		s += fmt.Sprintf("may be %s (%s): %s", f.Of, f.Why, rangesText(f))
	}
	return s
}
