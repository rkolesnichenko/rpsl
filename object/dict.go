package object

import (
	"sort"
	"strconv"
	"strings"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/lexer"
)

// AttrSpec describes how one attribute may appear within a class.
type AttrSpec struct {
	Required bool // must appear at least once
	Single   bool // must appear at most once
}

// ClassSpec is the attribute schema for one RPSL class. AllowUnknown permits
// attributes absent from Attrs without a diagnostic (RIPE reality carries many
// extensions); when false, any attribute not in Attrs is flagged.
type ClassSpec struct {
	Attrs        map[string]AttrSpec
	AllowUnknown bool
	// OneOf lists groups of attributes of which at least one must appear, e.g.
	// {"peering", "mp-peering"} for a peering-set (RFC 4012).
	OneOf [][]string
}

// Profile is a named class/attribute dictionary. The built-in profiles are RIPE
// (permissive, mirrors IRRd/RIPE reality) and RFCStrict (RFC 2622/2650/4012 only).
// The dictionary is data-driven so callers can supply their own profile.
type Profile struct {
	Name    string
	Classes map[string]ClassSpec
}

// Validate checks o against the profile and returns diagnostics for: an unknown
// class (dict/unknown-class), unknown attributes (dict/unknown-attr, suppressed
// when the class allows them), missing required attributes (dict/missing-required),
// (including an unmet OneOf group), and single-valued attributes appearing more
// than once (dict/cardinality). It
// never mutates o and is independent of Decode, so parsing stays resilient and
// validation is opt-in.
func (p Profile) Validate(o *ast.Object) []ast.Diagnostic {
	class := o.Class()
	spec, ok := p.Classes[class]
	if !ok {
		return []ast.Diagnostic{diag(ast.Error, "dict/unknown-class",
			"class "+strconv.Quote(class)+" is not defined in profile "+p.Name,
			classSpan(o, class))}
	}

	var diags []ast.Diagnostic
	counts := map[string]int{}
	for _, a := range o.Attributes() {
		counts[a.Name]++
		as, known := spec.Attrs[a.Name]
		if !known {
			if !spec.AllowUnknown {
				diags = append(diags, diag(ast.Warning, "dict/unknown-attr",
					"attribute "+strconv.Quote(a.Name)+" is not valid for class "+
						strconv.Quote(class)+" in profile "+p.Name, a.Span))
			}
			continue
		}
		if as.Single && counts[a.Name] == 2 { // emit once, on the second occurrence
			diags = append(diags, diag(ast.Error, "dict/cardinality",
				"attribute "+strconv.Quote(a.Name)+" must appear at most once", a.Span))
		}
	}

	// Missing-required, reported in a deterministic (sorted) order.
	var missing []string
	for name, as := range spec.Attrs {
		if as.Required && counts[name] == 0 {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	for _, name := range missing {
		diags = append(diags, diag(ast.Error, "dict/missing-required",
			"required attribute "+strconv.Quote(name)+" is missing for class "+
				strconv.Quote(class), classSpan(o, class)))
	}
	for _, group := range spec.OneOf {
		present := false
		for _, name := range group {
			present = present || counts[name] > 0
		}
		if !present {
			quoted := make([]string, len(group))
			for i, name := range group {
				quoted[i] = strconv.Quote(name)
			}
			diags = append(diags, diag(ast.Error, "dict/missing-required",
				"one of "+strings.Join(quoted, ", ")+" is required for class "+strconv.Quote(class),
				classSpan(o, class)))
		}
	}
	return diags
}

// classSpan returns the span of the class-defining first attribute, used to
// anchor whole-object diagnostics.
func classSpan(o *ast.Object, class string) lexer.Span {
	if a, ok := o.GetFirst(class); ok {
		return a.Span
	}
	return lexer.Span{}
}

func diag(sev ast.Severity, rule, msg string, span lexer.Span) ast.Diagnostic {
	return ast.Diagnostic{Severity: sev, Message: msg, Span: span, Rule: rule}
}
