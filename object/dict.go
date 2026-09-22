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
// (the RIPE Database's own templates) and RFCStrict (the RFC 2622, 2725, 2726
// and 4012 tables). The dictionary is data-driven so callers can supply their
// own with NewProfile. A Profile is read-only: its accessors return copies, so no user
// of a shared profile such as RIPE can change what Validate does for another.
type Profile struct {
	name    string
	classes map[string]ClassSpec
}

// NewProfile returns a profile with the given class schemas, keyed by class
// name. It copies classes, so later changes to the map do not affect it.
func NewProfile(name string, classes map[string]ClassSpec) Profile {
	c := make(map[string]ClassSpec, len(classes))
	for class, spec := range classes {
		c[class] = spec.clone()
	}
	return Profile{name: name, classes: c}
}

// Name returns the profile's name, e.g. "RIPE".
func (p Profile) Name() string { return p.name }

// Class returns a copy of the schema for class, and whether the profile
// defines it.
func (p Profile) Class(class string) (ClassSpec, bool) {
	spec, ok := p.classes[class]
	return spec.clone(), ok
}

// Classes returns the names of the classes the profile defines, sorted.
func (p Profile) Classes() []string {
	names := make([]string, 0, len(p.classes))
	for class := range p.classes {
		names = append(names, class)
	}
	sort.Strings(names)
	return names
}

// clone returns a deep copy of c.
func (c ClassSpec) clone() ClassSpec {
	out := ClassSpec{AllowUnknown: c.AllowUnknown}
	if c.Attrs != nil {
		out.Attrs = make(map[string]AttrSpec, len(c.Attrs))
		for name, as := range c.Attrs {
			out.Attrs[name] = as
		}
	}
	for _, group := range c.OneOf {
		out.OneOf = append(out.OneOf, append([]string(nil), group...))
	}
	return out
}

// Validate checks o against the profile and returns diagnostics for: an unknown
// class (dict/unknown-class), unknown attributes (dict/unknown-attr, suppressed
// when the class allows them), missing required attributes, including one that
// is present but empty and an unmet OneOf group (dict/missing-required), and
// single-valued attributes appearing more than once (dict/cardinality). It
// never mutates o and is independent of Decode, so parsing stays resilient and
// validation is opt-in.
func (p Profile) Validate(o *ast.Object) []ast.Diagnostic {
	if o == nil {
		return nil
	}
	class := o.Class()
	spec, ok := p.classes[class]
	if !ok {
		return []ast.Diagnostic{diag(ast.Error, "dict/unknown-class",
			"class "+strconv.Quote(class)+" is not defined in profile "+p.name,
			classSpan(o, class))}
	}

	var diags []ast.Diagnostic
	counts := map[string]int{} // occurrences, for cardinality
	filled := map[string]int{} // occurrences with a value, for presence
	firstEmpty := map[string]ast.Attribute{}
	for _, a := range o.Attributes() {
		counts[a.Name]++
		if strings.TrimSpace(a.Value) != "" {
			filled[a.Name]++
		} else if _, seen := firstEmpty[a.Name]; !seen {
			firstEmpty[a.Name] = a
		}
		as, known := spec.Attrs[a.Name]
		if !known {
			if !spec.AllowUnknown {
				diags = append(diags, diag(ast.Warning, "dict/unknown-attr",
					"attribute "+strconv.Quote(a.Name)+" is not valid for class "+
						strconv.Quote(class)+" in profile "+p.name, a.Span))
			}
			continue
		}
		if as.Single && counts[a.Name] == 2 { // emit once, on the second occurrence
			diags = append(diags, diag(ast.Error, "dict/cardinality",
				"attribute "+strconv.Quote(a.Name)+" must appear at most once", a.Span))
		}
	}

	// Missing-required, reported in a deterministic (sorted) order. A required
	// attribute whose every occurrence is empty is reported at the first one.
	var missing []string
	for name, as := range spec.Attrs {
		if as.Required && filled[name] == 0 {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	for _, name := range missing {
		if a, ok := firstEmpty[name]; ok {
			diags = append(diags, diag(ast.Error, "dict/missing-required",
				"required attribute "+strconv.Quote(name)+" is empty", a.Span))
			continue
		}
		diags = append(diags, diag(ast.Error, "dict/missing-required",
			"required attribute "+strconv.Quote(name)+" is missing for class "+
				strconv.Quote(class), classSpan(o, class)))
	}
	for _, group := range spec.OneOf {
		present := false
		for _, name := range group {
			present = present || filled[name] > 0
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
