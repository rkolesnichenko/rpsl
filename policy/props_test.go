package policy

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/ast"
)

// Properties every policy parse must have, checked by the fuzz targets on
// whatever they parse: diagnostics point inside the value and stop at the cap,
// the AST is no deeper than the nesting cap, every Raw is a piece of the value,
// and neither keyword case nor extra whitespace changes what is parsed.

// checkParse asserts the properties of one parse of s, whose result is v.
func checkParse(t *testing.T, s string, v any, diags []ast.Diagnostic, reparse func(string) (any, []ast.Diagnostic)) {
	t.Helper()
	if len(diags) > maxDiagnostics+1 {
		t.Fatalf("%q: %d diagnostics, over the cap of %d", s, len(diags), maxDiagnostics+1)
	}
	for _, d := range diags {
		if sp := d.Span; sp.StartByte < 0 || sp.EndByte > len(s) || sp.StartByte > sp.EndByte {
			t.Fatalf("%q: diagnostic %v points outside the value", s, d)
		}
	}
	if d := depth(reflect.ValueOf(v)); d > maxParseDepth+8 {
		t.Fatalf("%q: AST depth %d, over the nesting cap %d", s, d, maxParseDepth)
	}
	eachRaw(reflect.ValueOf(v), func(raw string) {
		if !strings.Contains(s, raw) {
			t.Fatalf("%q: Raw %q is not part of the value", s, raw)
		}
	})
	eachValue(reflect.ValueOf(v), func(x any) {
		if c, ok := x.(FilterCommunity); ok && !strings.HasPrefix(strings.ToLower(c.Raw), "community") {
			t.Fatalf("%q: %q was read as a community test", s, c.Raw)
		}
	})
	if reparse == nil || len(s) > 1<<12 {
		return
	}
	want, wantRules := render(v), diagRules(diags)
	for _, variant := range []string{swapKeywordCase(s), widenSpaces(s)} {
		got, ds := reparse(variant)
		if r := render(got); r != want || strings.Join(diagRules(ds), " ") != strings.Join(wantRules, " ") {
			t.Fatalf("%q parses as\n%s %v\nbut %q as\n%s %v", s, want, wantRules, variant, r, diagRules(ds))
		}
	}
}

var keywords = map[string]bool{"from": true, "to": true, "accept": true, "announce": true, "action": true,
	"except": true, "refine": true, "and": true, "or": true, "not": true, "any": true, "peeras": true,
	"at": true, "afi": true, "networks": true, "protocol": true, "into": true}

// swapKeywordCase changes the case of every keyword token of s.
func swapKeywordCase(s string) string {
	toks, ok := tokenize(s)
	if !ok {
		return s
	}
	var b strings.Builder
	last := 0
	for _, tk := range toks {
		if tk.kind != tWord || !keywords[strings.ToLower(tk.text)] {
			continue
		}
		b.WriteString(s[last:tk.start])
		for _, r := range tk.text {
			switch {
			case 'a' <= r && r <= 'z':
				r -= 'a' - 'A'
			case 'A' <= r && r <= 'Z':
				r += 'a' - 'A'
			}
			b.WriteRune(r)
		}
		last = tk.end
	}
	b.WriteString(s[last:])
	return b.String()
}

// widenSpaces adds whitespace wherever s already separates two tokens.
func widenSpaces(s string) string {
	toks, ok := tokenize(s)
	if !ok {
		return s
	}
	var b strings.Builder
	last := 0
	for _, tk := range toks {
		if gap := s[last:tk.start]; gap != "" {
			b.WriteString(gap + " \t ")
		}
		b.WriteString(s[tk.start:tk.end])
		last = tk.end
	}
	b.WriteString(s[last:])
	return b.String()
}

// render prints v for comparing parses: Raw fields are left out, and strings
// are lower-cased with whitespace runs collapsed, as RPSL does not tell them
// apart.
func render(v any) string {
	var b strings.Builder
	var walk func(v reflect.Value)
	walk = func(v reflect.Value) {
		if !v.IsValid() {
			b.WriteString("nil")
			return
		}
		if s, ok := v.Interface().(fmt.Stringer); ok && v.Kind() != reflect.Interface && v.Kind() != reflect.Pointer {
			b.WriteString(strings.ToLower(s.String()))
			return
		}
		switch v.Kind() {
		case reflect.Interface, reflect.Pointer:
			if v.IsNil() {
				b.WriteString("nil")
				return
			}
			walk(v.Elem())
		case reflect.Struct:
			b.WriteString(v.Type().Name() + "{")
			for i := 0; i < v.NumField(); i++ {
				if f := v.Type().Field(i); f.IsExported() && f.Name != "Raw" {
					b.WriteString(f.Name + ":")
					walk(v.Field(i))
					b.WriteString(" ")
				}
			}
			b.WriteString("}")
		case reflect.Slice:
			b.WriteString("[")
			for i := 0; i < v.Len(); i++ {
				walk(v.Index(i))
				b.WriteString(" ")
			}
			b.WriteString("]")
		case reflect.String:
			b.WriteString(strings.Join(strings.Fields(strings.ToLower(v.String())), " "))
		default:
			fmt.Fprint(&b, v.Interface())
		}
	}
	walk(reflect.ValueOf(v))
	return b.String()
}

// depth counts the AST nodes (interface values) on the longest path in v.
func depth(v reflect.Value) int {
	switch v.Kind() {
	case reflect.Interface, reflect.Pointer:
		if v.IsNil() {
			return 0
		}
		d := depth(v.Elem())
		if v.Kind() == reflect.Interface {
			d++
		}
		return d
	case reflect.Struct:
		m := 0
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() {
				m = max(m, depth(v.Field(i)))
			}
		}
		return m
	case reflect.Slice:
		m := 0
		for i := 0; i < v.Len(); i++ {
			m = max(m, depth(v.Index(i)))
		}
		return m
	}
	return 0
}

// eachRaw calls fn with every Raw string field in v.
func eachRaw(v reflect.Value, fn func(string)) {
	switch v.Kind() {
	case reflect.Interface, reflect.Pointer:
		if !v.IsNil() {
			eachRaw(v.Elem(), fn)
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			f := v.Type().Field(i)
			switch {
			case !f.IsExported():
			case f.Name == "Raw" && f.Type.Kind() == reflect.String:
				fn(v.Field(i).String())
			default:
				eachRaw(v.Field(i), fn)
			}
		}
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			eachRaw(v.Index(i), fn)
		}
	}
}

// eachValue calls fn with every exported value in v, v included.
func eachValue(v reflect.Value, fn func(any)) {
	if !v.IsValid() {
		return
	}
	if v.CanInterface() {
		fn(v.Interface())
	}
	switch v.Kind() {
	case reflect.Interface, reflect.Pointer:
		if !v.IsNil() {
			eachValue(v.Elem(), fn)
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() {
				eachValue(v.Field(i), fn)
			}
		}
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			eachValue(v.Index(i), fn)
		}
	}
}
