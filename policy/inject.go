package policy

import (
	"strings"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/types"
)

// Inject is a parsed inject: value of a route or route6 object (RFC 2622 §8.1):
// where an aggregate is injected, what it does to the route, and the condition
// under which it is injected at all. Every part is optional.
//
//	inject: at 1.1.1.1 action dpa = 100; upon HAVE-COMPONENTS {128.8.0.0/16}
type Inject struct {
	At      RouterExpr // "at <router-expression>"; nil when absent
	Actions []Action   // "action <action>; <action>"
	Upon    InjectCond // "upon <condition>"; nil when absent
	Raw     string     // the value as written, trimmed
}

// InjectCond is the sealed inject: condition node (RFC 2622 §8.1): the tests
// HAVE-COMPONENTS, EXCLUDE and STATIC composed with AND, OR and NOT.
type InjectCond interface{ isInjectCond() }

// InjectStatic is the STATIC test: the aggregate is injected unconditionally.
type InjectStatic struct{}

// InjectHaveComponents is "HAVE-COMPONENTS {…}": the aggregate is injected when
// every listed prefix is in the routing table.
type InjectHaveComponents struct{ Ranges []types.PrefixRange }

// InjectExclude is "EXCLUDE {…}": the aggregate is injected when none of the
// listed prefixes is in the routing table.
type InjectExclude struct{ Ranges []types.PrefixRange }

// InjectAnd holds two or more conditions that must all hold.
type InjectAnd struct{ Terms []InjectCond }

// InjectOr holds two or more conditions of which at least one must hold.
type InjectOr struct{ Terms []InjectCond }

// InjectNot negates a condition.
type InjectNot struct{ Inner InjectCond }

func (InjectStatic) isInjectCond()         {}
func (InjectHaveComponents) isInjectCond() {}
func (InjectExclude) isInjectCond()        {}
func (InjectAnd) isInjectCond()            {}
func (InjectOr) isInjectCond()             {}
func (InjectNot) isInjectCond()            {}

// injectStops are the keywords that end a clause inside an inject: value, so
// that "at 1.1.1.1 upon STATIC" does not read "upon" as another router.
var injectStops = []string{"at", "upon"}

// ParseInject parses an inject: value. It returns a best-effort Inject plus
// diagnostics; it never panics.
func ParseInject(s string) (Inject, []ast.Diagnostic) {
	in, p := parseInjectValue(s)
	return in, p.diags
}

func parseInjectValue(s string) (Inject, *parser) {
	p := newParser(s)
	p.stops = injectStops
	in := Inject{Raw: strings.TrimSpace(s)}
	if p.empty() {
		return in, p
	}
	in.At, in.Actions, in.Upon = p.parseInjectClauses()
	p.finish()
	return in, p
}

// parseInjectClauses reads the three optional clauses in order. A clause out of
// order, or repeated, is diagnosed where it is found rather than silently
// accepted, because RFC 2622 §8.1 fixes the order.
func (p *parser) parseInjectClauses() (at RouterExpr, actions []Action, upon InjectCond) {
	if p.cur().kw("at") {
		p.advance()
		at = p.parseRouterExpr()
	}
	if p.cur().kw("action") {
		p.advance()
		actions = p.parseActions()
	}
	if p.cur().kw("upon") {
		p.advance()
		upon = p.parseInjectCond()
	}
	return at, actions, upon
}

// parseInjectCond parses the condition grammar: OR is lowest, then AND, then
// NOT, with parentheses overriding — the same precedence as a policy filter.
func (p *parser) parseInjectCond() InjectCond {
	return p.parseInjectOr()
}

// An OR or AND chain is one flat node however long it is, as in a filter, so
// it costs one level of nesting, not one per operator.
func (p *parser) parseInjectOr() InjectCond {
	first := p.parseInjectAnd()
	if !p.cur().kw("or") {
		return first
	}
	if !p.enter() {
		return nil
	}
	defer p.leave()
	terms := []InjectCond{first}
	for p.cur().kw("or") {
		p.advance()
		terms = append(terms, p.parseInjectAnd())
	}
	return InjectOr{Terms: terms}
}

func (p *parser) parseInjectAnd() InjectCond {
	first := p.parseInjectNot()
	if !p.cur().kw("and") {
		return first
	}
	if !p.enter() {
		return nil
	}
	defer p.leave()
	terms := []InjectCond{first}
	for p.cur().kw("and") {
		p.advance()
		terms = append(terms, p.parseInjectNot())
	}
	return InjectAnd{Terms: terms}
}

func (p *parser) parseInjectNot() InjectCond {
	if p.cur().kw("not") {
		if !p.enter() {
			return nil
		}
		defer p.leave()
		p.advance()
		inner := p.parseInjectNot()
		if inner == nil {
			return nil
		}
		return InjectNot{Inner: inner}
	}
	return p.parseInjectPrim()
}

func (p *parser) parseInjectPrim() InjectCond {
	t := p.cur()
	switch {
	case t.kind == tLParen:
		if !p.enter() {
			return nil
		}
		defer p.leave()
		p.advance()
		c := p.parseInjectOr()
		if p.cur().kind != tRParen {
			p.errf(p.cur(), "policy/inject", "expected ')' in inject condition")
			return c
		}
		p.advance()
		return c
	case t.kw("static"):
		p.advance()
		return InjectStatic{}
	case t.kw("have-components"):
		p.advance()
		return InjectHaveComponents{Ranges: p.injectRanges("HAVE-COMPONENTS")}
	case t.kw("exclude"):
		p.advance()
		return InjectExclude{Ranges: p.injectRanges("EXCLUDE")}
	}
	p.errf(t, "policy/inject",
		"expected STATIC, HAVE-COMPONENTS, EXCLUDE, NOT or '(' in inject condition")
	return nil
}

// injectRanges reads the brace-enclosed prefix list a HAVE-COMPONENTS or
// EXCLUDE test takes, reusing the filter grammar's list parser so that the
// prefix diagnostics are identical everywhere.
func (p *parser) injectRanges(kw string) []types.PrefixRange {
	if p.cur().kind != tLBrace {
		p.errf(p.cur(), "policy/inject", "expected '{' after "+kw)
		return nil
	}
	list, _ := p.parsePrefixList().(FilterPrefixList)
	return list.Ranges
}
