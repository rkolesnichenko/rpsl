package policy

import (
	"strings"

	"github.com/rkolesnichenko/rpsl/ast"
)

// Components is a parsed components: value of a route or route6 object
// (RFC 2622 §8.1): which routes may form the aggregate.
//
//	components: ATOMIC
//	components: protocol BGP4 {128.8.0.0/16^+} protocol OSPF {128.9.0.0/16^+}
type Components struct {
	Atomic bool            // the ATOMIC keyword: the aggregate is not decomposed
	Lists  []ComponentList // one entry per [protocol] filter pair, in order
	Raw    string          // the value as written, trimmed
}

// ComponentList is one "[protocol <protocol>] <filter>" pair of a components:
// value. Protocol is "" when the pair carries no protocol clause.
type ComponentList struct {
	Protocol string
	Filter   Filter
}

// IsZero reports whether c carries nothing: no ATOMIC and no component list.
func (c Components) IsZero() bool { return !c.Atomic && len(c.Lists) == 0 }

// AggrMtd is a parsed aggr-mtd: value (RFC 2622 §8.1): how the aggregate is
// formed. Exactly one of Inbound and Outbound is true on a well-formed value;
// only the outbound form takes an AS expression.
//
//	aggr-mtd: inbound
//	aggr-mtd: outbound AS-ANY
type AggrMtd struct {
	Inbound  bool
	Outbound bool
	AS       ASExpr // the outbound form's optional as-expression; nil when absent
	Raw      string // the value as written, trimmed
}

// IsZero reports whether m carries neither method.
func (m AggrMtd) IsZero() bool { return !m.Inbound && !m.Outbound }

// ParseComponents parses a components: value. It returns a best-effort
// Components plus diagnostics; it never panics.
func ParseComponents(s string) (Components, []ast.Diagnostic) {
	c, p := parseComponentsValue(s)
	return c, p.diags
}

func parseComponentsValue(s string) (Components, *parser) {
	p := newParser(s)
	c := Components{Raw: strings.TrimSpace(s)}
	if p.empty() {
		return c, p
	}
	if p.cur().kw("atomic") {
		c.Atomic = true
		p.advance()
	}
	for !p.atEOF() && p.cur().kind != tSemi {
		before := p.pos
		var cl ComponentList
		if p.cur().kw("protocol") {
			cl.Protocol = p.protocolClause("protocol")
		}
		cl.Filter = p.parseFilter()
		if cl.Filter != nil || cl.Protocol != "" {
			c.Lists = append(c.Lists, cl)
		}
		if p.pos == before { // defensive: guarantee progress
			break
		}
	}
	p.finish()
	return c, p
}

// ParseAggrMtd parses an aggr-mtd: value. It returns a best-effort AggrMtd plus
// diagnostics; it never panics.
func ParseAggrMtd(s string) (AggrMtd, []ast.Diagnostic) {
	m, p := parseAggrMtdValue(s)
	return m, p.diags
}

func parseAggrMtdValue(s string) (AggrMtd, *parser) {
	p := newParser(s)
	m := AggrMtd{Raw: strings.TrimSpace(s)}
	if p.empty() {
		return m, p
	}
	switch t := p.cur(); {
	case t.kw("inbound"):
		m.Inbound = true
		p.advance()
	case t.kw("outbound"):
		m.Outbound = true
		p.advance()
		if !p.atEOF() && p.cur().kind != tSemi {
			if as, ok := p.parseASExpr(); ok {
				m.AS = as
			}
		}
	default:
		p.errf(t, "policy/aggr-mtd", "expected inbound or outbound, found "+describe(t))
		p.sync()
	}
	p.finish()
	return m, p
}

// ParseASExpression parses a standalone AS expression, the value of an
// aggr-bndry: attribute (RFC 2622 §8.1). It returns a best-effort ASExpr plus
// diagnostics; it never panics. The result is nil when nothing could be parsed.
func ParseASExpression(s string) (ASExpr, []ast.Diagnostic) {
	as, p := parseASExpressionValue(s)
	return as, p.diags
}

func parseASExpressionValue(s string) (ASExpr, *parser) {
	p := newParser(s)
	if p.empty() {
		return nil, p
	}
	as, ok := p.parseASExpr()
	if !ok {
		as = nil
	}
	p.finish()
	return as, p
}
