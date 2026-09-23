package policy

import (
	"strconv"
	"strings"

	"github.com/rkolesnichenko/rpsl/types"
)

// Canonical text for the policy AST. Every String here renders from the parsed
// structure, never from a Raw field, so it is one spelling per meaning: two
// values that parse alike print alike, whatever whitespace or keyword case the
// source used. That is what makes the AST usable for generating router
// configuration, which design §7 names as the real use for keeping these
// expressions structured.
//
// Parentheses are added only where precedence needs them: NOT binds tighter
// than AND, which binds tighter than OR, in filters and in AS and router
// expressions alike (RFC 2622 §5.4, §5.6).
//
// The lossless round-trip guarantee lives in the ast layer, over the original
// bytes; these renderings are canonical, not byte-identical to the source.

// Operator precedence levels, lowest first.
const (
	precOr  = iota + 1 // a OR b
	precAnd            // a AND b, a EXCEPT b
	precNot            // NOT a
	precAtom
)

// paren wraps s in parentheses when the node's precedence is looser than the
// context requires.
func paren(s string, have, want int) string {
	if have < want {
		return "(" + s + ")"
	}
	return s
}

// String renders the AS expression in canonical form.
func (e ASNum) String() string { return e.AS.String() }

// String renders the as-set reference in canonical form.
func (e ASSetRef) String() string { return e.Name.String() }

// String renders the per-peer as-set template in its original spelling.
func (e ASSetTemplate) String() string { return e.Template.String() }

// String renders the binary AS expression, parenthesized where precedence needs it.
func (e ASExprBinary) String() string { return asExprString(e, precOr) }

// asExprString renders an AS expression for a context of the given precedence.
func asExprString(e ASExpr, want int) string {
	b, ok := e.(ASExprBinary)
	if !ok {
		return exprText(e)
	}
	op, have := " OR ", precOr
	switch b.Op {
	case ASAnd:
		op, have = " AND ", precAnd
	case ASExcept:
		op, have = " EXCEPT ", precAnd
	}
	// AND and EXCEPT are left-associative, so the right operand of a chain at
	// the same level still needs its own parentheses.
	s := asExprString(b.L, have) + op + asExprString(b.R, have+1)
	return paren(s, have, want)
}

// String renders the router address.
func (e RouterAddr) String() string { return e.Addr.String() }

// String renders the inet-rtr name.
func (e RouterName) String() string { return e.Name }

// String renders the rtr-set reference in canonical form.
func (e RouterSetRef) String() string { return e.Name.String() }

// String renders the binary router expression, parenthesized where needed.
func (e RouterExprBinary) String() string { return routerExprString(e, precOr) }

func routerExprString(e RouterExpr, want int) string {
	b, ok := e.(RouterExprBinary)
	if !ok {
		return exprText(e)
	}
	op, have := " OR ", precOr
	switch b.Op {
	case RouterAnd:
		op, have = " AND ", precAnd
	case RouterExcept:
		op, have = " EXCEPT ", precAnd
	}
	s := routerExprString(b.L, have) + op + routerExprString(b.R, have+1)
	return paren(s, have, want)
}

// String renders the peering: an AS expression with its optional routers.
func (e PeeringAS) String() string {
	var b strings.Builder
	if e.AS != nil {
		b.WriteString(asExprString(e.AS, precOr))
	}
	if e.Router != nil {
		b.WriteString(" " + routerExprString(e.Router, precOr))
	}
	if e.AtRouter != nil {
		b.WriteString(" at " + routerExprString(e.AtRouter, precOr))
	}
	return b.String()
}

// String renders the peering-set reference in canonical form.
func (e PeeringSetRef) String() string { return e.Name.String() }

// String renders the AS-path regexp, brackets included. The body keeps its
// original spelling: it is the only representation the regexp sub-AST records.
func (e PeeringRegexp) String() string { return "<" + e.Raw + ">" }

// String renders the ANY filter.
func (FilterAny) String() string { return "ANY" }

// String renders the PeerAS filter with its range operator.
func (f FilterPeerAS) String() string { return "PeerAS" + f.Op.String() }

// String renders the prefix list.
func (f FilterPrefixList) String() string {
	parts := make([]string, len(f.Ranges))
	for i, r := range f.Ranges {
		parts[i] = r.String()
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// String renders the AS-expression filter with its range operator.
func (f FilterASExpr) String() string {
	// A range operator binds to one term, so a binary expression needs parentheses.
	want := precOr
	if !f.Op.IsZero() {
		want = precAtom
	}
	return asExprString(f.AS, want) + f.Op.String()
}

// String renders the set reference with its range operator.
func (f FilterSetRef) String() string { return f.Name.String() + f.Op.String() }

// String renders the per-peer set template with its range operator.
func (f FilterSetTemplate) String() string { return f.Template.String() + f.Op.String() }

// String renders the AS-path regexp, brackets included.
func (f FilterPathRE) String() string { return "<" + f.Raw + ">" }

// String renders the community test. A community value is uninterpreted text,
// so it keeps its spelling with whitespace runs collapsed — RPSL does not tell
// those runs apart, and leaving them in would make two spellings of one test
// render differently.
func (f FilterCommunity) String() string {
	vals := make([]string, len(f.Values))
	for i, v := range f.Values {
		vals[i] = collapse(v)
	}
	if f.Op == CommunityEquals {
		return "community == {" + strings.Join(vals, ", ") + "}"
	}
	return "community(" + strings.Join(vals, ", ") + ")"
}

// String renders the AND filter, parenthesized where precedence needs it.
func (f FilterAnd) String() string { return filterString(f, precOr) }

// String renders the OR filter.
func (f FilterOr) String() string { return filterString(f, precOr) }

// String renders the NOT filter.
func (f FilterNot) String() string { return filterString(f, precOr) }

// filterString renders a filter for a context of the given precedence.
func filterString(f Filter, want int) string {
	switch x := f.(type) {
	case FilterAnd:
		return paren(joinFilters(x.Terms, " AND ", precAnd), precAnd, want)
	case FilterOr:
		return paren(joinFilters(x.Terms, " OR ", precOr), precOr, want)
	case FilterNot:
		return paren("NOT "+filterString(x.Inner, precNot), precNot, want)
	}
	return exprText(f)
}

func joinFilters(terms []Filter, sep string, prec int) string {
	parts := make([]string, len(terms))
	for i, t := range terms {
		parts[i] = filterString(t, prec)
	}
	return strings.Join(parts, sep)
}

// String renders one peering clause with its actions. A via peering is left
// out: it stands before the clause's "from" or "to", which a policy's String
// writes and a PeerAction does not know.
func (p PeerAction) String() string {
	s := exprText(p.Peering)
	if len(p.Actions) > 0 {
		s += " action " + actionsString(p.Actions)
	}
	return s
}

// String renders one action in canonical form. It renders from the parsed
// Attr/Method/Op/Args/Value rather than from Raw, so spacing in the source does
// not leak into the output; the uninterpreted parts (a value, a method's
// arguments) keep their text with whitespace runs collapsed.
func (a Action) String() string {
	switch a.Op {
	case ActionAssign:
		return a.Attr + " = " + collapse(a.Value)
	case ActionAppend:
		return a.Attr + " .= " + collapse(a.Value)
	}
	if op := strings.TrimPrefix(a.Method, "operator"); op != a.Method {
		// An RFC 2622 Figure 25 operator, kept as the method it names.
		return a.Attr + " " + op + " " + collapse(strings.Join(a.Args, ", "))
	}
	args := make([]string, len(a.Args))
	for i, x := range a.Args {
		args[i] = collapse(x)
	}
	return a.Attr + "." + a.Method + "(" + strings.Join(args, ", ") + ")"
}

// collapse trims s and reduces every run of whitespace in it to one space, as
// RPSL does not tell such runs apart.
func collapse(s string) string { return strings.Join(strings.Fields(s), " ") }

// actionsString renders an action list, each action closed by a ';' as RFC 2622
// §6.1.1 writes them.
func actionsString(as []Action) string {
	parts := make([]string, len(as))
	for i, a := range as {
		parts[i] = a.String() + ";"
	}
	return strings.Join(parts, " ")
}

// String renders the inject: condition, parenthesized where precedence needs it.
func (c InjectStatic) String() string         { return "STATIC" }
func (c InjectHaveComponents) String() string { return "HAVE-COMPONENTS " + rangesString(c.Ranges) }
func (c InjectExclude) String() string        { return "EXCLUDE " + rangesString(c.Ranges) }
func (c InjectAnd) String() string            { return injectString(c, precOr) }
func (c InjectOr) String() string             { return injectString(c, precOr) }
func (c InjectNot) String() string            { return injectString(c, precOr) }

func injectString(c InjectCond, want int) string {
	switch x := c.(type) {
	case InjectAnd:
		return paren(joinInject(x.Terms, " AND ", precAnd), precAnd, want)
	case InjectOr:
		return paren(joinInject(x.Terms, " OR ", precOr), precOr, want)
	case InjectNot:
		return paren("NOT "+injectString(x.Inner, precNot), precNot, want)
	}
	return exprText(c)
}

func joinInject(terms []InjectCond, sep string, prec int) string {
	parts := make([]string, len(terms))
	for i, t := range terms {
		parts[i] = injectString(t, prec)
	}
	return strings.Join(parts, sep)
}

func rangesString[T interface{ String() string }](rs []T) string {
	parts := make([]string, len(rs))
	for i, r := range rs {
		parts[i] = r.String()
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// exprText renders a node that carries no precedence of its own, and "" for a
// nil interface, so a partially parsed AST still prints.
func exprText(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(interface{ String() string }); ok {
		return s.String()
	}
	return ""
}

// String renders the ifaddr: value in canonical form.
func (v Ifaddr) String() string {
	s := v.Addr.String()
	if v.Masklen >= 0 {
		s += " masklen " + strconv.Itoa(v.Masklen)
	}
	if len(v.Actions) > 0 {
		s += " action " + actionsString(v.Actions)
	}
	return s
}

// String renders the peering option in canonical form. An argument is
// uninterpreted text, so it keeps its spelling with whitespace runs collapsed —
// the same rule a community value follows, and for the same reason.
func (o PeerOption) String() string {
	args := make([]string, len(o.Args))
	for i, a := range o.Args {
		args[i] = collapse(a)
	}
	return o.Name + "(" + strings.Join(args, ", ") + ")"
}

// String renders the import: or mp-import: policy in canonical form.
func (i Import) String() string {
	return policyString(i.Protocol, i.IntoProtocol, i.AFIs, i.Expr, "from", "accept")
}

// String renders the export: or mp-export: policy in canonical form.
func (e Export) String() string {
	return policyString(e.Protocol, e.IntoProtocol, e.AFIs, e.Expr, "to", "announce")
}

// String renders the default: or mp-default: policy in canonical form.
func (d Default) String() string {
	var b strings.Builder
	writeAFIs(&b, d.AFIs)
	b.WriteString("to " + exprText(d.Peering))
	if len(d.Actions) > 0 {
		b.WriteString(" action " + actionsString(d.Actions))
	}
	if d.Networks != nil {
		b.WriteString(" networks " + filterString(d.Networks, precOr))
	}
	return b.String()
}

// policyString renders the shared shape of import: and export:, which differ
// only in the keywords that introduce a peering and a filter.
func policyString(proto, into string, afis []types.AddrFamily, e Expr, peerKw, filterKw string) string {
	var b strings.Builder
	if proto != "" {
		b.WriteString("protocol " + proto + " ")
	}
	if into != "" {
		b.WriteString("into " + into + " ")
	}
	writeAFIs(&b, afis)
	b.WriteString(exprString(e, peerKw, filterKw))
	return strings.TrimSpace(b.String())
}

// writeAFIs writes an "afi <list> " clause, or nothing when there is none.
func writeAFIs(b *strings.Builder, afis []types.AddrFamily) {
	if len(afis) == 0 {
		return
	}
	parts := make([]string, len(afis))
	for i, a := range afis {
		parts[i] = a.String()
	}
	b.WriteString("afi " + strings.Join(parts, ", ") + " ")
}

// exprString renders a policy expression. peerKw and filterKw are "from"/"accept"
// for an import and "to"/"announce" for an export.
func exprString(e Expr, peerKw, filterKw string) string {
	switch x := e.(type) {
	case Factor:
		var b strings.Builder
		for _, p := range x.Peers {
			if p.Via != nil {
				b.WriteString(exprText(p.Via) + " ")
			}
			b.WriteString(peerKw + " " + p.String() + " ")
		}
		b.WriteString(filterKw + " " + filterString(x.Filter, precOr))
		return b.String()
	case ExprList:
		parts := make([]string, len(x.Exprs))
		for i, sub := range x.Exprs {
			parts[i] = exprString(sub, peerKw, filterKw) + ";"
		}
		return "{ " + strings.Join(parts, " ") + " }"
	case Except:
		return exprString(x.Left, peerKw, filterKw) + " EXCEPT " +
			afiClause(x.AFIs) + exprString(x.Right, peerKw, filterKw)
	case Refine:
		return exprString(x.Left, peerKw, filterKw) + " REFINE " +
			afiClause(x.AFIs) + exprString(x.Right, peerKw, filterKw)
	}
	return ""
}

// afiClause renders an "afi <list> " clause for an except/refine right side.
func afiClause(afis []types.AddrFamily) string {
	var b strings.Builder
	writeAFIs(&b, afis)
	return b.String()
}
