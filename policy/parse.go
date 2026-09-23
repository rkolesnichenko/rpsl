package policy

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/lexer"
	"github.com/rkolesnichenko/rpsl/types"
)

// ParseImport parses an import: value ("[protocol …] [into …] from <peering>
// [action …] … accept <filter>", optionally structured with {…}, except and
// refine). It returns a best-effort Import plus diagnostics whose byte offsets
// are relative to s (the caller re-bases them onto the owning attribute).
// Every token is either parsed or diagnosed; it never panics.
func ParseImport(s string) (Import, []ast.Diagnostic) {
	imp, p := parseImport(s, false)
	return imp, p.diags
}

// ParseMPImport parses an mp-import: value (RFC 4012). It differs from
// ParseImport only in marking the result MP, which makes an absent afi clause
// mean every address family.
func ParseMPImport(s string) (Import, []ast.Diagnostic) {
	imp, p := parseImport(s, true)
	return imp, p.diags
}

func parseImport(s string, mp bool) (Import, *parser) {
	p := newParser(s)
	p.mp = mp
	imp := Import{MP: mp}
	if p.empty() {
		return imp, p
	}
	imp.Protocol, imp.IntoProtocol = p.parseProtocols()
	imp.AFIs = p.parseAFIs()
	imp.Expr = p.parseExpr("from", "accept")
	p.finish()
	return imp, p
}

// ParseExport parses an export: value ("… to <peering> [action …] … announce
// <filter>"). Structurally identical to ParseImport but with to/announce.
func ParseExport(s string) (Export, []ast.Diagnostic) {
	exp, p := parseExport(s, false)
	return exp, p.diags
}

// ParseMPExport parses an mp-export: value (RFC 4012); see ParseMPImport.
func ParseMPExport(s string) (Export, []ast.Diagnostic) {
	exp, p := parseExport(s, true)
	return exp, p.diags
}

func parseExport(s string, mp bool) (Export, *parser) {
	p := newParser(s)
	p.mp = mp
	exp := Export{MP: mp}
	if p.empty() {
		return exp, p
	}
	exp.Protocol, exp.IntoProtocol = p.parseProtocols()
	exp.AFIs = p.parseAFIs()
	exp.Expr = p.parseExpr("to", "announce")
	p.finish()
	return exp, p
}

// ParseDefault parses a default: value ("to <peering> [action …] [networks
// <filter>]"). Networks is nil when no networks clause is present.
func ParseDefault(s string) (Default, []ast.Diagnostic) {
	d, p := parseDefault(s, false)
	return d, p.diags
}

// ParseMPDefault parses an mp-default: value (RFC 4012); see ParseMPImport.
func ParseMPDefault(s string) (Default, []ast.Diagnostic) {
	d, p := parseDefault(s, true)
	return d, p.diags
}

func parseDefault(s string, mp bool) (Default, *parser) {
	p := newParser(s)
	p.mp = mp
	d := Default{MP: mp}
	if p.empty() {
		return d, p
	}
	d.AFIs = p.parseAFIs()
	if !p.cur().kw("to") {
		p.errf(p.cur(), "policy/default-to", "expected 'to' at start of default")
		return d, p
	}
	p.advance()
	d.Peering = p.parsePeering()
	if p.cur().kw("action") {
		p.advance()
		d.Actions = p.parseActions()
	}
	if p.cur().kw("networks") {
		p.advance()
		d.Networks = p.parseFilter()
	}
	p.finish()
	return d, p
}

// maxParseDepth caps recursion in the policy and AS-path-regexp parsers. Hostile
// input — deeply nested parens/braces or a long "not not not …" chain — would
// otherwise recurse one stack frame per level and overflow the stack. Past the
// cap the parser records one diagnostic and abandons the value instead of
// panicking. Real policy nests only a handful of levels.
const maxParseDepth = 1000

// maxTokens caps the tokens in one policy value (and in one AS-path regexp).
// The largest real value, a RIPE IPv6 bogon filter-set, has about 236,000; a
// longer value is refused with "policy/too-long" before its tokens are built.
const maxTokens = 1 << 20

// maxDiagnostics caps the diagnostics reported for one value. Past it the
// parser records "policy/too-many-errors" and abandons the value: the rest
// would only repeat the problem at a cost of memory per error.
const maxDiagnostics = 100

// ParsePeering parses a standalone peering specification (the value of a
// peering:/mp-peering: attribute in a peering-set). It returns a best-effort
// Peering plus diagnostics; it never panics.
func ParsePeering(s string) (Peering, []ast.Diagnostic) {
	pe, p := parsePeeringValue(s)
	return pe, p.diags
}

func parsePeeringValue(s string) (Peering, *parser) {
	p := newParser(s)
	pe := p.parsePeering()
	p.finish()
	return pe, p
}

// ParseFilter parses a standalone policy filter (the value of a filter:/mp-filter:
// attribute in a filter-set). It returns a best-effort Filter plus diagnostics;
// it never panics.
func ParseFilter(s string) (Filter, []ast.Diagnostic) {
	f, p := parseFilterValue(s)
	return f, p.diags
}

func parseFilterValue(s string) (Filter, *parser) {
	p := newParser(s)
	f := p.parseFilter()
	p.finish()
	return f, p
}

type parser struct {
	src    string
	toks   []token
	pos    int
	depth  int
	bailed bool // nesting cap hit: the rest of the value is abandoned
	mp     bool // an mp-* value, where an afi clause is allowed
	// via is the peer keyword ("from" or "to") of an import-via: or
	// export-via: value, whose clauses start with a via peering (via.go);
	// "" for every other policy.
	via string
	// afterExcept: the next factor is the right-hand side of an EXCEPT, where
	// a filter term instead of from/to gets a hint (exceptHint).
	afterExcept bool
	// stops are extra keywords that end a clause, a peering or a router
	// expression. The import:/export:/default: grammar sets none; the
	// sub-grammars of inject:, interface: and peer: add their own keywords so
	// that, say, "upon" is not read as part of the action list before it.
	stops []string
	// dict, when set, is the RP-attribute dictionary actions and protocol names
	// are checked against (RFC 2622 §9). Nil means syntax-only checking.
	dict  *Dictionary
	diags []ast.Diagnostic
}

// isStop reports whether t is one of this parser's extra stop keywords.
func (p *parser) isStop(t token) bool {
	for _, k := range p.stops {
		if t.kw(k) {
			return true
		}
	}
	return false
}

// clauseKw, peeringStop and filterStop are the grammar's stop predicates widened
// by p.stops; every grammar method uses these rather than the bare functions.
func (p *parser) clauseKw(t token) bool    { return isClauseKw(t) || p.isStop(t) }
func (p *parser) peeringStop(t token) bool { return isPeeringStop(t) || p.isStop(t) }
func (p *parser) filterStop(t token) bool  { return isFilterStop(t) || p.isStop(t) }

// startsFilterTerm reports whether t can begin another filter term, i.e. an
// implicit OR continues the filter.
func (p *parser) startsFilterTerm(t token) bool {
	switch t.kind {
	case tLParen, tLBrace, tRegex:
		return true
	case tWord:
		return !p.filterStop(t)
	}
	return false
}

// newParser tokenizes s. A value over maxTokens gets one "policy/too-long"
// diagnostic and parses as empty, with no further diagnostics.
func newParser(s string) *parser {
	toks, ok := tokenize(s)
	if ok {
		p := &parser{src: s, toks: toks}
		p.checkDelimiters()
		p.checkUnicodeSpace()
		return p
	}
	p := &parser{src: s, toks: []token{{tEOF, "", len(s), len(s)}}}
	p.errf(token{tEOF, "", 0, len(s)}, "policy/too-long",
		fmt.Sprintf("policy value has more than %d tokens and is not parsed", maxTokens))
	p.bailed = true
	return p
}

// checkDelimiters diagnoses an AS-path regexp with no closing '>' and removes,
// after diagnosing, each '>' that closes nothing, so the grammar never sees it.
func (p *parser) checkDelimiters() {
	kept := p.toks[:0]
	for _, t := range p.toks {
		switch {
		case t.kind == tStray:
			p.errf(t, "policy/as-path-regexp", "'>' without an opening '<'")
			continue
		case t.kind == tRegex && !t.closed():
			p.errf(t, "policy/as-path-regexp", "unterminated AS-path regexp: expected '>'")
		}
		kept = append(kept, t)
	}
	p.toks = kept
	if p.bailed { // the diagnostic cap moved pos to the old end
		p.pos = len(p.toks) - 1
	}
}

func (p *parser) cur() token { return p.toks[p.pos] }
func (p *parser) peek() token {
	if p.pos+1 < len(p.toks) {
		return p.toks[p.pos+1]
	}
	return p.toks[len(p.toks)-1]
}
func (p *parser) advance() {
	if p.pos < len(p.toks)-1 {
		p.pos++
	}
}
func (p *parser) atEOF() bool { return p.cur().kind == tEOF }

func (p *parser) errf(t token, rule, msg string)  { p.diag(ast.Error, t, rule, msg) }
func (p *parser) warnf(t token, rule, msg string) { p.diag(ast.Warning, t, rule, msg) }

// diag records a diagnostic at t. Columns are 1-based; byte offsets are 0-based
// and relative to the parsed value, for object's rebase onto the attribute.
// Once the nesting cap has been hit, further diagnostics are suppressed: they
// would only be cascades of the abandoned parse. Past maxDiagnostics the value
// is abandoned the same way, with one "policy/too-many-errors".
func (p *parser) diag(sev ast.Severity, t token, rule, msg string) {
	if p.bailed {
		return
	}
	if len(p.diags) >= maxDiagnostics {
		sev, rule = ast.Error, "policy/too-many-errors"
		msg = fmt.Sprintf("more than %d problems; the rest of the value is not checked", maxDiagnostics)
		p.bailed = true
		p.pos = len(p.toks) - 1
	}
	p.diags = append(p.diags, ast.Diagnostic{
		Severity: sev,
		Message:  msg,
		Span: lexer.Span{
			StartLine: 1, EndLine: 1,
			StartCol: t.start + 1, EndCol: t.end + 1,
			StartByte: t.start, EndByte: t.end,
		},
		Rule: rule,
	})
}

// enter descends one nesting level, or — past maxParseDepth — records a single
// diagnostic, abandons the rest of the value, and reports false. Callers that
// get true must defer p.leave().
func (p *parser) enter() bool {
	if p.bailed {
		return false
	}
	if p.depth >= maxParseDepth {
		p.errf(p.cur(), "policy/nesting", "policy nesting too deep")
		p.bailed = true
		p.pos = len(p.toks) - 1
		return false
	}
	p.depth++
	return true
}

func (p *parser) leave() { p.depth-- }

// empty diagnoses an empty value.
func (p *parser) empty() bool {
	if p.atEOF() {
		p.errf(p.cur(), "policy/empty", "empty policy")
		return true
	}
	return false
}

// finish consumes an optional trailing ';' and diagnoses anything left over, so
// no input is ever dropped silently.
func (p *parser) finish() {
	if p.cur().kind == tSemi {
		p.advance()
	}
	if !p.atEOF() {
		p.errf(p.cur(), "policy/trailing", "unexpected "+describe(p.cur())+" after the policy expression")
	}
}

// sync skips to the end of the current factor — a ';' or '}' at the current
// brace depth, or EOF — after an unrecoverable factor error.
func (p *parser) sync() {
	depth := 0
	for !p.atEOF() {
		switch p.cur().kind {
		case tLBrace:
			depth++
		case tRBrace:
			if depth == 0 {
				return
			}
			depth--
		case tSemi:
			if depth == 0 {
				return
			}
		}
		p.advance()
	}
}

// parseProtocols consumes optional "protocol X" and "into Y" prefixes.
func (p *parser) parseProtocols() (proto, into string) {
	return p.protocolClause("protocol"), p.protocolClause("into")
}

// protocolClause consumes "<kw> <protocol name>" if the value continues with
// kw, diagnosing a missing name.
func (p *parser) protocolClause(kw string) string {
	if !p.cur().kw(kw) {
		return ""
	}
	kwTok := p.cur()
	p.advance()
	if t := p.cur(); t.kind == tWord && !p.clauseKw(t) && !t.kw("into") && !t.kw("afi") {
		p.advance()
		p.checkProtocol(t.text, t)
		return t.text
	}
	p.errf(kwTok, "policy/protocol", "expected a protocol name after '"+kw+"'")
	return ""
}

// parseAFIs consumes an optional "afi <afi-list>" clause (RFC 4012). The list is
// comma- or space-separated address families; parsing stops at the first token
// that is not one (typically the from/to/{ that begins the expression).
func (p *parser) parseAFIs() []types.AddrFamily {
	if !p.cur().kw("afi") {
		return nil
	}
	afiTok := p.cur()
	p.advance()
	var afis []types.AddrFamily
	for {
		t := p.cur()
		if t.kind != tWord || p.clauseKw(t) {
			break
		}
		af, err := types.ParseAddrFamily(t.text)
		if err != nil {
			p.errf(t, "policy/afi", "invalid address family "+describe(t))
			return afis
		}
		afis = append(afis, af)
		p.advance()
		if p.cur().kind == tComma {
			p.advance()
		} else if p.via != "" {
			break // a via peering follows the list, not a keyword
		}
	}
	if len(afis) == 0 {
		p.errf(afiTok, "policy/afi", "empty afi list")
	}
	if !p.mp {
		p.errf(afiTok, "policy/afi", "an afi clause is RFC 4012 syntax, valid only in mp-import, "+
			"mp-export and mp-default; it is ignored")
		return nil
	}
	return afis
}

// parseExpr parses a policy expression (RFC 2622 §6.6, RFC 4012 §2.5):
//
//	expr = term [";"] ("except" | "refine") [afi-list] expr | term
//
// Except and refine are right-associative ("performed right to left"), and the
// factor-terminating ';' before them is optional.
func (p *parser) parseExpr(peerKw, filterKw string) Expr {
	if !p.enter() {
		return ExprList{}
	}
	defer p.leave()
	left := p.parseTerm(peerKw, filterKw)
	if p.cur().kind == tSemi && (p.peek().kw("except") || p.peek().kw("refine")) {
		p.advance()
	}
	switch {
	case p.cur().kw("except"):
		p.advance()
		afis := p.parseAFIs()
		p.afterExcept = true
		return Except{Left: left, AFIs: afis, MP: p.mp, Right: p.parseExpr(peerKw, filterKw)}
	case p.cur().kw("refine"):
		p.advance()
		afis := p.parseAFIs()
		return Refine{Left: left, AFIs: afis, MP: p.mp, Right: p.parseExpr(peerKw, filterKw)}
	}
	return left
}

// parseTerm parses a single factor or a brace-enclosed list of expressions, each
// terminated by ';' (optional before the closing brace).
func (p *parser) parseTerm(peerKw, filterKw string) Expr {
	if p.cur().kind == tLBrace {
		p.afterExcept = false // a { } list of policies: the brace answers the EXCEPT
	}
	if p.cur().kind != tLBrace {
		return p.parseFactor(peerKw, filterKw)
	}
	open := p.cur()
	p.advance() // consume '{'
	var exprs []Expr
	for !p.atEOF() && p.cur().kind != tRBrace {
		start := p.pos
		exprs = append(exprs, p.parseExpr(peerKw, filterKw))
		switch {
		case p.cur().kind == tSemi:
			p.advance()
		case p.cur().kind == tRBrace || p.atEOF():
		default:
			p.warnf(p.cur(), "policy/missing-semicolon", "expected ';' between policy expressions")
		}
		if p.pos == start { // defensive: guarantee progress on malformed input
			p.advance()
		}
	}
	if p.cur().kind == tRBrace {
		if len(exprs) == 0 {
			p.warnf(token{tLBrace, "{}", open.start, p.cur().end}, "policy/empty", "empty { } policy expression")
		}
		p.advance()
	} else {
		p.errf(p.cur(), "policy/expr-brace", "expected '}'")
	}
	return ExprList{Exprs: exprs}
}

// parseFactor parses one or more "<peerKw> <peering> [action …]" clauses
// followed by a "<filterKw> <filter>" clause. A factor missing either part is
// diagnosed and skipped to its end.
func (p *parser) parseFactor(peerKw, filterKw string) Factor {
	afterExcept := p.afterExcept
	p.afterExcept = false
	if afterExcept && p.startsFilterTerm(p.cur()) && !p.cur().kw(peerKw) && !p.startsPeeringHere() {
		p.errf(p.cur(), "policy/expect-peering", exceptHint(peerKw, p.cur()))
		p.sync()
		return Factor{}
	}
	if p.via != "" {
		return p.parseViaFactor(peerKw, filterKw)
	}
	var f Factor
	for p.cur().kw(peerKw) {
		p.advance()
		pa := PeerAction{Peering: p.parsePeering()}
		if p.cur().kw("action") {
			p.advance()
			pa.Actions = p.parseActions()
		}
		f.Peers = append(f.Peers, pa)
	}
	if len(f.Peers) == 0 {
		p.errf(p.cur(), "policy/expect-peering", "expected '"+peerKw+"' clause")
		if !p.cur().kw(filterKw) {
			p.sync()
			return f
		}
	}
	if !p.cur().kw(filterKw) {
		p.errf(p.cur(), "policy/expect-filter", "expected '"+filterKw+"' clause")
		p.sync()
		return f
	}
	p.advance()
	f.Filter = p.parseFilter()
	return f
}

// isClauseKw reports whether the token begins a new clause (and thus terminates
// an afi list or an action list).
func isClauseKw(t token) bool {
	return t.kw("from") || t.kw("to") || t.kw("accept") || t.kw("announce") ||
		t.kw("action") || t.kw("networks") || t.kw("except") || t.kw("refine")
}

// isPeeringStop reports whether t ends a peering specification. Unlike
// isClauseKw it excludes "except": inside a peering that is the AS- or
// router-expression operator (RFC 2622 §5.6).
func isPeeringStop(t token) bool {
	switch t.kind {
	case tEOF, tSemi, tRBrace:
		return true
	}
	return t.kw("from") || t.kw("to") || t.kw("accept") || t.kw("announce") ||
		t.kw("action") || t.kw("networks") || t.kw("refine")
}

// parsePeering parses a peering specification (RFC 2622 §5.6): an AS
// expression with optional router expressions, a peering-set reference, or an
// AS-path regexp.
func (p *parser) parsePeering() Peering {
	t := p.cur()
	if t.kind == tRegex {
		p.advance()
		return PeeringRegexp{Raw: t.text, Regexp: p.parseRegexp(t)}
	}
	if t.kind == tWord {
		if sn, err := types.ParseSetName(t.text); err == nil && sn.Class() == types.ClassPeeringSet {
			p.advance()
			return PeeringSetRef{Name: sn}
		}
	}
	if (t.kind != tWord && t.kind != tLParen) || p.peeringStop(t) || t.kw("at") {
		p.errf(t, "policy/peering", "expected peering specification")
		return PeeringAS{}
	}
	as, ok := p.parseASExpr()
	if !ok {
		for !p.peeringStop(p.cur()) { // the error is reported; skip the rest of the peering
			p.advance()
		}
		return PeeringAS{}
	}
	pa := PeeringAS{AS: as, Router: p.parseRouterExpr()}
	if p.cur().kw("at") {
		atTok := p.cur()
		p.advance()
		before := len(p.diags)
		if pa.AtRouter = p.parseRouterExpr(); pa.AtRouter == nil && len(p.diags) == before {
			p.errf(atTok, "policy/peering", "expected router expression after 'at'")
		}
	}
	return pa
}

// parseASExpr parses an AS expression (RFC 2622 §5.6):
//
//	as-expr = as-and {"OR" as-and};  as-and = as-prim {("AND"|"EXCEPT") as-prim}
//	as-prim = ASN | as-set | as-set template | "(" as-expr ")"
//
// It reports false after recording a diagnostic.
//
// Each operator nests the tree built so far one level deeper, so a chain counts
// toward the nesting cap like parentheses do.
func (p *parser) parseASExpr() (ASExpr, bool) {
	l, ok := p.parseASAnd()
	for ok && p.cur().kw("or") {
		if !p.enter() {
			return nil, false
		}
		defer p.leave()
		p.advance()
		var r ASExpr
		if r, ok = p.parseASAnd(); ok {
			l = ASExprBinary{Op: ASOr, L: l, R: r}
		}
	}
	return l, ok
}

func (p *parser) parseASAnd() (ASExpr, bool) {
	l, ok := p.parseASPrim()
	for ok && (p.cur().kw("and") || p.cur().kw("except")) {
		if !p.enter() {
			return nil, false
		}
		defer p.leave()
		op := ASAnd
		if p.cur().kw("except") {
			op = ASExcept
		}
		p.advance()
		var r ASExpr
		if r, ok = p.parseASPrim(); ok {
			l = ASExprBinary{Op: op, L: l, R: r}
		}
	}
	return l, ok
}

func (p *parser) parseASPrim() (ASExpr, bool) {
	t := p.cur()
	if t.kind == tLParen {
		if !p.enter() {
			return nil, false
		}
		defer p.leave()
		p.advance()
		e, ok := p.parseASExpr()
		if !ok {
			return nil, false
		}
		if p.cur().kind != tRParen {
			p.errf(p.cur(), "policy/as-expr", "expected ')' in AS expression")
			return nil, false
		}
		p.advance()
		return e, true
	}
	if t.kw("not") {
		p.errf(t, "policy/as-expr", `NOT is not an AS-expression operator (RFC 2622 §5.6): write "X EXCEPT Y" for "X AND NOT Y"`)
		return nil, false
	}
	if t.kind != tWord || p.peeringStop(t) || t.kw("at") || t.kw("and") || t.kw("or") || t.kw("except") {
		p.errf(t, "policy/as-expr", "expected an AS number or as-set")
		return nil, false
	}
	p.advance()
	if asn, err := types.ParseASN(t.text); err == nil {
		return ASNum{AS: asn}, true
	}
	if sn, err := types.ParseSetName(t.text); err == nil {
		if sn.Class() == types.ClassAsSet {
			return ASSetRef{Name: sn}, true
		}
		p.errf(t, "policy/peering", describe(t)+" is a "+sn.Class().String()+", not an as-set")
		return nil, false
	}
	if tpl, err := ParseSetNameTemplate(t.text); err == nil && tpl.Class() == types.ClassAsSet {
		return ASSetTemplate{Template: tpl}, true
	}
	p.errf(t, "policy/peering", "invalid peering term "+describe(t))
	return nil, false
}

// parseRouterExpr parses an optional router expression (RFC 2622 §5.6):
//
//	rtr-expr = rtr-and {"OR" rtr-and};  rtr-and = rtr-prim {("AND"|"EXCEPT") rtr-prim}
//	rtr-prim = address | inet-rtr name | rtr-set | "(" rtr-expr ")"
//
// It returns nil when none is present (the peering ends, or "at" follows).
// Routers written side by side without an operator are diagnosed and the rest
// of the router expression skipped.
func (p *parser) parseRouterExpr() RouterExpr {
	if p.peeringStop(p.cur()) || p.cur().kw("at") || p.startsNextVia(p.cur()) {
		return nil
	}
	before := len(p.diags)
	e := p.parseRouterOr()
	if t := p.cur(); !p.peeringStop(t) && !t.kw("at") && !p.startsNextVia(t) && !p.bailed {
		if len(p.diags) == before { // else the error is already reported
			p.errf(t, "policy/router", "expected AND, OR or EXCEPT before "+describe(t)+" in router expression")
		}
		for !p.peeringStop(p.cur()) && !p.cur().kw("at") && !p.startsNextVia(p.cur()) {
			p.advance()
		}
	}
	return e
}

func (p *parser) parseRouterOr() RouterExpr {
	l := p.parseRouterAnd()
	for l != nil && p.cur().kw("or") {
		if !p.enter() {
			return nil
		}
		defer p.leave()
		p.advance()
		r := p.parseRouterAnd()
		if r == nil {
			return nil
		}
		l = RouterExprBinary{Op: RouterOr, L: l, R: r}
	}
	return l
}

func (p *parser) parseRouterAnd() RouterExpr {
	l := p.parseRouterPrim()
	for l != nil && (p.cur().kw("and") || p.cur().kw("except")) {
		if !p.enter() {
			return nil
		}
		defer p.leave()
		op := RouterAnd
		if p.cur().kw("except") {
			op = RouterExcept
		}
		p.advance()
		r := p.parseRouterPrim()
		if r == nil {
			return nil
		}
		l = RouterExprBinary{Op: op, L: l, R: r}
	}
	return l
}

// parseRouterPrim parses one router, or a parenthesized router expression. A
// single-label name ("PEERING", which real policies use as a label) is kept
// but warned about: an inet-rtr name is a DNS name.
func (p *parser) parseRouterPrim() RouterExpr {
	t := p.cur()
	if t.kind == tLParen {
		if !p.enter() {
			return nil
		}
		defer p.leave()
		p.advance()
		e := p.parseRouterOr()
		if e == nil {
			return nil
		}
		if p.cur().kind != tRParen {
			p.errf(p.cur(), "policy/router", "expected ')' in router expression")
			return nil
		}
		p.advance()
		return e
	}
	if t.kw("not") {
		p.errf(t, "policy/router", `NOT is not a router-expression operator (RFC 2622 §5.6): write "X EXCEPT Y" for "X AND NOT Y"`)
		return nil
	}
	if t.kind != tWord || p.peeringStop(t) || t.kw("at") || t.kw("and") || t.kw("or") || t.kw("except") {
		p.errf(t, "policy/router", "expected a router address, inet-rtr name or rtr-set")
		return nil
	}
	p.advance()
	if a, err := types.ParseAddr(t.text); err == nil {
		p.warnPadded(t, a.String())
		return RouterAddr{Addr: a}
	}
	if sn, err := types.ParseSetName(t.text); err == nil {
		if sn.Class() == types.ClassRtrSet {
			return RouterSetRef{Name: sn}
		}
		p.errf(t, "policy/router", describe(t)+" is a "+sn.Class().String()+", not a router or rtr-set")
		return nil
	}
	switch labels := dnsLabels(t.text); {
	case labels > 1:
		return RouterName{Name: t.text}
	case labels == 1:
		p.warnf(t, "policy/router", describe(t)+" is not a router address, rtr-set or fully qualified inet-rtr name")
		return RouterName{Name: t.text}
	}
	p.errf(t, "policy/router", "invalid router "+describe(t))
	return nil
}

// dnsLabels returns the number of labels in s if it is a DNS name (letters,
// digits and hyphens in dot-separated labels, a trailing dot allowed), else 0.
func dnsLabels(s string) int {
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return 0
	}
	labels := strings.Split(s, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return 0
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-') {
				return 0
			}
		}
	}
	return len(labels)
}

// parseRegexp parses the AS-path regexp of token t, recording a diagnostic at
// the offending token (and returning nil) if it does not parse, and a Warning
// for each AS number written without "AS". The Raw text is kept regardless.
func (p *parser) parseRegexp(t token) *ASPathRE {
	re, bare, err := parseASPathRegexp(t.text)
	var rerr *reError
	switch {
	case errors.Is(err, errRegexpTooLong):
		p.errf(t, "policy/too-long", err.Error())
		return nil
	case errors.As(err, &rerr):
		p.errf(p.inRegexp(t, rerr.start, rerr.end), "policy/as-path-regexp", err.Error())
		return nil
	case err != nil:
		p.errf(t, "policy/as-path-regexp", err.Error())
		return nil
	}
	for _, b := range bare {
		p.warnf(p.inRegexp(t, b.start, b.end), "policy/as-path-regexp",
			quote(b.text)+` lacks the "AS" prefix RFC 2622 writes AS numbers with; it is read as an AS number`)
	}
	return re
}

// inRegexp returns a token for bytes [start, end) of regexp token t's body. A
// zero-width range at the end of the body points at the closing '>' if there
// is one.
func (p *parser) inRegexp(t token, start, end int) token {
	body := t.start + 1 // after '<'
	if start == end && end == len(t.text) && t.closed() {
		end++
	}
	return token{tRegex, t.text, min(body+start, t.end), min(body+end, t.end)}
}

// parseActions parses a ';'-separated action list, stopping at a clause keyword,
// an unmatched '}', or EOF. Each action is cut at its ';' (braces inside a value,
// as in "community .= {1:2}", are kept) and interpreted by parseAction; one that
// does not follow the action grammar is diagnosed and left out.
func (p *parser) parseActions() []Action {
	var actions []Action
	for !p.atEOF() && !p.clauseKw(p.cur()) && p.cur().kind != tRBrace && !p.actionsEndBeforeVia() {
		start := p.cur().start
		end := start
		depth := 0
		for !p.atEOF() && !p.clauseKw(p.cur()) {
			k := p.cur().kind
			if depth == 0 && (k == tSemi || k == tRBrace) {
				break
			}
			if k == tLBrace {
				depth++
			} else if k == tRBrace {
				depth--
			}
			end = p.cur().end
			p.advance()
		}
		if raw := strings.TrimSpace(p.src[start:end]); raw != "" {
			if a, msg := parseAction(raw); msg == "" {
				p.checkAction(a, token{tWord, raw, start, start + len(raw)})
				actions = append(actions, a)
			} else {
				p.errf(token{tWord, raw, start, start + len(raw)}, "policy/action", msg)
			}
		}
		if p.cur().kind != tSemi {
			break
		}
		p.advance()
	}
	return actions
}

// actionOps are the operators of RFC 2622 Figure 25, longest first so that
// "<<=" is not read as "<". The assignments change a route attribute; the
// comparisons only test one, so they are filters, never actions.
var actionOps = []struct {
	op     string
	assign bool
}{
	{"<<=", true}, {">>=", true}, {"==", false}, {"!=", false}, {"<=", false}, {">=", false},
	{".=", true}, {"+=", true}, {"-=", true}, {"*=", true}, {"/=", true}, {"=", true},
	{"<", false}, {">", false},
}

// parseAction interprets one action (RFC 2622 §6.1.1, §7): "attr = value",
// "attr .= value" or "attr.method(args)". The other assignment operators of
// RFC 2622 Figure 25 ("med += 5") are the operator methods they are named for
// (Method "operator+=", one argument). It returns a message saying what is
// wrong when raw is none of these.
func parseAction(raw string) (Action, string) {
	a, msg := parseActionText(asciiSpaces(raw))
	if msg == "" {
		a.Raw = raw // as written, Unicode spaces and all
	}
	return a, msg
}

// asciiSpaces returns s with each other space (see otherSpaceAt) turned into an
// ASCII one, so the text parsers that split raw text read them alike.
func asciiSpaces(s string) string {
	if !strings.ContainsFunc(s, isOtherSpace) {
		return s
	}
	return strings.Map(func(r rune) rune {
		if isOtherSpace(r) {
			return ' '
		}
		return r
	}, s)
}

// parseActionText parses one action from text whose spaces are all ASCII.
func parseActionText(raw string) (Action, string) {
	const form = "expected 'attr = value', 'attr .= value' or 'attr.method(args)'"
	if open := strings.IndexByte(raw, '('); open >= 0 && !strings.Contains(raw[:open], "=") {
		attr, method, dotted := strings.Cut(strings.TrimSpace(raw[:open]), ".")
		closing := matchParen(raw, open)
		switch {
		case !dotted || !isRPName(attr) || !isRPName(method):
			return Action{}, form
		case closing < 0:
			return Action{}, "unbalanced '(' in action " + quote(raw)
		case strings.TrimSpace(raw[closing+1:]) != "":
			return Action{}, "expected ';' after " + quote(raw[:closing+1])
		}
		return Action{Attr: normAttr(attr), Method: normAttr(method), Op: ActionMethod,
			Args: splitTrim(raw[open+1 : closing]), Raw: raw}, ""
	}
	name := rpNamePrefix(raw)
	rest := strings.TrimLeft(raw[len(name):], " \t\r\n")
	if name == "" || !isRPName(name) {
		return Action{}, form
	}
	for _, o := range actionOps {
		op := o.op
		if !strings.HasPrefix(rest, op) {
			continue
		}
		if !o.assign {
			return Action{}, quote(op) + " compares; an action assigns with = or .=, or calls a method"
		}
		value := strings.TrimSpace(rest[len(op):])
		if msg := checkActionValue(value); msg != "" {
			return Action{}, msg
		}
		switch op {
		case "=":
			return Action{Attr: normAttr(name), Op: ActionAssign, Value: value, Raw: raw}, ""
		case ".=":
			return Action{Attr: normAttr(name), Op: ActionAppend, Value: value, Raw: raw}, ""
		}
		return Action{Attr: normAttr(name), Method: "operator" + op, Op: ActionMethod,
			Args: []string{value}, Raw: raw}, ""
	}
	return Action{}, form
}

// checkActionValue checks an action's right-hand side: one word, or one {…}
// list. Anything after it means a missing ';'.
func checkActionValue(v string) string {
	switch {
	case v == "":
		return "action has no value"
	case strings.HasPrefix(v, "{"):
		if j := strings.IndexByte(v, '}'); j < 0 {
			return "unterminated '{' in action value"
		} else if rest := strings.TrimSpace(v[j+1:]); rest != "" {
			return "expected ';' before " + quote(rest)
		}
		return ""
	}
	if i := strings.IndexAny(v, " \t\r\n"); i >= 0 {
		return "expected ';' before " + quote(strings.TrimSpace(v[i:]))
	}
	if strings.ContainsAny(v, "={}()") {
		return "invalid action value " + quote(v)
	}
	return ""
}

// rpNamePrefix returns the leading run of s that can belong to an rp-attribute
// name, stopping before a '-' that begins the operator "-=".
func rpNamePrefix(s string) string {
	i := 0
	for i < len(s) {
		c := s[i]
		ok := 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '_' ||
			c == '-' && !strings.HasPrefix(s[i:], "-=")
		if !ok {
			break
		}
		i++
	}
	return s[:i]
}

// isRPName reports whether s is an rp-attribute or method name: a letter, then
// letters, digits, '-' or '_'.
func isRPName(s string) bool {
	if s == "" || !('a' <= s[0] && s[0] <= 'z' || 'A' <= s[0] && s[0] <= 'Z') {
		return false
	}
	return rpNamePrefix(s) == s
}

// matchParen returns the index of the ')' that closes the '(' at open, or -1.
func matchParen(s string, open int) int {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			if depth--; depth == 0 {
				return i
			}
		}
	}
	return -1
}

// normAttr canonicalizes an rp-attribute name (lowercase, trimmed).
func normAttr(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// parseFilter parses a policy filter (RFC 2622 §5.4) with precedence
// NOT > AND > OR, where juxtaposition ("x y") is an implicit OR.
func (p *parser) parseFilter() Filter { return p.parseFilterOr() }

func (p *parser) parseFilterOr() Filter {
	terms := []Filter{p.parseFilterAnd()}
	for {
		if p.cur().kw("or") {
			p.advance()
		} else if !p.startsFilterTerm(p.cur()) {
			break
		}
		start := p.pos
		terms = append(terms, p.parseFilterAnd())
		if p.pos == start { // defensive: guarantee progress
			p.advance()
		}
	}
	if len(terms) == 1 {
		return terms[0]
	}
	return FilterOr{Terms: terms}
}

// isFilterStop reports whether a word ends a filter rather than continuing it.
func isFilterStop(t token) bool {
	for _, k := range [...]string{"and", "or", "except", "refine", "from", "to", "action",
		"accept", "announce", "networks", "at", "afi", "protocol", "into"} {
		if t.kw(k) {
			return true
		}
	}
	return false
}

func (p *parser) parseFilterAnd() Filter {
	terms := []Filter{p.parseFilterNot()}
	for p.cur().kw("and") {
		p.advance()
		terms = append(terms, p.parseFilterNot())
	}
	if len(terms) == 1 {
		return terms[0]
	}
	return FilterAnd{Terms: terms}
}

func (p *parser) parseFilterNot() Filter {
	if !p.cur().kw("not") {
		return p.parseFilterPrimary()
	}
	if !p.enter() {
		return nil
	}
	defer p.leave()
	p.advance()
	return FilterNot{Inner: p.parseFilterNot()}
}

func (p *parser) parseFilterPrimary() Filter {
	t := p.cur()
	switch t.kind {
	case tLParen:
		if !p.enter() {
			return nil
		}
		defer p.leave()
		p.advance()
		f := p.parseFilterOr()
		if p.cur().kind == tRParen {
			p.advance()
		} else {
			p.errf(p.cur(), "policy/filter-paren", "expected ')'")
		}
		return f
	case tLBrace:
		return p.parsePrefixList()
	case tRegex:
		p.advance()
		return FilterPathRE{Raw: t.text, Regexp: p.parseRegexp(t)}
	case tWord:
		if !p.filterStop(t) {
			return p.parseFilterWord()
		}
	}
	p.errf(t, "policy/filter", "unexpected "+describe(t)+" in filter")
	if t.kind != tEOF {
		p.advance()
	}
	return nil
}

// parseFilterWord handles word-led filter terms: ANY, PeerAS, AS numbers, set
// names, and PeerAS set-name templates, each optionally followed by a range
// operator ("AS-FOO^+", "PeerAS^0-32"), and rp-attribute method calls
// (community(...)). A term followed by '(' is an implicit OR with a
// parenthesized group ("AS1 (AS2 OR AS3)"), never a method call.
func (p *parser) parseFilterWord() Filter {
	t := p.cur()
	if p.peek().kind == tLParen && !isFilterTerm(t.text) {
		return p.parseFilterMethod()
	}
	if strings.EqualFold(t.text, "community") && p.peek().kind == tEq {
		return p.parseCommunityEquals()
	}
	p.advance()
	base, opText, hasOp := strings.Cut(t.text, "^")
	var op types.RangeOperator
	if hasOp {
		o, err := types.ParseRangeOperator(opText)
		if err != nil {
			p.errf(t, "policy/range-op", "invalid range operator in "+describe(t))
			return nil
		}
		op = o
	}
	switch {
	case strings.EqualFold(base, "any"):
		if hasOp {
			p.errf(t, "policy/range-op", "ANY takes no range operator")
		}
		return FilterAny{}
	case strings.EqualFold(base, "peeras"):
		return FilterPeerAS{Op: op}
	}
	if asn, err := types.ParseASN(base); err == nil {
		return FilterASExpr{AS: ASNum{AS: asn}, Op: op}
	}
	if sn, err := types.ParseSetName(base); err == nil {
		switch sn.Class() {
		case types.ClassAsSet:
			return FilterASExpr{AS: ASSetRef{Name: sn}, Op: op}
		case types.ClassRouteSet:
			return FilterSetRef{Name: sn, Op: op}
		case types.ClassFilterSet:
			if hasOp {
				p.errf(t, "policy/range-op", "a filter-set takes no range operator")
			}
			return FilterSetRef{Name: sn}
		}
		p.errf(t, "policy/filter", "a "+sn.Class().String()+" cannot be used as a filter")
		return nil
	}
	if tpl, err := ParseSetNameTemplate(base); err == nil {
		switch tpl.Class() {
		case types.ClassAsSet:
			return FilterASExpr{AS: ASSetTemplate{Template: tpl}, Op: op}
		case types.ClassRouteSet, types.ClassFilterSet:
			return FilterSetTemplate{Template: tpl, Op: op}
		}
	}
	p.errf(t, "policy/filter", "invalid filter term "+describe(t))
	return nil
}

// isFilterTerm reports whether word is a filter term (with or without a range
// operator) rather than the name of an rp-attribute method.
func isFilterTerm(word string) bool {
	base, _, _ := strings.Cut(word, "^")
	if strings.EqualFold(base, "any") || strings.EqualFold(base, "peeras") {
		return true
	}
	if _, err := types.ParseASN(base); err == nil {
		return true
	}
	if _, err := types.ParseSetName(base); err == nil {
		return true
	}
	_, err := ParseSetNameTemplate(base)
	return err == nil
}

// parseFilterMethod parses an rp-attribute method call, name(args), through its
// matching ')'. Only the route tests of RFC 2622 §7 are filters —
// community(...) and community.contains(...); methods that modify a route
// (community.append, aspath.prepend, ...) are actions and are diagnosed, as are
// unknown names and an unterminated call.
func (p *parser) parseFilterMethod() Filter {
	name := p.cur()
	end := name.end
	p.advance()
	depth := 0
	for closed := false; !closed; {
		if p.atEOF() {
			p.errf(name, "policy/filter-paren", "unterminated "+quote(name.text+"(")+": expected ')'")
			return nil
		}
		c := p.cur()
		switch c.kind {
		case tLParen:
			depth++
		case tRParen:
			depth--
			closed = depth == 0
		}
		end = c.end
		p.advance()
	}
	switch lower := strings.ToLower(name.text); {
	case lower == "community" || lower == "community.contains":
		raw := p.src[name.start:end]
		return FilterCommunity{Op: CommunityContains, Values: delimited(raw, '(', ')'), Raw: raw}
	case strings.Contains(lower, "."):
		p.errf(name, "policy/filter-method", quote(name.text)+" is an action method, not a filter "+
			"(filters test routes with community(...) or community.contains(...))")
	default:
		p.errf(name, "policy/filter-method", "unknown filter method "+quote(name.text))
	}
	return nil
}

// parseCommunityEquals parses "community == {…}" (RFC 2622 §7): routes whose
// communities are exactly the listed ones.
func (p *parser) parseCommunityEquals() Filter {
	name := p.cur()
	p.advance()
	eq := p.cur()
	p.advance()
	if p.cur().kind != tEq || p.cur().start != eq.end {
		p.errf(eq, "policy/filter", "expected '==' after community")
		return nil
	}
	p.advance()
	if p.cur().kind != tLBrace {
		p.errf(p.cur(), "policy/filter", "expected '{' after 'community =='")
		return nil
	}
	p.advance()
	var values []string
	wantItem := true
	for p.cur().kind != tRBrace {
		t := p.cur()
		switch {
		case t.kind == tEOF:
			p.errf(t, "policy/filter", "expected '}' to close the community list")
			return nil
		case t.kind == tComma:
			wantItem = true
		case t.kind == tWord && wantItem:
			values = append(values, t.text)
			wantItem = false
		case t.kind == tWord:
			p.errf(t, "policy/filter", "expected ',' before "+describe(t)+" in community list")
		default:
			p.errf(t, "policy/filter", "unexpected "+describe(t)+" in community list")
		}
		p.advance()
	}
	end := p.cur().end
	p.advance()
	return FilterCommunity{Op: CommunityEquals, Values: values, Raw: p.src[name.start:end]}
}

// parsePrefixList parses a brace-enclosed prefix-range list and an optional
// outer range operator, which is composed into each member (RFC 2622 §5.2).
func (p *parser) parsePrefixList() Filter {
	p.advance() // consume '{'
	var ranges []types.PrefixRange
	wantItem, commas := true, 0
	for !p.atEOF() && p.cur().kind != tRBrace {
		t := p.cur()
		switch t.kind {
		case tWord:
			pr, err := types.ParsePrefixRange(t.text)
			switch {
			case !wantItem:
				p.errf(t, "policy/prefix-list", "expected ',' before "+describe(t)+"; it is left out")
			case err != nil:
				p.errf(t, "policy/prefix-list", "invalid prefix "+describe(t))
			default:
				if hasHostBits(t.text) {
					p.warnf(t, "policy/host-bits", describe(t)+" has host bits set; it is read as "+pr.String())
				}
				p.warnPadded(t, pr.String())
				ranges = append(ranges, pr)
			}
			wantItem = false
		case tComma:
			if wantItem {
				p.warnf(t, "policy/prefix-list", "empty item in prefix list")
			}
			wantItem = true
			commas++
		default:
			p.errf(t, "policy/prefix-list", "unexpected token in prefix list")
		}
		p.advance()
	}
	if wantItem && commas > 0 && p.cur().kind == tRBrace {
		p.warnf(p.cur(), "policy/prefix-list", "empty item in prefix list")
	}
	if p.cur().kind != tRBrace {
		p.errf(p.cur(), "policy/prefix-list", "expected '}'")
		return FilterPrefixList{Ranges: ranges}
	}
	p.advance()
	if t := p.cur(); t.kind == tWord && strings.HasPrefix(t.text, "^") {
		p.advance()
		op, err := types.ParseRangeOperator(t.text[1:])
		if err != nil {
			p.errf(t, "policy/range-op", "invalid range operator "+describe(t))
			return FilterPrefixList{Ranges: ranges}
		}
		composed := ranges[:0]
		for _, r := range ranges {
			if c, ok := op.Apply(r); ok {
				composed = append(composed, c)
			}
		}
		ranges = composed
	}
	return FilterPrefixList{Ranges: ranges}
}

// hasHostBits reports whether the prefix of a prefix-range token ("a/n" or
// "a/n^op") has bits set beyond its length, which ParsePrefixRange clears.
func hasHostBits(text string) bool {
	base, _, _ := strings.Cut(text, "^")
	pfx, err := types.ParsePrefix(base)
	return err == nil && pfx != pfx.Masked()
}

// warnPadded reports an IPv4 address or prefix token written with zero-padded
// octets, which types.ParseAddr and ParsePrefix read as decimal.
func (p *parser) warnPadded(t token, canonical string) {
	text, _, _ := strings.Cut(t.text, "^")
	if types.PaddedIPv4(text) {
		p.warnf(t, "policy/leading-zeros", describe(t)+" has zero-padded octets; it is read as "+canonical+" (decimal)")
	}
}

// checkUnicodeSpace reports the first non-ASCII space in the value, which the
// tokenizer reads as whitespace (see otherSpaceAt).
func (p *parser) checkUnicodeSpace() {
	for i := 0; i < len(p.src); i++ {
		if size := otherSpaceAt(p.src, i); size > 0 {
			r, _ := utf8.DecodeRuneInString(p.src[i:])
			p.warnf(token{tWord, p.src[i : i+size], i, i + size}, "policy/unicode-space",
				fmt.Sprintf("%U is read as a space; RPSL separates tokens with ASCII spaces, tabs and newlines", r))
			return
		}
	}
}

// startsPeeringHere reports whether the current token can begin a via clause's
// peering (an AS number, an as-set or peering-set name, an AS-path regexp or a
// parenthesized AS expression), so that a via policy's right-hand side of
// EXCEPT is not mistaken for a filter.
func (p *parser) startsPeeringHere() bool {
	if p.via == "" {
		return false
	}
	t := p.cur()
	switch t.kind {
	case tRegex, tLParen:
		return true
	case tWord:
		if _, err := types.ParseASN(t.text); err == nil {
			return true
		}
		if sn, err := types.ParseSetName(t.text); err == nil {
			return sn.Class() == types.ClassAsSet || sn.Class() == types.ClassPeeringSet
		}
	}
	return false
}

// exceptHint explains a filter term where EXCEPT needs a policy: in
// "accept ANY except FLTR-BOGONS" (common in some registries) EXCEPT joins two
// policies (RFC 2622 §6.6), and the filter meant is "ANY AND NOT FLTR-BOGONS".
func exceptHint(peerKw string, t token) string {
	term := "<filter>"
	if t.kind == tWord {
		term = t.text
	}
	return "expected '" + peerKw + "' after EXCEPT: EXCEPT joins two policies; to leave " + term +
		" out of the filter, write \"AND NOT " + term + "\""
}

// describe names a token for a diagnostic: its text, quoted, or "end of value"
// for the end, whose text is empty. An AS-path regexp is quoted with its
// delimiters, since its text is only the body.
func describe(t token) string {
	switch t.kind {
	case tEOF:
		return "end of value"
	case tRegex:
		if t.end-t.start == len(t.text)+2 {
			return quote("<" + t.text + ">")
		}
		return quote("<" + t.text) // never closed
	}
	return quote(t.text)
}

// quote wraps a token for diagnostics.
func quote(s string) string { return "\"" + s + "\"" }
