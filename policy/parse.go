package policy

import (
	"strings"

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
	diags  []ast.Diagnostic
}

func newParser(s string) *parser { return &parser{src: s, toks: tokenize(s)} }

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
// would only be cascades of the abandoned parse.
func (p *parser) diag(sev ast.Severity, t token, rule, msg string) {
	if p.bailed {
		return
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
		p.errf(p.cur(), "policy/trailing", "unexpected "+quote(p.cur().text)+" after the policy expression")
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
	if p.cur().kw("protocol") {
		p.advance()
		if p.cur().kind == tWord {
			proto = p.cur().text
			p.advance()
		}
	}
	if p.cur().kw("into") {
		p.advance()
		if p.cur().kind == tWord {
			into = p.cur().text
			p.advance()
		}
	}
	return
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
		if t.kind != tWord || isClauseKw(t) {
			break
		}
		af, err := types.ParseAddrFamily(t.text)
		if err != nil {
			p.errf(t, "policy/afi", "invalid address family "+quote(t.text))
			return afis
		}
		afis = append(afis, af)
		p.advance()
		if p.cur().kind == tComma {
			p.advance()
		}
	}
	if len(afis) == 0 {
		p.errf(afiTok, "policy/afi", "empty afi list")
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
		return Except{Left: left, AFIs: afis, Right: p.parseExpr(peerKw, filterKw)}
	case p.cur().kw("refine"):
		p.advance()
		afis := p.parseAFIs()
		return Refine{Left: left, AFIs: afis, Right: p.parseExpr(peerKw, filterKw)}
	}
	return left
}

// parseTerm parses a single factor or a brace-enclosed list of expressions, each
// terminated by ';' (optional before the closing brace).
func (p *parser) parseTerm(peerKw, filterKw string) Expr {
	if p.cur().kind != tLBrace {
		return p.parseFactor(peerKw, filterKw)
	}
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
		if sn, err := types.ParseSetName(t.text); err == nil && sn.Class() == types.PeeringSet {
			p.advance()
			return PeeringSetRef{Name: sn}
		}
	}
	if (t.kind != tWord && t.kind != tLParen) || isPeeringStop(t) || t.kw("at") {
		p.errf(t, "policy/peering", "expected peering specification")
		return PeeringAS{}
	}
	as, ok := p.parseASExpr()
	if !ok {
		return PeeringAS{}
	}
	pa := PeeringAS{AS: as, Router: p.parseRouterExpr()}
	if p.cur().kw("at") {
		atTok := p.cur()
		p.advance()
		if pa.AtRouter = p.parseRouterExpr(); pa.AtRouter == "" {
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
func (p *parser) parseASExpr() (ASExpr, bool) {
	l, ok := p.parseASAnd()
	for ok && p.cur().kw("or") {
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
	if t.kind != tWord || isPeeringStop(t) || t.kw("at") || t.kw("and") || t.kw("or") || t.kw("except") {
		p.errf(t, "policy/as-expr", "expected an AS number or as-set")
		return nil, false
	}
	p.advance()
	if asn, err := types.ParseASN(t.text); err == nil {
		return ASNum{AS: asn}, true
	}
	if sn, err := types.ParseSetName(t.text); err == nil {
		if sn.Class() == types.AsSet {
			return ASSetRef{Name: sn}, true
		}
		p.errf(t, "policy/peering", quote(t.text)+" is a "+sn.Class().String()+", not an as-set")
		return nil, false
	}
	if tpl, err := ParseSetNameTemplate(t.text); err == nil && tpl.Class() == types.AsSet {
		return ASSetTemplate{Template: tpl}, true
	}
	p.errf(t, "policy/peering", "invalid peering term "+quote(t.text))
	return nil, false
}

// parseRouterExpr captures a router expression — router addresses, inet-rtr
// and rtr-set names combined with AND/OR/EXCEPT and parentheses (RFC 2622
// §5.6) — as raw text, stopping at "at" or the end of the peering.
func (p *parser) parseRouterExpr() string {
	start, end, depth := -1, -1, 0
	for {
		t := p.cur()
		if depth == 0 && (isPeeringStop(t) || t.kw("at")) {
			break
		}
		switch t.kind {
		case tLParen:
			depth++
		case tRParen:
			if depth == 0 {
				p.errf(t, "policy/peering", "unbalanced ')' in router expression")
				return p.rawSpan(start, end)
			}
			depth--
		case tWord:
		default: // regexps, braces, commas, '=' are not router syntax
			if depth == 0 {
				return p.rawSpan(start, end)
			}
		}
		if t.kind == tEOF {
			p.errf(t, "policy/peering", "unbalanced '(' in router expression")
			break
		}
		if start < 0 {
			start = t.start
		}
		end = t.end
		p.advance()
	}
	return p.rawSpan(start, end)
}

func (p *parser) rawSpan(start, end int) string {
	if start < 0 {
		return ""
	}
	return p.src[start:end]
}

// parseRegexp parses an AS-path regexp body, recording a non-fatal diagnostic
// (and returning nil) if it does not parse. The Raw text is kept regardless.
func (p *parser) parseRegexp(t token) *ASPathRE {
	re, err := ParseASPathRegexp(t.text)
	if err != nil {
		p.errf(t, "policy/as-path-regexp", err.Error())
		return nil
	}
	return re
}

// parseActions parses a ';'-separated action list, stopping at a clause keyword,
// an unmatched '}', or EOF. Each action's raw text is interpreted into
// attr/op/value; braces inside a value ("community .= {1:2}") are kept.
func (p *parser) parseActions() []Action {
	var actions []Action
	for !p.atEOF() && !isClauseKw(p.cur()) && p.cur().kind != tRBrace {
		start := p.cur().start
		end := start
		depth := 0
		for !p.atEOF() && !isClauseKw(p.cur()) {
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
			actions = append(actions, parseAction(raw))
		}
		if p.cur().kind != tSemi {
			break
		}
		p.advance()
	}
	return actions
}

// parseAction interprets one action's raw text.
func parseAction(raw string) Action {
	if eq := strings.IndexByte(raw, '='); eq >= 0 {
		left := strings.TrimSpace(raw[:eq])
		right := strings.TrimSpace(raw[eq+1:])
		if strings.HasSuffix(left, ".") {
			return Action{Attr: normAttr(strings.TrimSuffix(left, ".")), Op: ActionAppend, Value: right}
		}
		return Action{Attr: normAttr(left), Op: ActionAssign, Value: right}
	}
	if paren := strings.IndexByte(raw, '('); paren >= 0 {
		return Action{Attr: normAttr(raw[:paren]), Op: ActionMethod, Value: raw}
	}
	return Action{Attr: normAttr(raw), Op: ActionMethod, Value: raw}
}

// normAttr canonicalizes an rp-attribute name (lowercase, trimmed). Method
// targets like "aspath.prepend" keep their dotted form.
func normAttr(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// parseFilter parses a policy filter (RFC 2622 §5.4) with precedence
// NOT > AND > OR, where juxtaposition ("x y") is an implicit OR.
func (p *parser) parseFilter() Filter { return p.parseFilterOr() }

func (p *parser) parseFilterOr() Filter {
	l := p.parseFilterAnd()
	for {
		if p.cur().kw("or") {
			p.advance()
		} else if !startsFilterTerm(p.cur()) {
			return l
		}
		start := p.pos
		r := p.parseFilterAnd()
		l = FilterOr{L: l, R: r}
		if p.pos == start { // defensive: guarantee progress
			p.advance()
		}
	}
}

// startsFilterTerm reports whether t can begin another filter term, i.e. an
// implicit OR continues the filter.
func startsFilterTerm(t token) bool {
	switch t.kind {
	case tLParen, tLBrace, tRegex:
		return true
	case tWord:
		return !isFilterStop(t)
	}
	return false
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
	l := p.parseFilterNot()
	for p.cur().kw("and") {
		p.advance()
		r := p.parseFilterNot()
		l = FilterAnd{L: l, R: r}
	}
	return l
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
		if !isFilterStop(t) {
			return p.parseFilterWord()
		}
	}
	p.errf(t, "policy/filter", "unexpected "+quote(t.text)+" in filter")
	if t.kind != tEOF {
		p.advance()
	}
	return nil
}

// parseFilterWord handles word-led filter terms: ANY, PeerAS, method calls
// (community(...)), AS numbers, set names, and PeerAS set-name templates, each
// optionally followed by a range operator ("AS-FOO^+", "PeerAS^0-32").
func (p *parser) parseFilterWord() Filter {
	t := p.cur()
	// A word immediately followed by '(' is a method-call filter (community(...)).
	if p.peek().kind == tLParen {
		start, end := t.start, t.end
		p.advance() // word
		depth := 0
		for !p.atEOF() {
			c := p.cur()
			if c.kind == tLParen {
				depth++
			}
			end = c.end
			p.advance()
			if c.kind == tRParen {
				depth--
				if depth == 0 {
					break
				}
			}
		}
		return FilterCommunity{Raw: p.src[start:end]}
	}
	p.advance()
	base, opText, hasOp := strings.Cut(t.text, "^")
	var op types.RangeOperator
	if hasOp {
		o, err := types.ParseRangeOperator(opText)
		if err != nil {
			p.errf(t, "policy/range-op", "invalid range operator in "+quote(t.text))
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
		case types.AsSet:
			return FilterASExpr{AS: ASSetRef{Name: sn}, Op: op}
		case types.RouteSet:
			return FilterSetRef{Name: sn, Op: op}
		case types.FilterSet:
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
		case types.AsSet:
			return FilterASExpr{AS: ASSetTemplate{Template: tpl}, Op: op}
		case types.RouteSet, types.FilterSet:
			return FilterSetTemplate{Template: tpl, Op: op}
		}
	}
	p.errf(t, "policy/filter", "invalid filter term "+quote(t.text))
	return nil
}

// parsePrefixList parses a brace-enclosed prefix-range list and an optional
// outer range operator, which is composed into each member (RFC 2622 §5.2).
func (p *parser) parsePrefixList() Filter {
	p.advance() // consume '{'
	var ranges []types.PrefixRange
	for !p.atEOF() && p.cur().kind != tRBrace {
		t := p.cur()
		switch t.kind {
		case tWord:
			if pr, err := types.ParsePrefixRange(t.text); err == nil {
				ranges = append(ranges, pr)
			} else {
				p.errf(t, "policy/prefix-list", "invalid prefix "+quote(t.text))
			}
		case tComma:
		default:
			p.errf(t, "policy/prefix-list", "unexpected token in prefix list")
		}
		p.advance()
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
			p.errf(t, "policy/range-op", "invalid range operator "+quote(t.text))
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

// quote wraps a token for diagnostics.
func quote(s string) string { return "\"" + s + "\"" }
