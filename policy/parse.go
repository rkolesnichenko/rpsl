package policy

import (
	"strings"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/lexer"
	"github.com/rkolesnichenko/rpsl/types"
)

// ParseImport parses an import: value ("[protocol …] [into …] from <peering>
// [action …] … accept <filter>"). It returns a best-effort Import plus
// diagnostics whose spans are byte offsets within s (the caller re-bases them
// onto the owning attribute). It never panics.
func ParseImport(s string) (Import, []ast.Diagnostic) {
	p := newParser(s)
	imp := Import{}
	imp.Protocol, imp.IntoProtocol = p.parseProtocols()
	imp.AFIs = p.parseAFIs()
	imp.Expr = p.parseExpr("from", "accept")
	return imp, p.diags
}

// ParseExport parses an export: value ("… to <peering> [action …] … announce
// <filter>"). Structurally identical to ParseImport but with to/announce.
func ParseExport(s string) (Export, []ast.Diagnostic) {
	p := newParser(s)
	exp := Export{}
	exp.Protocol, exp.IntoProtocol = p.parseProtocols()
	exp.AFIs = p.parseAFIs()
	exp.Expr = p.parseExpr("to", "announce")
	return exp, p.diags
}

// ParseDefault parses a default: value ("to <peering> [action …] [networks
// <filter>]"). Networks is nil when no networks clause is present.
func ParseDefault(s string) (Default, []ast.Diagnostic) {
	p := newParser(s)
	d := Default{}
	d.AFIs = p.parseAFIs()
	if !p.cur().kw("to") {
		p.errf(p.cur(), "policy/default-to", "expected 'to' at start of default")
		return d, p.diags
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
	return d, p.diags
}

// maxParseDepth caps recursion in the policy and AS-path-regexp parsers. Hostile
// input — deeply nested parens/braces or a long "not not not …" chain — would
// otherwise recurse one stack frame per level and overflow the stack. Past the
// cap we record a diagnostic and stop descending instead of panicking. Real
// policy nests only a handful of levels, so this never trips on valid data.
const maxParseDepth = 1000

// ParsePeering parses a standalone peering specification (the value of a
// peering:/mp-peering: attribute in a peering-set). It returns a best-effort
// Peering plus diagnostics; it never panics.
func ParsePeering(s string) (Peering, []ast.Diagnostic) {
	p := newParser(s)
	return p.parsePeering(), p.diags
}

// ParseFilter parses a standalone policy filter (the value of a filter:/mp-filter:
// attribute in a filter-set). It returns a best-effort Filter plus diagnostics;
// it never panics.
func ParseFilter(s string) (Filter, []ast.Diagnostic) {
	p := newParser(s)
	return p.parseFilter(), p.diags
}

type parser struct {
	src   string
	toks  []token
	pos   int
	depth int
	diags []ast.Diagnostic
}

func newParser(s string) *parser { return &parser{src: s, toks: tokenize(s)} }

func (p *parser) cur() token { return p.toks[p.pos] }
func (p *parser) advance() {
	if p.pos < len(p.toks)-1 {
		p.pos++
	}
}
func (p *parser) atEOF() bool { return p.cur().kind == tEOF }

func (p *parser) errf(t token, rule, msg string) {
	p.diags = append(p.diags, ast.Diagnostic{
		Severity: ast.Error,
		Message:  msg,
		Span: lexer.Span{
			StartLine: 1, EndLine: 1,
			StartCol: t.start, EndCol: t.end,
			StartByte: t.start, EndByte: t.end,
		},
		Rule: rule,
	})
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
// that is not a valid address family (typically the from/to/{ that begins the
// expression).
func (p *parser) parseAFIs() []types.AddrFamily {
	if !p.cur().kw("afi") {
		return nil
	}
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
			break
		}
		afis = append(afis, af)
		p.advance()
		if p.cur().kind == tComma {
			p.advance()
		}
	}
	return afis
}

// parseExpr parses a policy expression: a term, optionally composed with
// left-associative EXCEPT / REFINE operators.
func (p *parser) parseExpr(peerKw, filterKw string) Expr {
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > maxParseDepth {
		p.errf(p.cur(), "policy/nesting", "policy expression nesting too deep")
		return ExprList{}
	}
	left := p.parseTerm(peerKw, filterKw)
	for {
		switch {
		case p.cur().kw("except"):
			p.advance()
			afis := p.parseAFIs() // an afi clause scopes the refinement
			left = Except{Left: left, AFIs: afis, Right: p.parseTerm(peerKw, filterKw)}
		case p.cur().kw("refine"):
			p.advance()
			afis := p.parseAFIs()
			left = Refine{Left: left, AFIs: afis, Right: p.parseTerm(peerKw, filterKw)}
		default:
			return left
		}
	}
}

// parseTerm parses either a brace-enclosed expression list or a single factor.
func (p *parser) parseTerm(peerKw, filterKw string) Expr {
	if p.cur().kind != tLBrace {
		return p.parseFactor(peerKw, filterKw)
	}
	p.advance() // consume '{'
	var exprs []Expr
	for !p.atEOF() && p.cur().kind != tRBrace {
		start := p.pos
		exprs = append(exprs, p.parseExpr(peerKw, filterKw))
		if p.cur().kind == tSemi {
			p.advance()
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
// followed by a "<filterKw> <filter>" clause.
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
	if p.cur().kw(filterKw) {
		p.advance()
		f.Filter = p.parseFilter()
	} else if !p.atEOF() {
		p.errf(p.cur(), "policy/expect-filter", "expected '"+filterKw+"' clause")
	}
	return f
}

// isClauseKw reports whether the token begins a new clause (and thus terminates
// the current peering, action list, or router list).
func isClauseKw(t token) bool {
	return t.kw("from") || t.kw("to") || t.kw("accept") || t.kw("announce") ||
		t.kw("action") || t.kw("networks") || t.kw("except") || t.kw("refine")
}

// parsePeering parses a peering specification: an AS expression with optional
// routers, a peering-set reference, or an AS-path regexp.
func (p *parser) parsePeering() Peering {
	t := p.cur()
	if t.kind == tRegex {
		p.advance()
		return PeeringRegexp{Raw: t.text, Regexp: p.parseRegexp(t)}
	}
	if t.kind != tWord {
		p.errf(t, "policy/peering", "expected peering specification")
		p.advance() // guarantee progress
		return PeeringAS{}
	}
	p.advance()
	if asn, err := types.ParseASN(t.text); err == nil {
		router, at := p.parseRouters()
		return PeeringAS{AS: ASNum{AS: asn}, Router: router, AtRouter: at}
	}
	if sn, err := types.ParseSetName(t.text); err == nil {
		if sn.Class == types.PeeringSet {
			return PeeringSetRef{Name: sn}
		}
		router, at := p.parseRouters()
		return PeeringAS{AS: ASSetRef{Name: sn}, Router: router, AtRouter: at}
	}
	p.errf(t, "policy/peering", "invalid peering term "+quote(t.text))
	return PeeringAS{}
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

// parseRouters consumes an optional router word and an optional "at <router>".
func (p *parser) parseRouters() (router, at string) {
	t := p.cur()
	if t.kind == tWord && !isClauseKw(t) && !t.kw("at") && !isFilterOp(t) {
		router = t.text
		p.advance()
	}
	if p.cur().kw("at") {
		p.advance()
		if p.cur().kind == tWord {
			at = p.cur().text
			p.advance()
		}
	}
	return
}

// parseActions parses a ';'-separated action list, stopping at a clause keyword
// or EOF. Each action's raw text is interpreted into attr/op/value.
func (p *parser) parseActions() []Action {
	var actions []Action
	for !p.atEOF() && !isClauseKw(p.cur()) {
		start := p.cur().start
		end := start
		for !p.atEOF() && p.cur().kind != tSemi && !isClauseKw(p.cur()) {
			end = p.cur().end
			p.advance()
		}
		if raw := strings.TrimSpace(p.src[start:end]); raw != "" {
			actions = append(actions, parseAction(raw))
		}
		if p.cur().kind == tSemi {
			p.advance()
		} else {
			break
		}
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

// parseFilter parses a policy filter with precedence NOT > AND > OR.
func (p *parser) parseFilter() Filter { return p.parseFilterOr() }

func (p *parser) parseFilterOr() Filter {
	l := p.parseFilterAnd()
	for p.cur().kw("or") {
		p.advance()
		r := p.parseFilterAnd()
		l = FilterOr{L: l, R: r}
	}
	return l
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
	if p.cur().kw("not") {
		p.depth++
		defer func() { p.depth-- }()
		if p.depth > maxParseDepth {
			p.errf(p.cur(), "policy/nesting", "filter nesting too deep")
			p.advance() // consume the 'not' to guarantee progress
			return nil
		}
		p.advance()
		return FilterNot{Inner: p.parseFilterNot()}
	}
	return p.parseFilterPrimary()
}

func (p *parser) parseFilterPrimary() Filter {
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > maxParseDepth {
		p.errf(p.cur(), "policy/nesting", "filter nesting too deep")
		p.advance() // consume a token to guarantee progress
		return nil
	}
	t := p.cur()
	switch t.kind {
	case tLParen:
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
		return p.parseFilterWord()
	default:
		p.errf(t, "policy/filter", "unexpected token in filter")
		p.advance()
		return nil
	}
}

// parseFilterWord handles word-led filter leaves: ANY, PeerAS, community(...),
// AS expressions, and set references.
func (p *parser) parseFilterWord() Filter {
	t := p.cur()
	if t.kw("any") {
		p.advance()
		return FilterAny{}
	}
	if t.kw("peeras") {
		p.advance()
		return FilterPeerAS{}
	}
	// A word immediately followed by '(' is a method-call filter (community(...)).
	if p.toks[p.pos+1].kind == tLParen {
		start := t.start
		end := t.end
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
	if asn, err := types.ParseASN(t.text); err == nil {
		return FilterASExpr{AS: ASNum{AS: asn}}
	}
	if sn, err := types.ParseSetName(t.text); err == nil {
		if sn.Class == types.AsSet {
			return FilterASExpr{AS: ASSetRef{Name: sn}}
		}
		return FilterSetRef{Name: sn}
	}
	p.errf(t, "policy/filter", "invalid filter term "+quote(t.text))
	return nil
}

// parsePrefixList parses a brace-enclosed prefix-range list.
func (p *parser) parsePrefixList() Filter {
	p.advance() // consume '{'
	var ranges []types.PrefixRange
	for !p.atEOF() && p.cur().kind != tRBrace {
		t := p.cur()
		if t.kind == tWord {
			if pr, err := types.ParsePrefixRange(t.text); err == nil {
				ranges = append(ranges, pr)
			} else {
				p.errf(t, "policy/prefix-list", "invalid prefix "+quote(t.text))
			}
			p.advance()
		} else if t.kind == tComma {
			p.advance()
		} else {
			p.errf(t, "policy/prefix-list", "unexpected token in prefix list")
			p.advance()
		}
	}
	if p.cur().kind == tRBrace {
		p.advance()
	} else {
		p.errf(p.cur(), "policy/prefix-list", "expected '}'")
	}
	return FilterPrefixList{Ranges: ranges}
}

// isFilterOp reports whether the token is a boolean filter operator keyword.
func isFilterOp(t token) bool { return t.kw("and") || t.kw("or") || t.kw("not") }

// quote wraps a token for diagnostics.
func quote(s string) string { return "\"" + s + "\"" }
