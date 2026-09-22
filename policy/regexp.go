package policy

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/rkolesnichenko/rpsl/types"
)

// ASPathRE is a parsed AS-path regular expression (the body of a <...> term in
// import/export policy, RFC 2622 §5.4). It is structured but NOT evaluated
// against live BGP paths — that is a separate consumer's job (design guardrail).
// The '^' and '$' anchors are atoms of Body (ASPathStart / ASPathEnd), so they
// may appear anywhere, e.g. "<AS1$|AS2$>".
type ASPathRE struct {
	Body ASPathExpr
}

// ASPathExpr is the sealed AS-path regexp node.
type ASPathExpr interface{ isASPathExpr() }

// ASPathAlt is a '|'-separated alternation of two or more branches.
type ASPathAlt struct{ Alts []ASPathExpr }

// ASPathSeq is an implicit concatenation of zero or more terms.
type ASPathSeq struct{ Terms []ASPathExpr }

// ASPathRepeat applies a quantifier to an inner expression. Max is -1 when
// unbounded (for '*', '+', and open '{m,}' ranges). Same marks the ~*, ~+ and
// ~{m,n} forms, where every repetition must match the same AS.
type ASPathRepeat struct {
	Inner    ASPathExpr
	Op       RepeatOp
	Min, Max int
	Same     bool
}

// ASPathAny is the '.' wildcard: any single AS.
type ASPathAny struct{}

// ASPathASN matches one specific autonomous system.
type ASPathASN struct{ AS types.ASN }

// ASPathSet matches any AS in the named as-set.
type ASPathSet struct{ Name types.SetName }

// ASPathSetTemplate matches any AS in a per-peer as-set ("AS1:AS-X:PeerAS").
type ASPathSetTemplate struct{ Template SetNameTemplate }

// ASPathPeerAS matches the peer's AS (the PeerAS keyword).
type ASPathPeerAS struct{}

// ASPathStart is the '^' anchor: the beginning of the AS path.
type ASPathStart struct{}

// ASPathEnd is the '$' anchor: the end of the AS path.
type ASPathEnd struct{}

// ASPathClass is a bracketed AS set, "[...]", matching any one of its Items, or
// none of them when Negated ("[^...]"). Items are ASPathASN, ASPathASNRange,
// ASPathSet, ASPathSetTemplate, ASPathPeerAS, or ASPathAny.
type ASPathClass struct {
	Negated bool
	Items   []ASPathExpr
}

// ASPathASNRange is an inclusive AS-number range ("AS1 - AS10"). It appears only
// inside an ASPathClass.
type ASPathASNRange struct{ Lo, Hi types.ASN }

func (ASPathAlt) isASPathExpr()         {}
func (ASPathSeq) isASPathExpr()         {}
func (ASPathRepeat) isASPathExpr()      {}
func (ASPathAny) isASPathExpr()         {}
func (ASPathASN) isASPathExpr()         {}
func (ASPathSet) isASPathExpr()         {}
func (ASPathSetTemplate) isASPathExpr() {}
func (ASPathPeerAS) isASPathExpr()      {}
func (ASPathStart) isASPathExpr()       {}
func (ASPathEnd) isASPathExpr()         {}
func (ASPathClass) isASPathExpr()       {}
func (ASPathASNRange) isASPathExpr()    {}

// RepeatOp distinguishes the quantifier forms.
type RepeatOp uint8

const (
	RepeatStar  RepeatOp = iota // *   (0..∞)
	RepeatPlus                  // +   (1..∞)
	RepeatQuest                 // ?   (0..1)
	RepeatRange                 // {m} / {m,} / {m,n}
)

// ---- tokenizer over the regexp body ----

type reTokKind uint8

const (
	reWord reTokKind = iota
	reCaret
	reDollar
	reDot
	reStar
	rePlus
	reQuest
	rePipe
	reLParen
	reRParen
	reLBrace
	reRBrace
	reComma
	reLBracket
	reRBracket
	reTilde
	reDash
	reEOF
)

// reToken is one regexp token; start and end are byte offsets in the body.
type reToken struct {
	kind       reTokKind
	text       string
	start, end int
}

// reError is a problem in an AS-path regexp, located by byte offsets in the
// body so the policy parser can point at the offending token.
type reError struct {
	msg        string
	start, end int
}

func (e *reError) Error() string { return "rpsl/policy: " + e.msg }

// reSingle maps the one-byte regexp operators to their token kinds.
var reSingle = map[byte]reTokKind{
	'^': reCaret, '$': reDollar, '.': reDot, '*': reStar, '+': rePlus,
	'?': reQuest, '|': rePipe, '(': reLParen, ')': reRParen, '{': reLBrace,
	'}': reRBrace, ',': reComma, '[': reLBracket, ']': reRBracket, '~': reTilde,
	'-': reDash,
}

// errRegexpTooLong is returned for an AS-path regexp of more than maxTokens
// tokens, before they are all built.
var errRegexpTooLong = fmt.Errorf("rpsl/policy: AS-path regexp has more than %d tokens", maxTokens)

// reTokenize splits a regexp body into tokens, ending with reEOF. A byte that
// is neither whitespace, an operator, nor part of a word is an error: skipping
// it would silently change the expression's meaning.
func reTokenize(body string) ([]reToken, error) {
	count := 0
	if err := reScan(body, func(reToken) bool { count++; return count <= maxTokens }); err != nil {
		return nil, err
	}
	toks := make([]reToken, 0, count+1)
	_ = reScan(body, func(t reToken) bool { toks = append(toks, t); return true })
	return append(toks, reToken{kind: reEOF, start: len(body), end: len(body)}), nil
}

// reScan emits body's tokens to emit, returning errRegexpTooLong when emit
// refuses one and an error for a byte no token starts with.
func reScan(body string, emit func(reToken) bool) error {
	i, n := 0, len(body)
	for i < n {
		c := body[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			i++
		case isWordStart(c):
			j := i
			for j < n {
				if isWordCont(body[j]) {
					j++
					continue
				}
				if body[j] == '.' && j+1 < n && isDigit(body[j+1]) { // asdot, e.g. AS1.10
					j++
					continue
				}
				break
			}
			if !emit(reToken{reWord, body[i:j], i, j}) {
				return errRegexpTooLong
			}
			i = j
		default:
			k, ok := reSingle[c]
			if !ok {
				return &reError{fmt.Sprintf("unexpected %q in AS-path regexp", c), i, i + 1}
			}
			if !emit(reToken{k, body[i : i+1], i, i + 1}) {
				return errRegexpTooLong
			}
			i++
		}
	}
	return nil
}

func isDigit(c byte) bool     { return c >= '0' && c <= '9' }
func isWordStart(c byte) bool { return isDigit(c) || isLetter(c) }
func isLetter(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}
func isWordCont(c byte) bool {
	return isWordStart(c) || c == ':' || c == '_' || c == '-'
}

// ---- recursive-descent parser ----

type reParser struct {
	toks  []reToken
	pos   int
	depth int
	bare  []reToken // AS numbers written without "AS"
}

func (p *reParser) cur() reToken { return p.toks[p.pos] }
func (p *reParser) peek() reToken {
	if p.pos+1 < len(p.toks) {
		return p.toks[p.pos+1]
	}
	return p.toks[len(p.toks)-1]
}
func (p *reParser) advance() {
	if p.pos < len(p.toks)-1 {
		p.pos++
	}
}

// errAt returns an error located at t.
func errAt(t reToken, format string, args ...any) error {
	return &reError{fmt.Sprintf(format, args...), t.start, t.end}
}

// ParseASPathRegexp parses the interior of a <...> AS-path regexp (no angle
// brackets). It returns a structured AST or an error; it never panics. A bare
// number ("3333") is read as the AS it names; the policy parsers warn about it,
// since RFC 2622 writes AS3333.
func ParseASPathRegexp(body string) (*ASPathRE, error) {
	re, _, err := parseASPathRegexp(body)
	return re, err
}

// parseASPathRegexp is ParseASPathRegexp that also returns the bare-number
// tokens it read.
func parseASPathRegexp(body string) (*ASPathRE, []reToken, error) {
	toks, err := reTokenize(body)
	if err != nil {
		return nil, nil, err
	}
	if len(toks) == 1 {
		return nil, nil, &reError{"empty AS-path regexp", 0, len(body)}
	}
	p := &reParser{toks: toks}
	expr, err := p.parseAlt()
	if err != nil {
		return nil, nil, err
	}
	if t := p.cur(); t.kind != reEOF {
		return nil, nil, errAt(t, "unexpected %q in AS-path regexp", t.text)
	}
	return &ASPathRE{Body: expr}, p.bare, nil
}

func (p *reParser) parseAlt() (ASPathExpr, error) {
	// Each nested group "(...)" re-enters parseAlt; cap the depth so a regexp like
	// "<(((((…)))))>" cannot overflow the stack (shared cap with the policy parser).
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > maxParseDepth {
		return nil, errAt(p.cur(), "AS-path regexp nesting too deep")
	}
	first, err := p.parseSeq()
	if err != nil {
		return nil, err
	}
	alts := []ASPathExpr{first}
	for p.cur().kind == rePipe {
		p.advance()
		s, err := p.parseSeq()
		if err != nil {
			return nil, err
		}
		alts = append(alts, s)
	}
	if len(alts) == 1 {
		return first, nil
	}
	return ASPathAlt{Alts: alts}, nil
}

func (p *reParser) parseSeq() (ASPathExpr, error) {
	var terms []ASPathExpr
	for isAtomStart(p.cur().kind) {
		t, err := p.parseTerm()
		if err != nil {
			return nil, err
		}
		terms = append(terms, t)
	}
	if len(terms) == 1 {
		return terms[0], nil
	}
	return ASPathSeq{Terms: terms}, nil // len 0 = empty match
}

func isAtomStart(k reTokKind) bool {
	switch k {
	case reWord, reDot, reLParen, reLBracket, reCaret, reDollar:
		return true
	}
	return false
}

// parseTerm parses an atom and any postfix quantifiers applied to it. Each
// quantifier wraps the term one level deeper, so a run of them counts toward
// the nesting cap.
func (p *reParser) parseTerm() (ASPathExpr, error) {
	atom, err := p.parseAtom()
	if err != nil {
		return nil, err
	}
	for quantifiers := 0; ; quantifiers++ {
		if p.depth+quantifiers > maxParseDepth {
			return nil, errAt(p.cur(), "AS-path regexp nesting too deep")
		}
		same := false
		if t := p.cur(); t.kind == reTilde {
			switch p.peek().kind {
			case reStar, rePlus, reLBrace:
				same = true
				p.advance()
			default:
				return nil, errAt(t, "'~' must be followed by *, + or {m,n}")
			}
		}
		q := p.cur()
		var rep ASPathRepeat
		switch q.kind {
		case reStar:
			p.advance()
			rep = ASPathRepeat{Op: RepeatStar, Min: 0, Max: -1}
		case rePlus:
			p.advance()
			rep = ASPathRepeat{Op: RepeatPlus, Min: 1, Max: -1}
		case reQuest:
			p.advance()
			rep = ASPathRepeat{Op: RepeatQuest, Min: 0, Max: 1}
		case reLBrace:
			if rep, err = p.parseRange(); err != nil {
				return nil, err
			}
		default:
			return atom, nil
		}
		switch atom.(type) {
		case ASPathStart, ASPathEnd:
			return nil, errAt(q, "quantifier applied to an anchor")
		}
		rep.Inner, rep.Same = atom, same
		atom = rep
	}
}

// parseRange parses a {m}, {m,} or {m,n} quantifier.
func (p *reParser) parseRange() (ASPathRepeat, error) {
	open := p.cur()
	p.advance() // '{'
	lo, err := p.quantBound("lower")
	if err != nil {
		return ASPathRepeat{}, err
	}
	hi := lo
	if p.cur().kind == reComma {
		p.advance()
		if p.cur().kind == reWord { // {m,n}
			if hi, err = p.quantBound("upper"); err != nil {
				return ASPathRepeat{}, err
			}
		} else { // {m,}
			hi = -1
		}
	}
	if p.cur().kind != reRBrace {
		return ASPathRepeat{}, errAt(p.cur(), "expected '}' in quantifier")
	}
	closing := p.cur()
	p.advance()
	if hi >= 0 && hi < lo {
		return ASPathRepeat{}, &reError{fmt.Sprintf("quantifier {%d,%d} has min > max", lo, hi), open.start, closing.end}
	}
	return ASPathRepeat{Op: RepeatRange, Min: lo, Max: hi}, nil
}

func (p *reParser) quantBound(which string) (int, error) {
	t := p.cur()
	v, err := strconv.Atoi(t.text)
	if t.kind != reWord || err != nil || v < 0 {
		return 0, errAt(t, "invalid {m,n} %s bound %q", which, t.text)
	}
	p.advance()
	return v, nil
}

func (p *reParser) parseAtom() (ASPathExpr, error) {
	t := p.cur()
	switch t.kind {
	case reLParen:
		p.advance()
		inner, err := p.parseAlt()
		if err != nil {
			return nil, err
		}
		if p.cur().kind != reRParen {
			return nil, errAt(p.cur(), "expected ')' in AS-path regexp")
		}
		p.advance()
		return inner, nil
	case reLBracket:
		return p.parseClass()
	case reDot:
		p.advance()
		return ASPathAny{}, nil
	case reCaret:
		p.advance()
		return ASPathStart{}, nil
	case reDollar:
		p.advance()
		return ASPathEnd{}, nil
	case reWord:
		p.advance()
		return p.classifyWord(t)
	default:
		return nil, errAt(t, "unexpected %q in AS-path regexp", t.text)
	}
}

// parseClass parses "[...]" or "[^...]": ASNs, AS ranges ("AS1 - AS10" or
// "AS1-AS10"), as-sets, templates, PeerAS, and '.'.
func (p *reParser) parseClass() (ASPathExpr, error) {
	open := p.cur()
	p.advance() // '['
	var c ASPathClass
	if p.cur().kind == reCaret {
		c.Negated = true
		p.advance()
	}
	for p.cur().kind != reRBracket {
		t := p.cur()
		switch t.kind {
		case reDot:
			p.advance()
			c.Items = append(c.Items, ASPathAny{})
		case reWord:
			p.advance()
			item, err := p.classItem(t)
			if err != nil {
				return nil, err
			}
			c.Items = append(c.Items, item)
		case reEOF:
			return nil, errAt(open, "unterminated '[' in AS-path regexp")
		default:
			return nil, errAt(t, "unexpected %q in AS-path [...] set", t.text)
		}
	}
	p.advance() // ']'
	if len(c.Items) == 0 {
		return nil, errAt(open, "empty [...] set in AS-path regexp")
	}
	return c, nil
}

// classItem parses the [...] item that starts with word t: a range "AS1 - AS10"
// or "AS1-AS10", or a single term.
func (p *reParser) classItem(t reToken) (ASPathExpr, error) {
	if p.cur().kind == reDash {
		p.advance()
		last := p.cur()
		if last.kind != reWord {
			return nil, errAt(last, "expected AS number after '-' in [...]")
		}
		p.advance()
		return p.asnRange(t.text, last.text, t.start, last.end)
	}
	if lo, hi, ok := strings.Cut(t.text, "-"); ok && isASNWord(lo) && isASNWord(hi) {
		return p.asnRange(lo, hi, t.start, t.end)
	}
	return p.classifyWord(t)
}

// isASNWord reports whether w is an AS number, bare or AS-prefixed.
func isASNWord(w string) bool {
	_, _, err := regexpASN(w)
	return err == nil
}

// asnRange builds an inclusive AS range written from byte start to end,
// recording it if a bound is a bare number.
func (p *reParser) asnRange(lo, hi string, start, end int) (ASPathExpr, error) {
	l, lBare, err1 := regexpASN(lo)
	h, hBare, err2 := regexpASN(hi)
	switch {
	case err1 != nil || err2 != nil:
		return nil, &reError{fmt.Sprintf("invalid AS range %s-%s", lo, hi), start, end}
	case h < l:
		return nil, &reError{fmt.Sprintf("AS range %s-%s is reversed", lo, hi), start, end}
	}
	if lBare || hBare {
		p.bare = append(p.bare, reToken{reWord, lo + "-" + hi, start, end})
	}
	return ASPathASNRange{Lo: l, Hi: h}, nil
}

// regexpASN accepts plain ("3333") and AS-prefixed ("AS3333", "AS1.10") AS
// numbers; bare reports the plain form.
func regexpASN(w string) (as types.ASN, bare bool, err error) {
	if v, err := strconv.ParseUint(w, 10, 32); err == nil {
		return types.ASN(v), true, nil
	}
	as, err = types.ParseASN(w)
	return as, false, err
}

// classifyWord resolves a word to an ASN, PeerAS, an as-set, or an as-set
// template — the terms RFC 2622 §5.4 allows in an AS-path regexp.
func (p *reParser) classifyWord(t reToken) (ASPathExpr, error) {
	w := t.text
	if as, bare, err := regexpASN(w); err == nil {
		if bare {
			p.bare = append(p.bare, t)
		}
		return ASPathASN{AS: as}, nil
	}
	if strings.EqualFold(w, "peeras") {
		return ASPathPeerAS{}, nil
	}
	if sn, err := types.ParseSetName(w); err == nil {
		if sn.Class() != types.ClassAsSet {
			return nil, errAt(t, "%q is a %s; an AS-path regexp names AS numbers, as-sets and PeerAS", w, sn.Class())
		}
		return ASPathSet{Name: sn}, nil
	}
	if tpl, err := ParseSetNameTemplate(w); err == nil {
		if tpl.Class() != types.ClassAsSet {
			return nil, errAt(t, "%q is a %s template; an AS-path regexp names AS numbers, as-sets and PeerAS", w, tpl.Class())
		}
		return ASPathSetTemplate{Template: tpl}, nil
	}
	return nil, errAt(t, "invalid AS-path term %q", w)
}
