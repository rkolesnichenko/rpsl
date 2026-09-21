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

type reToken struct {
	kind reTokKind
	text string
}

// reSingle maps the one-byte regexp operators to their token kinds.
var reSingle = map[byte]reTokKind{
	'^': reCaret, '$': reDollar, '.': reDot, '*': reStar, '+': rePlus,
	'?': reQuest, '|': rePipe, '(': reLParen, ')': reRParen, '{': reLBrace,
	'}': reRBrace, ',': reComma, '[': reLBracket, ']': reRBracket, '~': reTilde,
	'-': reDash,
}

// reTokenize splits a regexp body into tokens. A byte that is neither
// whitespace, an operator, nor part of a word is an error: skipping it would
// silently change the expression's meaning.
func reTokenize(body string) ([]reToken, error) {
	var toks []reToken
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
			toks = append(toks, reToken{kind: reWord, text: body[i:j]})
			i = j
		default:
			k, ok := reSingle[c]
			if !ok {
				return nil, fmt.Errorf("rpsl/policy: unexpected %q in AS-path regexp", c)
			}
			toks = append(toks, reToken{kind: k})
			i++
		}
	}
	return append(toks, reToken{kind: reEOF}), nil
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

// ParseASPathRegexp parses the interior of a <...> AS-path regexp (no angle
// brackets). It returns a structured AST or an error; it never panics.
func ParseASPathRegexp(body string) (*ASPathRE, error) {
	toks, err := reTokenize(body)
	if err != nil {
		return nil, err
	}
	p := &reParser{toks: toks}
	expr, err := p.parseAlt()
	if err != nil {
		return nil, err
	}
	if p.cur().kind != reEOF {
		return nil, fmt.Errorf("rpsl/policy: trailing tokens in AS-path regexp %q", body)
	}
	return &ASPathRE{Body: expr}, nil
}

func (p *reParser) parseAlt() (ASPathExpr, error) {
	// Each nested group "(...)" re-enters parseAlt; cap the depth so a regexp like
	// "<(((((…)))))>" cannot overflow the stack (shared cap with the policy parser).
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > maxParseDepth {
		return nil, fmt.Errorf("rpsl/policy: AS-path regexp nesting too deep")
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

// parseTerm parses an atom and any postfix quantifiers applied to it.
func (p *reParser) parseTerm() (ASPathExpr, error) {
	atom, err := p.parseAtom()
	if err != nil {
		return nil, err
	}
	for {
		same := false
		if p.cur().kind == reTilde {
			switch p.peek().kind {
			case reStar, rePlus, reLBrace:
				same = true
				p.advance()
			default:
				return nil, fmt.Errorf("rpsl/policy: '~' must be followed by *, + or {m,n}")
			}
		}
		var rep ASPathRepeat
		switch p.cur().kind {
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
			return nil, fmt.Errorf("rpsl/policy: quantifier applied to an anchor")
		}
		rep.Inner, rep.Same = atom, same
		atom = rep
	}
}

// parseRange parses a {m}, {m,} or {m,n} quantifier.
func (p *reParser) parseRange() (ASPathRepeat, error) {
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
		return ASPathRepeat{}, fmt.Errorf("rpsl/policy: expected '}' in quantifier")
	}
	p.advance()
	if hi >= 0 && hi < lo {
		return ASPathRepeat{}, fmt.Errorf("rpsl/policy: quantifier {%d,%d} has min > max", lo, hi)
	}
	return ASPathRepeat{Op: RepeatRange, Min: lo, Max: hi}, nil
}

func (p *reParser) quantBound(which string) (int, error) {
	t := p.cur()
	v, err := strconv.Atoi(t.text)
	if t.kind != reWord || err != nil || v < 0 {
		return 0, fmt.Errorf("rpsl/policy: invalid {m,n} %s bound %q", which, t.text)
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
			return nil, fmt.Errorf("rpsl/policy: expected ')' in AS-path regexp")
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
		return classifyASPathWord(t.text)
	default:
		return nil, fmt.Errorf("rpsl/policy: unexpected token in AS-path regexp")
	}
}

// parseClass parses "[...]" or "[^...]": ASNs, AS ranges ("AS1 - AS10" or
// "AS1-AS10"), as-sets, templates, PeerAS, and '.'.
func (p *reParser) parseClass() (ASPathExpr, error) {
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
			item, err := classifyASPathWord(t.text)
			if err != nil {
				lo, hi, ok := strings.Cut(t.text, "-")
				if !ok {
					return nil, err
				}
				if item, err = asnRange(lo, hi); err != nil {
					return nil, err
				}
			} else if p.cur().kind == reDash { // "AS1 - AS10"
				p.advance()
				if p.cur().kind != reWord {
					return nil, fmt.Errorf("rpsl/policy: expected AS number after '-' in [...]")
				}
				first, ok := item.(ASPathASN)
				if !ok {
					return nil, fmt.Errorf("rpsl/policy: range bound %q is not an AS number", t.text)
				}
				if item, err = asnRange(first.AS.String(), p.cur().text); err != nil {
					return nil, err
				}
				p.advance()
			}
			c.Items = append(c.Items, item)
		default:
			return nil, fmt.Errorf("rpsl/policy: unexpected token in AS-path [...] set")
		}
	}
	p.advance() // ']'
	if len(c.Items) == 0 {
		return nil, fmt.Errorf("rpsl/policy: empty [...] set in AS-path regexp")
	}
	return c, nil
}

// asnRange builds an inclusive AS range from two AS-number words.
func asnRange(lo, hi string) (ASPathExpr, error) {
	l, err1 := parseRegexpASN(lo)
	h, err2 := parseRegexpASN(hi)
	if err1 != nil || err2 != nil {
		return nil, fmt.Errorf("rpsl/policy: invalid AS range %s-%s", lo, hi)
	}
	if h < l {
		return nil, fmt.Errorf("rpsl/policy: AS range %s-%s is reversed", lo, hi)
	}
	return ASPathASNRange{Lo: l, Hi: h}, nil
}

// parseRegexpASN accepts plain ("3333") and AS-prefixed ("AS3333", "AS1.10")
// AS numbers.
func parseRegexpASN(w string) (types.ASN, error) {
	if v, err := strconv.ParseUint(w, 10, 32); err == nil {
		return types.ASN(v), nil
	}
	return types.ParseASN(w)
}

// classifyASPathWord resolves a word to an ASN, PeerAS, an as-set, or a PeerAS
// set-name template.
func classifyASPathWord(w string) (ASPathExpr, error) {
	if as, err := parseRegexpASN(w); err == nil {
		return ASPathASN{AS: as}, nil
	}
	if strings.EqualFold(w, "peeras") {
		return ASPathPeerAS{}, nil
	}
	if sn, err := types.ParseSetName(w); err == nil {
		return ASPathSet{Name: sn}, nil
	}
	if tpl, err := ParseSetNameTemplate(w); err == nil {
		return ASPathSetTemplate{Template: tpl}, nil
	}
	return nil, fmt.Errorf("rpsl/policy: invalid AS-path term %q", w)
}
