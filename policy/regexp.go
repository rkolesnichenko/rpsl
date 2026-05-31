package policy

import (
	"fmt"
	"strconv"

	"github.com/rkolesnichenko/rpsl/types"
)

// ASPathRE is a parsed AS-path regular expression (the body of a <...> term in
// import/export policy, RFC 2622 §5.6). It is structured but NOT evaluated
// against live BGP paths — that is a separate consumer's job (design guardrail).
// AnchorStart/AnchorEnd record a leading '^' / trailing '$'.
type ASPathRE struct {
	AnchorStart bool
	AnchorEnd   bool
	Body        ASPathExpr
}

// ASPathExpr is the sealed AS-path regexp node.
type ASPathExpr interface{ isASPathExpr() }

// ASPathAlt is a '|'-separated alternation of two or more branches.
type ASPathAlt struct{ Alts []ASPathExpr }

// ASPathSeq is an implicit concatenation of two or more terms.
type ASPathSeq struct{ Terms []ASPathExpr }

// ASPathRepeat applies a quantifier to an inner expression. Max is -1 when
// unbounded (for '*', '+', and open '{m,}' ranges).
type ASPathRepeat struct {
	Inner    ASPathExpr
	Op       RepeatOp
	Min, Max int
}

// ASPathAny is the '.' wildcard: any single AS.
type ASPathAny struct{}

// ASPathASN matches one specific autonomous system.
type ASPathASN struct{ AS types.ASN }

// ASPathSet matches any AS in the named as-set.
type ASPathSet struct{ Name types.SetName }

func (ASPathAlt) isASPathExpr()    {}
func (ASPathSeq) isASPathExpr()    {}
func (ASPathRepeat) isASPathExpr() {}
func (ASPathAny) isASPathExpr()    {}
func (ASPathASN) isASPathExpr()    {}
func (ASPathSet) isASPathExpr()    {}

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
	reEOF
)

type reToken struct {
	kind reTokKind
	text string
}

func reTokenize(body string) []reToken {
	var toks []reToken
	i, n := 0, len(body)
	emit := func(k reTokKind) { toks = append(toks, reToken{kind: k}) }
	for i < n {
		c := body[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			i++
		case c == '^':
			emit(reCaret)
			i++
		case c == '$':
			emit(reDollar)
			i++
		case c == '*':
			emit(reStar)
			i++
		case c == '+':
			emit(rePlus)
			i++
		case c == '?':
			emit(reQuest)
			i++
		case c == '|':
			emit(rePipe)
			i++
		case c == '(':
			emit(reLParen)
			i++
		case c == ')':
			emit(reRParen)
			i++
		case c == '{':
			emit(reLBrace)
			i++
		case c == '}':
			emit(reRBrace)
			i++
		case c == ',':
			emit(reComma)
			i++
		case c == '.':
			// A standalone '.' is the any-AS wildcard; asdot '.' inside an ASN
			// (e.g. AS1.10) is absorbed by the word scanner below.
			emit(reDot)
			i++
		case isWordStart(c):
			j := i
			for j < n {
				if isWordCont(body[j]) {
					j++
					continue
				}
				if body[j] == '.' && j+1 < n && isDigit(body[j+1]) { // asdot
					j++
					continue
				}
				break
			}
			toks = append(toks, reToken{kind: reWord, text: body[i:j]})
			i = j
		default:
			i++ // skip unknown byte; never stall
		}
	}
	return append(toks, reToken{kind: reEOF})
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
func (p *reParser) advance() {
	if p.pos < len(p.toks)-1 {
		p.pos++
	}
}

// ParseASPathRegexp parses the interior of a <...> AS-path regexp (no angle
// brackets). It returns a structured AST or an error; it never panics.
func ParseASPathRegexp(body string) (*ASPathRE, error) {
	p := &reParser{toks: reTokenize(body)}
	re := &ASPathRE{}
	if p.cur().kind == reCaret {
		re.AnchorStart = true
		p.advance()
	}
	expr, err := p.parseAlt()
	if err != nil {
		return nil, err
	}
	re.Body = expr
	if p.cur().kind == reDollar {
		re.AnchorEnd = true
		p.advance()
	}
	if p.cur().kind != reEOF {
		return nil, fmt.Errorf("rpsl/policy: trailing tokens in AS-path regexp %q", body)
	}
	return re, nil
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
	return k == reWord || k == reDot || k == reLParen
}

func (p *reParser) parseTerm() (ASPathExpr, error) {
	atom, err := p.parseAtom()
	if err != nil {
		return nil, err
	}
	switch p.cur().kind {
	case reStar:
		p.advance()
		return ASPathRepeat{Inner: atom, Op: RepeatStar, Min: 0, Max: -1}, nil
	case rePlus:
		p.advance()
		return ASPathRepeat{Inner: atom, Op: RepeatPlus, Min: 1, Max: -1}, nil
	case reQuest:
		p.advance()
		return ASPathRepeat{Inner: atom, Op: RepeatQuest, Min: 0, Max: 1}, nil
	case reLBrace:
		return p.parseRange(atom)
	default:
		return atom, nil
	}
}

func (p *reParser) parseRange(atom ASPathExpr) (ASPathExpr, error) {
	p.advance() // '{'
	if p.cur().kind != reWord {
		return nil, fmt.Errorf("rpsl/policy: expected number in {m,n} quantifier")
	}
	min, err := strconv.Atoi(p.cur().text)
	if err != nil {
		return nil, fmt.Errorf("rpsl/policy: invalid {m,n} lower bound %q", p.cur().text)
	}
	p.advance()
	max := min
	if p.cur().kind == reComma {
		p.advance()
		if p.cur().kind == reWord { // {m,n}
			max, err = strconv.Atoi(p.cur().text)
			if err != nil {
				return nil, fmt.Errorf("rpsl/policy: invalid {m,n} upper bound %q", p.cur().text)
			}
			p.advance()
		} else { // {m,}
			max = -1
		}
	}
	if p.cur().kind != reRBrace {
		return nil, fmt.Errorf("rpsl/policy: expected '}' in quantifier")
	}
	p.advance()
	return ASPathRepeat{Inner: atom, Op: RepeatRange, Min: min, Max: max}, nil
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
	case reDot:
		p.advance()
		return ASPathAny{}, nil
	case reWord:
		p.advance()
		return classifyASPathWord(t.text)
	default:
		return nil, fmt.Errorf("rpsl/policy: unexpected token in AS-path regexp")
	}
}

// classifyASPathWord resolves a word to an ASN (plain digits or AS-prefixed) or
// an as-set reference.
func classifyASPathWord(w string) (ASPathExpr, error) {
	if v, err := strconv.ParseUint(w, 10, 32); err == nil { // plain ASN, e.g. "3333"
		return ASPathASN{AS: types.ASN(v)}, nil
	}
	if as, err := types.ParseASN(w); err == nil {
		return ASPathASN{AS: as}, nil
	}
	if sn, err := types.ParseSetName(w); err == nil {
		return ASPathSet{Name: sn}, nil
	}
	return nil, fmt.Errorf("rpsl/policy: invalid AS-path term %q", w)
}
