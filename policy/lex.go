package policy

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// tokKind enumerates the policy token classes.
type tokKind uint8

const (
	tWord   tokKind = iota // identifier, ASN, set name, prefix-range, number, keyword
	tLBrace                // {
	tRBrace                // }
	tLParen                // (
	tRParen                // )
	tSemi                  // ;
	tComma                 // ,
	tEq                    // =
	tRegex                 // <...> AS-path regexp; text excludes the angle brackets
	tStray                 // a '>' outside a regexp; diagnosed and removed by newParser
	tEOF
)

// token is one lexical unit with byte offsets into the source value. start/end
// bracket the token text in the original string so the parser can recover exact
// raw slices (used for actions and unparsed leaves).
type token struct {
	kind  tokKind
	text  string
	start int
	end   int
}

// isWordByte reports whether c may appear inside a word token. Words greedily
// absorb the characters that make up ASNs (incl. asdot '.'), set names (':'),
// prefixes ('/', '.', ':'), and prefix-range operators ('^', '+', '-'). The
// structural punctuation { } ( ) ; , = < > and whitespace terminate a word.
func isWordByte(c byte) bool {
	switch c {
	case ' ', '\t', '\r', '\n', '{', '}', '(', ')', ';', ',', '=', '<', '>':
		return false
	}
	return true
}

// tokenize splits a policy value into tokens, ending with tEOF. It never
// fails on malformed input (an unterminated <...> regexp runs to the end of the
// input and a stray '>' is a tStray token, both for the parser to diagnose),
// but reports false when the value has more than maxTokens tokens. It
// counts first and then fills a slice of exactly that size, so memory stays
// proportional to the tokens a value really has.
func tokenize(src string) ([]token, bool) {
	count := 0
	if !scan(src, func(token) bool { count++; return count <= maxTokens+1 }) {
		return nil, false
	}
	toks := make([]token, 0, count)
	scan(src, func(t token) bool { toks = append(toks, t); return true })
	return toks, true
}

// scan emits src's tokens, then tEOF, to emit; it stops early, reporting false,
// when emit does.
func scan(src string, emit func(token) bool) bool {
	i, n := 0, len(src)
	for i < n {
		c := src[i]
		if size := otherSpaceAt(src, i); size > 0 {
			i += size // a Unicode space separates tokens as an ASCII one does
			continue
		}
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			i++
		case c == '{':
			if !emit(token{tLBrace, "{", i, i + 1}) {
				return false
			}
			i++
		case c == '}':
			if !emit(token{tRBrace, "}", i, i + 1}) {
				return false
			}
			i++
		case c == '(':
			if !emit(token{tLParen, "(", i, i + 1}) {
				return false
			}
			i++
		case c == ')':
			if !emit(token{tRParen, ")", i, i + 1}) {
				return false
			}
			i++
		case c == ';':
			if !emit(token{tSemi, ";", i, i + 1}) {
				return false
			}
			i++
		case c == ',':
			if !emit(token{tComma, ",", i, i + 1}) {
				return false
			}
			i++
		case c == '=':
			if !emit(token{tEq, "=", i, i + 1}) {
				return false
			}
			i++
		case (c == '<' || c == '>') && relOpAt(src, i) != "":
			// "<<=", "<=", ">>=" and ">=" are action or comparison operators
			// (RFC 2622 Figure 25), never a regexp delimiter.
			op := relOpAt(src, i)
			if !emit(token{tWord, op, i, i + len(op)}) {
				return false
			}
			i += len(op)
		case c == '<':
			// Scan an AS-path regexp to the matching '>'. Kept raw; not nested.
			j := i + 1
			for j < n && src[j] != '>' {
				j++
			}
			body := src[i+1 : j]
			end := j
			if j < n { // include the '>' in the consumed span
				end = j + 1
			}
			if !emit(token{tRegex, body, i, end}) {
				return false
			}
			i = end
		case c == '>':
			// A '>' outside a <...> regexp closes nothing.
			if !emit(token{tStray, ">", i, i + 1}) {
				return false
			}
			i++
		default:
			j := i
			for j < n && isWordByte(src[j]) && otherSpaceAt(src, j) == 0 {
				j++
			}
			if j == i { // defensive: never stall on an unclassified byte
				i++
				continue
			}
			if !emit(token{tWord, src[i:j], i, j}) {
				return false
			}
			i = j
		}
	}
	return emit(token{tEOF, "", n, n})
}

// otherSpaceAt returns the length of the space at src[i:] that is not an ASCII
// space, tab or newline, or 0: a vertical tab or form feed, a no-break space
// (U+00A0), an ideographic space (U+3000), … — whatever unicode.IsSpace
// reports. RPSL separates tokens with spaces and tabs, but registries hold such
// spaces in policies, and IRRd, splitting with Python's str.split, reads them as
// whitespace; the parser reports the first one (policy/unicode-space).
func otherSpaceAt(src string, i int) int {
	if c := src[i]; c < utf8.RuneSelf {
		if c == '\v' || c == '\f' {
			return 1
		}
		return 0
	}
	if r, size := utf8.DecodeRuneInString(src[i:]); unicode.IsSpace(r) {
		return size
	}
	return 0
}

// isOtherSpace reports whether r is a space otherSpaceAt reads.
func isOtherSpace(r rune) bool {
	return unicode.IsSpace(r) && r != ' ' && r != '\t' && r != '\r' && r != '\n'
}

// relOpAt returns the operator "<<=", "<=", ">>=" or ">=" at src[i:], or "".
func relOpAt(src string, i int) string {
	for _, op := range [...]string{"<<=", ">>=", "<=", ">="} {
		if strings.HasPrefix(src[i:], op) {
			return op
		}
	}
	return ""
}

// closed reports whether a tRegex token ends with its '>'.
func (t token) closed() bool { return t.end-t.start == len(t.text)+2 }

// kw reports whether a word token equals the given keyword, case-insensitively.
func (t token) kw(word string) bool {
	return t.kind == tWord && strings.EqualFold(t.text, word)
}
