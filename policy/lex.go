package policy

import "strings"

// tokKind enumerates the policy token classes.
type tokKind uint8

const (
	tWord   tokKind = iota // identifier, ASN, set name, prefix-range, number, keyword
	tLBrace               // {
	tRBrace               // }
	tLParen               // (
	tRParen               // )
	tSemi                 // ;
	tComma                // ,
	tEq                   // =
	tRegex                // <...> AS-path regexp; text excludes the angle brackets
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

// tokenize splits a policy attribute value into tokens. It never fails: an
// unterminated <...> regexp simply runs to end of input.
func tokenize(src string) []token {
	var toks []token
	i, n := 0, len(src)
	for i < n {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			i++
		case c == '{':
			toks = append(toks, token{tLBrace, "{", i, i + 1})
			i++
		case c == '}':
			toks = append(toks, token{tRBrace, "}", i, i + 1})
			i++
		case c == '(':
			toks = append(toks, token{tLParen, "(", i, i + 1})
			i++
		case c == ')':
			toks = append(toks, token{tRParen, ")", i, i + 1})
			i++
		case c == ';':
			toks = append(toks, token{tSemi, ";", i, i + 1})
			i++
		case c == ',':
			toks = append(toks, token{tComma, ",", i, i + 1})
			i++
		case c == '=':
			toks = append(toks, token{tEq, "=", i, i + 1})
			i++
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
			toks = append(toks, token{tRegex, body, i, end})
			i = end
		case c == '>':
			// A '>' outside a <...> regexp is stray punctuation; skip it so the
			// scanner always makes progress.
			i++
		default:
			j := i
			for j < n && isWordByte(src[j]) {
				j++
			}
			if j == i { // defensive: never stall on an unclassified byte
				i++
				continue
			}
			toks = append(toks, token{tWord, src[i:j], i, j})
			i = j
		}
	}
	toks = append(toks, token{tEOF, "", n, n})
	return toks
}

// kw reports whether a word token equals the given keyword, case-insensitively.
func (t token) kw(word string) bool {
	return t.kind == tWord && strings.EqualFold(t.text, word)
}
