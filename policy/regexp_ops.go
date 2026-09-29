package policy

import (
	"sort"
	"strconv"
	"strings"

	"github.com/rkolesnichenko/rpsl/types"
)

// Operations on a parsed AS-path regexp that a policy evaluator and a router
// configuration printer need: rendering it, binding it to a peer, and listing
// the as-sets it names. None evaluates it against a path (design §13).

// Precedences for rendering, lowest first: an alternation, a sequence, an atom.
const (
	rePrecAlt = iota
	rePrecSeq
	rePrecAtom
)

// String renders the regexp without its angle brackets, in a canonical form
// that ParseASPathRegexp reads back to the same tree: terms separated by one
// space, a class's range as "AS1 - AS10" (a word may contain '-', so the
// spaces are needed), groups in parentheses only where precedence needs them.
// A nil regexp renders as "".
func (r *ASPathRE) String() string {
	if r == nil {
		return ""
	}
	return reString(r.Body, rePrecAlt)
}

func reString(e ASPathExpr, want int) string {
	switch x := e.(type) {
	case ASPathAlt:
		parts := make([]string, len(x.Alts))
		for i, a := range x.Alts {
			parts[i] = reString(a, rePrecSeq)
		}
		return reParen(strings.Join(parts, " | "), rePrecAlt, want)
	case ASPathSeq:
		if len(x.Terms) == 0 {
			// Empty sequence from "()" — render to round-trip
			return "()"
		}
		parts := make([]string, len(x.Terms))
		for i, t := range x.Terms {
			parts[i] = reString(t, rePrecAtom)
		}
		return reParen(strings.Join(parts, " "), rePrecSeq, want)
	case ASPathRepeat:
		return reString(x.Inner, rePrecAtom) + repeatString(x)
	case ASPathAny:
		return "."
	case ASPathASN:
		return x.AS.String()
	case ASPathSet:
		return x.Name.String()
	case ASPathSetTemplate:
		return x.Template.String()
	case ASPathPeerAS:
		return "PeerAS"
	case ASPathStart:
		return "^"
	case ASPathEnd:
		return "$"
	case ASPathClass:
		parts := make([]string, len(x.Items))
		for i, it := range x.Items {
			parts[i] = reString(it, rePrecAtom)
		}
		neg := ""
		if x.Negated {
			neg = "^"
		}
		return "[" + neg + strings.Join(parts, " ") + "]"
	case ASPathASNRange:
		return x.Lo.String() + " - " + x.Hi.String()
	}
	return ""
}

func reParen(s string, prec, want int) string {
	if prec < want {
		return "(" + s + ")"
	}
	return s
}

func repeatString(x ASPathRepeat) string {
	var s string
	switch x.Op {
	case RepeatStar:
		s = "*"
	case RepeatPlus:
		s = "+"
	case RepeatQuest:
		s = "?"
	default:
		switch {
		case x.Max == x.Min:
			s = "{" + strconv.Itoa(x.Min) + "}"
		case x.Max < 0:
			s = "{" + strconv.Itoa(x.Min) + ",}"
		default:
			s = "{" + strconv.Itoa(x.Min) + "," + strconv.Itoa(x.Max) + "}"
		}
	}
	if x.Same {
		return "~" + s
	}
	return s
}

// Bind returns the regexp with PeerAS replaced by peer and each set template
// (AS1:AS-X:PeerAS) replaced by the set it names for peer. The receiver is not
// modified. A zero peer, or a nil regexp, returns the receiver.
func (r *ASPathRE) Bind(peer types.ASN) *ASPathRE {
	if r == nil || peer == 0 {
		return r
	}
	return &ASPathRE{Body: bindRE(r.Body, peer)}
}

func bindRE(e ASPathExpr, peer types.ASN) ASPathExpr {
	switch x := e.(type) {
	case ASPathAlt:
		out := make([]ASPathExpr, len(x.Alts))
		for i, a := range x.Alts {
			out[i] = bindRE(a, peer)
		}
		return ASPathAlt{Alts: out}
	case ASPathSeq:
		out := make([]ASPathExpr, len(x.Terms))
		for i, t := range x.Terms {
			out[i] = bindRE(t, peer)
		}
		return ASPathSeq{Terms: out}
	case ASPathRepeat:
		x.Inner = bindRE(x.Inner, peer)
		return x
	case ASPathClass:
		out := make([]ASPathExpr, len(x.Items))
		for i, it := range x.Items {
			out[i] = bindRE(it, peer)
		}
		return ASPathClass{Negated: x.Negated, Items: out}
	case ASPathPeerAS:
		return ASPathASN{AS: peer}
	case ASPathSetTemplate:
		return ASPathSet{Name: x.Template.Instantiate(peer)}
	}
	return e
}

// UsesPeer reports whether the regexp names PeerAS or a set template, so that
// it means something only for a given peer.
func (r *ASPathRE) UsesPeer() bool {
	if r == nil {
		return false
	}
	uses := false
	walkRE(r.Body, func(e ASPathExpr) {
		switch e.(type) {
		case ASPathPeerAS, ASPathSetTemplate:
			uses = true
		}
	})
	return uses
}

// SetNames returns the as-sets the regexp names, each once, sorted by their
// text. A template's set is not among them until the regexp is bound.
func (r *ASPathRE) SetNames() []types.SetName {
	if r == nil {
		return nil
	}
	seen := map[types.SetName]bool{}
	var out []types.SetName
	walkRE(r.Body, func(e ASPathExpr) {
		if s, ok := e.(ASPathSet); ok && !seen[s.Name] {
			seen[s.Name] = true
			out = append(out, s.Name)
		}
	})
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// walkRE calls fn for e and every node beneath it.
func walkRE(e ASPathExpr, fn func(ASPathExpr)) {
	fn(e)
	switch x := e.(type) {
	case ASPathAlt:
		for _, a := range x.Alts {
			walkRE(a, fn)
		}
	case ASPathSeq:
		for _, t := range x.Terms {
			walkRE(t, fn)
		}
	case ASPathRepeat:
		walkRE(x.Inner, fn)
	case ASPathClass:
		for _, it := range x.Items {
			walkRE(it, fn)
		}
	}
}
