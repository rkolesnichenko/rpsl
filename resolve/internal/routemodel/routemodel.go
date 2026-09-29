// Package routemodel decides whether a normalized filter accepts a concrete
// route. It exists for tests: it is the one place in the module that matches
// AS-path regexps against AS paths, and the paths it sees are synthetic. The
// library itself never evaluates a regexp against a path (design §13).
package routemodel

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"sync"

	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

// Route is a route as a filter sees it: its prefix, its AS path (the
// neighbour first) and its communities, written as a filter writes them.
type Route struct {
	Prefix      netip.Prefix
	Path        []types.ASN
	Communities []string
}

// ErrTooComplex reports a repetition count Go's regexp package cannot
// compile (over 1000).
var ErrTooComplex = errors.New("routemodel: repetition count too large to model")

// ErrNotSingleAS reports a same-AS repetition ("~*", "~+", "~{m,n}") whose
// inner expression is not itself a single-AS atom — for example one quantifier
// chained directly onto another, as in "AS1*~{2}". RFC 2622 §5.4's "same AS"
// constraint only has a defined meaning when every repetition fills in one AS
// number, so this package declines to evaluate it rather than guess.
var ErrNotSingleAS = errors.New("routemodel: not a single-AS atom under a same-AS repetition")

// Match reports whether any conjunct of f accepts r.
func Match(f resolve.NormalFilter, r Route) (bool, error) {
	for _, c := range f.Conjuncts {
		ok, err := MatchConjunct(c, r)
		if err != nil || ok {
			return ok, err
		}
	}
	return false, nil
}

// MatchConjunct reports whether every part of c accepts r.
func MatchConjunct(c resolve.Conjunct, r Route) (bool, error) {
	if !inRanges(c.Prefixes, r.Prefix) || inRanges(c.NotPrefixes, r.Prefix) {
		return false, nil
	}
	for _, p := range c.Paths {
		ok, err := MatchPath(p, r.Path)
		if err != nil {
			return false, err
		}
		if ok == p.Negated {
			return false, nil
		}
	}
	for _, m := range c.Communities {
		if MatchCommunity(m.Test, r.Communities) == m.Negated {
			return false, nil
		}
	}
	return true, nil
}

func inRanges(rs resolve.RangeSet, p netip.Prefix) bool {
	for _, x := range rs.List() {
		if x.Contains(p) {
			return true
		}
	}
	return false
}

// MatchCommunity reports whether a route carrying have passes the test:
// every listed community present (community(…)), or exactly those present
// (community == {…}). Communities compare as text, without regard to case.
func MatchCommunity(t policy.FilterCommunity, have []string) bool {
	set := map[string]bool{}
	for _, c := range have {
		set[canon(c)] = true
	}
	want := map[string]bool{}
	for _, v := range t.Values {
		want[canon(v)] = true
	}
	for v := range want {
		if !set[v] {
			return false
		}
	}
	return t.Op != policy.CommunityEquals || len(set) == len(want)
}

func canon(s string) string { return strings.ToLower(strings.Join(strings.Fields(s), " ")) }

// MatchPath reports whether path matches m's regexp by RFC 2622 §5.4: the
// regexp may match any contiguous part of the path unless an anchor pins it.
// Each AS becomes the token "<n>", and the regexp a Go regexp over tokens; '.'
// and negated classes range over the ASes of this path, which is all a path
// can hold.
func MatchPath(m resolve.PathMatch, path []types.ASN) (bool, error) {
	if m.RE == nil {
		return false, errors.New("routemodel: nil regexp")
	}
	b := builder{sets: m.Sets, universe: distinct(path)}
	expr, err := b.expr(m.RE.Body)
	if err != nil {
		return false, err
	}
	re, err := compile(expr)
	if err != nil {
		return false, err
	}
	return re.MatchString(encode(path)), nil
}

var cache sync.Map // expression → *regexp.Regexp

func compile(expr string) (*regexp.Regexp, error) {
	if re, ok := cache.Load(expr); ok {
		return re.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		if strings.Contains(err.Error(), "repeat") {
			return nil, ErrTooComplex
		}
		return nil, err
	}
	cache.Store(expr, re)
	return re, nil
}

func encode(path []types.ASN) string {
	var b strings.Builder
	for _, a := range path {
		b.WriteString(tok(a))
	}
	return b.String()
}

func tok(a types.ASN) string { return fmt.Sprintf("<%d>", uint32(a)) }

func distinct(path []types.ASN) []types.ASN {
	seen := map[types.ASN]bool{}
	var out []types.ASN
	for _, a := range path {
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}

const never = "(?:<never>)"

type builder struct {
	sets     map[types.SetName]resolve.ASNSet
	universe []types.ASN
}

func (b builder) alt(as []types.ASN) string {
	if len(as) == 0 {
		return never
	}
	parts := make([]string, len(as))
	for i, a := range as {
		parts[i] = tok(a)
	}
	return "(?:" + strings.Join(parts, "|") + ")"
}

// single reports whether the atom e matches the one AS a.
func (b builder) single(e policy.ASPathExpr, a types.ASN) (bool, error) {
	switch x := e.(type) {
	case policy.ASPathAny:
		return true, nil
	case policy.ASPathASN:
		return x.AS == a, nil
	case policy.ASPathASNRange:
		return x.Lo <= a && a <= x.Hi, nil
	case policy.ASPathSet:
		if strings.EqualFold(x.Name.String(), "AS-ANY") {
			return true, nil
		}
		s, ok := b.sets[x.Name]
		if !ok {
			return false, fmt.Errorf("routemodel: %s was not expanded", x.Name)
		}
		return s.Has(a), nil
	case policy.ASPathClass:
		in := false
		for _, it := range x.Items {
			ok, err := b.single(it, a)
			if err != nil {
				return false, err
			}
			in = in || ok
		}
		return in != x.Negated, nil
	case policy.ASPathPeerAS, policy.ASPathSetTemplate:
		return false, errors.New("routemodel: regexp not bound to a peer")
	}
	return false, fmt.Errorf("%w: %T", ErrNotSingleAS, e)
}

// members are the ASes of the path the atom e matches.
func (b builder) members(e policy.ASPathExpr) ([]types.ASN, error) {
	var out []types.ASN
	for _, a := range b.universe {
		ok, err := b.single(e, a)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, a)
		}
	}
	return out, nil
}

func (b builder) expr(e policy.ASPathExpr) (string, error) {
	switch x := e.(type) {
	case policy.ASPathAlt:
		parts := make([]string, len(x.Alts))
		for i, a := range x.Alts {
			s, err := b.expr(a)
			if err != nil {
				return "", err
			}
			parts[i] = s
		}
		return "(?:" + strings.Join(parts, "|") + ")", nil
	case policy.ASPathSeq:
		var sb strings.Builder
		for _, t := range x.Terms {
			s, err := b.expr(t)
			if err != nil {
				return "", err
			}
			sb.WriteString(s)
		}
		return "(?:" + sb.String() + ")", nil
	case policy.ASPathRepeat:
		q, err := quant(x)
		if err != nil {
			return "", err
		}
		if x.Same {
			as, err := b.members(x.Inner)
			if err != nil {
				return "", err
			}
			alts := []string{}
			for _, a := range as {
				alts = append(alts, "(?:"+tok(a)+")"+q)
			}
			if x.Min == 0 {
				alts = append(alts, "")
			}
			if len(alts) == 0 {
				return never, nil
			}
			return "(?:" + strings.Join(alts, "|") + ")", nil
		}
		inner, err := b.expr(x.Inner)
		if err != nil {
			return "", err
		}
		return "(?:" + inner + ")" + q, nil
	case policy.ASPathStart:
		return "^", nil
	case policy.ASPathEnd:
		return "$", nil
	}
	as, err := b.members(e)
	if err != nil {
		return "", err
	}
	return b.alt(as), nil
}

func quant(x policy.ASPathRepeat) (string, error) {
	switch x.Op {
	case policy.RepeatStar:
		return "*", nil
	case policy.RepeatPlus:
		return "+", nil
	case policy.RepeatQuest:
		return "?", nil
	}
	if x.Min > 1000 || x.Max > 1000 {
		return "", ErrTooComplex
	}
	switch {
	case x.Max < 0:
		return fmt.Sprintf("{%d,}", x.Min), nil
	case x.Max == x.Min:
		return fmt.Sprintf("{%d}", x.Min), nil
	}
	return fmt.Sprintf("{%d,%d}", x.Min, x.Max), nil
}
