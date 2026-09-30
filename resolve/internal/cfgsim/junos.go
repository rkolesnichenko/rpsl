package cfgsim

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"unicode"

	"github.com/rkolesnichenko/rpsl/types"
)

// jnode is one Junos configuration statement: its words, and its block when
// it has one ("a b { … }") rather than ending in ";".
type jnode struct {
	words []string
	block []*jnode
	isBlk bool
}

// jtokens splits Junos configuration text into words, quoted strings (without
// their quotes) and the punctuation { } ; [ ].
func jtokens(text string) ([]string, error) {
	var toks []string
	for i := 0; i < len(text); {
		c := text[i]
		switch {
		case unicode.IsSpace(rune(c)):
			i++
		case c == '#':
			for i < len(text) && text[i] != '\n' {
				i++
			}
		case strings.IndexByte("{};[]", c) >= 0:
			toks = append(toks, string(c))
			i++
		case c == '"':
			j := strings.IndexByte(text[i+1:], '"')
			if j < 0 {
				return nil, fmt.Errorf("cfgsim: junos: unclosed quote")
			}
			toks = append(toks, "\x00"+text[i+1:i+1+j]) // marked as quoted
			i += j + 2
		default:
			j := i
			for j < len(text) && !unicode.IsSpace(rune(text[j])) && strings.IndexByte("{};[]\"", text[j]) < 0 {
				j++
			}
			toks = append(toks, text[i:j])
			i = j
		}
	}
	return toks, nil
}

func jparse(toks []string, pos int, depth int) ([]*jnode, int, error) {
	if depth > 64 {
		return nil, pos, fmt.Errorf("cfgsim: junos: nested too deep")
	}
	var out []*jnode
	var words []string
	for pos < len(toks) {
		t := toks[pos]
		switch t {
		case ";":
			if len(words) > 0 {
				out = append(out, &jnode{words: words})
			}
			words = nil
			pos++
		case "{":
			kids, next, err := jparse(toks, pos+1, depth+1)
			if err != nil {
				return nil, pos, err
			}
			if next >= len(toks) || toks[next] != "}" {
				return nil, pos, fmt.Errorf("cfgsim: junos: unclosed {")
			}
			out = append(out, &jnode{words: words, block: kids, isBlk: true})
			words = nil
			pos = next + 1
		case "}":
			if len(words) > 0 {
				return nil, pos, fmt.Errorf("cfgsim: junos: %q not terminated", strings.Join(words, " "))
			}
			return out, pos, nil
		default:
			words = append(words, t)
			pos++
		}
	}
	if len(words) > 0 {
		return nil, pos, fmt.Errorf("cfgsim: junos: %q not terminated", strings.Join(words, " "))
	}
	return out, pos, nil
}

func unquote(w string) string { return strings.TrimPrefix(w, "\x00") }

// listWords returns the words of a statement after its first n, with the
// brackets of a [ … ] list dropped.
func listWords(words []string, n int) []string {
	var out []string
	for _, w := range words[n:] {
		if w != "[" && w != "]" {
			out = append(out, unquote(w))
		}
	}
	return out
}

type jroute struct {
	p      netip.Prefix
	typ    string
	lo, hi int    // the lengths the match type admits
	action string // "", "accept" or "reject"
}

type jterm struct {
	name string
	from []*jnode
	then []*jnode
}

// validFromWords and validThenWords are the "from" conditions and "then"
// actions cfgsim's Junos reader understands; anything else inside
// policy-options or a term is an error, diagnosed at parse time rather than
// deferred to evaluation.
var validFromWords = map[string]bool{"route-filter": true, "policy": true, "as-path": true, "community": true}
var validThenWords = map[string]bool{
	"accept": true, "reject": true, "local-preference": true, "metric": true,
	"community": true, "as-path-prepend": true, "next-hop": true,
}

type junosConfig struct {
	policies map[string][]*jterm
	order    []string
	paths    map[string]string
	comms    map[string][]string
	attached map[attachKey]string
}

// ParseJunos reads a Junos configuration: policy-options (policy-statements,
// as-paths, communities) and protocols bgp neighbours' import and export
// policies.
func ParseJunos(text string) (Config, error) {
	toks, err := jtokens(text)
	if err != nil {
		return nil, err
	}
	top, pos, err := jparse(toks, 0, 0)
	if err != nil {
		return nil, err
	}
	if pos != len(toks) {
		return nil, fmt.Errorf("cfgsim: junos: unbalanced }")
	}
	c := &junosConfig{policies: map[string][]*jterm{}, paths: map[string]string{}, comms: map[string][]string{},
		attached: map[attachKey]string{}}
	for _, n := range top {
		if len(n.words) == 0 {
			continue
		}
		switch n.words[0] {
		case "policy-options":
			if err := c.policyOptions(n.block); err != nil {
				return nil, err
			}
		case "protocols":
			c.protocols(n.block, "", "")
		default:
			return nil, fmt.Errorf("cfgsim: junos: unknown top-level %q", n.words[0])
		}
	}
	return c, nil
}

func (c *junosConfig) policyOptions(nodes []*jnode) error {
	for _, n := range nodes {
		w := n.words
		switch {
		case len(w) == 2 && w[0] == "policy-statement" && n.isBlk:
			if _, ok := c.policies[w[1]]; !ok {
				c.order = append(c.order, w[1])
			}
			for _, t := range n.block {
				if len(t.words) != 2 || t.words[0] != "term" || !t.isBlk {
					return fmt.Errorf("cfgsim: junos: policy %s: %q", w[1], strings.Join(t.words, " "))
				}
				term := &jterm{name: t.words[1]}
				for _, part := range t.block {
					var target *[]*jnode
					var valid map[string]bool
					switch part.words[0] {
					case "from":
						target, valid = &term.from, validFromWords
					case "then":
						target, valid = &term.then, validThenWords
					default:
						return fmt.Errorf("cfgsim: junos: term %s: %q", term.name, part.words[0])
					}
					var nodes []*jnode
					if part.isBlk {
						nodes = part.block
					} else {
						nodes = []*jnode{{words: part.words[1:]}}
					}
					for _, node := range nodes {
						if len(node.words) == 0 || !valid[node.words[0]] {
							return fmt.Errorf("cfgsim: junos: term %s: %q", term.name, strings.Join(node.words, " "))
						}
					}
					*target = append(*target, nodes...)
				}
				c.policies[w[1]] = append(c.policies[w[1]], term)
			}
		case len(w) == 3 && w[0] == "as-path":
			c.paths[w[1]] = unquote(w[2])
		case len(w) >= 4 && w[0] == "community" && w[2] == "members":
			cs, err := canonList(listWords(w, 3))
			if err != nil {
				return err
			}
			c.comms[w[1]] = cs
		default:
			return fmt.Errorf("cfgsim: junos: policy-options %q", strings.Join(w, " "))
		}
	}
	return nil
}

// protocols records bgp neighbours' import and export policies, a group's
// applying to its neighbours that name none.
func (c *junosConfig) protocols(nodes []*jnode, imp, exp string) {
	for _, n := range nodes {
		w := n.words
		switch {
		case len(w) == 2 && w[0] == "import":
			imp = w[1]
		case len(w) == 2 && w[0] == "export":
			exp = w[1]
		}
	}
	for _, n := range nodes {
		if !n.isBlk || len(n.words) == 0 {
			continue
		}
		if n.words[0] == "neighbor" && len(n.words) == 2 {
			addr, err := netip.ParseAddr(n.words[1])
			if err != nil {
				continue
			}
			ni, ne := imp, exp
			for _, k := range n.block {
				switch {
				case len(k.words) == 2 && k.words[0] == "import":
					ni = k.words[1]
				case len(k.words) == 2 && k.words[0] == "export":
					ne = k.words[1]
				}
			}
			if ni != "" {
				c.attached[attachKey{addr, false}] = ni
			}
			if ne != "" {
				c.attached[attachKey{addr, true}] = ne
			}
			continue
		}
		c.protocols(n.block, imp, exp)
	}
}

func (c *junosConfig) Policies() []string { return append([]string(nil), c.order...) }

func (c *junosConfig) Attached(n netip.Addr, export bool) (string, bool) {
	name, ok := c.attached[attachKey{n, export}]
	return name, ok
}

const (
	jFall = iota
	jAccept
	jReject
)

func (c *junosConfig) Policy(name string, r Route) (bool, Attrs, error) {
	if _, ok := c.policies[name]; !ok {
		return false, Attrs{}, fmt.Errorf("cfgsim: no policy-statement %q", name)
	}
	s := newState(r)
	res, err := c.run(name, s, 0)
	if err != nil || res == jReject {
		return false, Attrs{}, err
	}
	return true, s.finish(), nil // accepted, or fell off the end: BGP's default accepts
}

func (c *junosConfig) run(name string, s *state, depth int) (int, error) {
	if depth > 32 {
		return 0, fmt.Errorf("cfgsim: junos: policy %s nested too deep", name)
	}
	terms, ok := c.policies[name]
	if !ok {
		return 0, fmt.Errorf("cfgsim: no policy-statement %q", name)
	}
	for _, t := range terms {
		ok, action, err := c.from(t, s, depth)
		if err != nil {
			return 0, err
		}
		if !ok {
			continue
		}
		switch action {
		case "accept":
			return jAccept, nil
		case "reject":
			return jReject, nil
		}
		for _, n := range t.then {
			res, err := c.then(n.words, s)
			if err != nil {
				return 0, fmt.Errorf("cfgsim: junos: term %s: %w", t.name, err)
			}
			if res != jFall {
				return res, nil
			}
		}
	}
	return jFall, nil
}

// from evaluates a term's conditions. action is a chosen route-filter's own
// action, when it has one.
func (c *junosConfig) from(t *jterm, s *state, depth int) (bool, string, error) {
	var rfs []jroute
	var chain []string // every "policy" condition's words: Junos merges them into one
	for _, n := range t.from {
		w := n.words
		switch w[0] {
		case "route-filter":
			rf, err := parseRouteFilter(w)
			if err != nil {
				return false, "", err
			}
			rfs = append(rfs, rf)
		case "policy":
			chain = append(chain, w[1:]...)
		case "as-path":
			hit := false
			for _, name := range listWords(w, 1) {
				re, ok := c.paths[name]
				if !ok {
					return false, "", fmt.Errorf("cfgsim: junos: no as-path %q", name)
				}
				m, err := MatchJunos(re, s.r.Path)
				if err != nil {
					return false, "", err
				}
				hit = hit || m
			}
			if !hit {
				return false, "", nil
			}
		case "community":
			hit := false
			for _, name := range listWords(w, 1) {
				cs, ok := c.comms[name]
				if !ok {
					return false, "", fmt.Errorf("cfgsim: junos: no community %q", name)
				}
				hit = hit || s.has(cs)
			}
			if !hit {
				return false, "", nil
			}
		default:
			return false, "", fmt.Errorf("cfgsim: junos: term %s: condition %q", t.name, w[0])
		}
	}
	if len(chain) > 0 {
		ok, err := c.policyCond(chain, s, depth)
		if err != nil || !ok {
			return false, "", err
		}
	}
	if len(rfs) == 0 {
		return true, "", nil
	}
	return routeFilters(rfs, s.r.Prefix)
}

// policyCond evaluates a "from policy" condition as Junos does.
//   - A list of names (repeated "policy" lines merge into one) is a policy
//     chain: the first subroutine that accepts or rejects decides, and a chain
//     none decides takes BGP's default, accept.
//   - An expression, "(a && b)", "(a || !b)", combines the subroutines'
//     results; a subroutine that decides nothing counts as accept.
//
// rtconfig writes the first form by default and the second with
// -junos_and_not_or (D12).
func (c *junosConfig) policyCond(words []string, s *state, depth int) (bool, error) {
	text := strings.Join(listWords(words, 0), " ")
	if !strings.ContainsAny(text, "(&|!") {
		for _, name := range strings.Fields(text) {
			res, err := c.run(name, s, depth+1)
			if err != nil {
				return false, err
			}
			if res != jFall {
				return res == jAccept, nil
			}
		}
		return true, nil
	}
	for _, op := range []string{"(", ")", "&&", "||", "!"} {
		text = strings.ReplaceAll(text, op, " "+op+" ")
	}
	toks, i := strings.Fields(text), 0
	var or func() (bool, error)
	var unary func() (bool, error)
	binary := func(op string, next func() (bool, error)) (bool, error) {
		v, err := next()
		for err == nil && i < len(toks) && toks[i] == op {
			i++
			var r bool
			if r, err = next(); err == nil {
				if op == "&&" {
					v = v && r
				} else {
					v = v || r
				}
			}
		}
		return v, err
	}
	and := func() (bool, error) { return binary("&&", unary) }
	or = func() (bool, error) { return binary("||", and) }
	unary = func() (bool, error) {
		if i == len(toks) {
			return false, fmt.Errorf("cfgsim: junos: policy expression %q ends early", text)
		}
		switch t := toks[i]; t {
		case "!":
			i++
			v, err := unary()
			return !v, err
		case "(":
			i++
			v, err := or()
			if err == nil && (i == len(toks) || toks[i] != ")") {
				err = fmt.Errorf("cfgsim: junos: policy expression %q: unclosed (", text)
			}
			i++
			return v, err
		case ")", "&&", "||":
			return false, fmt.Errorf("cfgsim: junos: policy expression %q: unexpected %q", text, t)
		default:
			i++
			res, err := c.run(t, s, depth+1)
			return res != jReject, err
		}
	}
	v, err := or()
	if err == nil && i != len(toks) {
		err = fmt.Errorf("cfgsim: junos: policy expression %q: unexpected %q", text, toks[i])
	}
	return v, err
}

func parseRouteFilter(w []string) (jroute, error) {
	if len(w) < 3 {
		return jroute{}, fmt.Errorf("cfgsim: junos: route-filter %q", strings.Join(w, " "))
	}
	p, err := netip.ParsePrefix(w[1])
	if err != nil {
		return jroute{}, err
	}
	rf := jroute{p: p, typ: w[2]}
	max, rest := p.Addr().BitLen(), w[3:]
	switch w[2] {
	case "exact":
		rf.lo, rf.hi = p.Bits(), p.Bits()
	case "orlonger":
		rf.lo, rf.hi = p.Bits(), max
	case "longer":
		rf.lo, rf.hi = p.Bits()+1, max
	case "upto":
		if len(rest) == 0 {
			return jroute{}, fmt.Errorf("cfgsim: junos: upto needs a length")
		}
		n, err := strconv.Atoi(strings.TrimPrefix(rest[0], "/"))
		if err != nil {
			return jroute{}, err
		}
		rf.lo, rf.hi, rest = p.Bits(), n, rest[1:]
	case "prefix-length-range":
		if len(rest) == 0 {
			return jroute{}, fmt.Errorf("cfgsim: junos: prefix-length-range needs lengths")
		}
		a, b, ok := strings.Cut(rest[0], "-")
		lo, err1 := strconv.Atoi(strings.TrimPrefix(a, "/"))
		hi, err2 := strconv.Atoi(strings.TrimPrefix(b, "/"))
		if !ok || err1 != nil || err2 != nil {
			return jroute{}, fmt.Errorf("cfgsim: junos: prefix-length-range %q", rest[0])
		}
		rf.lo, rf.hi, rest = lo, hi, rest[1:]
	default:
		return jroute{}, fmt.Errorf("cfgsim: junos: route-filter match type %q", w[2])
	}
	if len(rest) > 0 {
		rf.action = rest[0]
	}
	return rf, nil
}

// routeFilters applies Junos's longest match: of the route-filters whose
// prefix contains the route's, those with the longest prefix decide; the
// route matches when its length fits one of them.
func routeFilters(rfs []jroute, p netip.Prefix) (bool, string, error) {
	best := -1
	for _, rf := range rfs {
		if rf.p.Addr().Is4() == p.Addr().Is4() && rf.p.Bits() <= p.Bits() && rf.p.Contains(p.Addr()) && rf.p.Bits() > best {
			best = rf.p.Bits()
		}
	}
	if best < 0 {
		return false, "", nil
	}
	for _, rf := range rfs {
		if rf.p.Bits() == best && rf.p.Contains(p.Addr()) && p.Bits() >= rf.lo && p.Bits() <= rf.hi {
			return true, rf.action, nil
		}
	}
	return false, "", nil
}

// then applies one action; it returns jAccept or jReject for a terminal one.
func (c *junosConfig) then(w []string, s *state) (int, error) {
	switch {
	case len(w) == 1 && w[0] == "accept":
		return jAccept, nil
	case len(w) == 1 && w[0] == "reject":
		return jReject, nil
	case len(w) == 2 && w[0] == "local-preference":
		v, err := strconv.Atoi(w[1])
		s.attrs.LocalPref = v
		return jFall, err
	case len(w) == 2 && w[0] == "metric" && w[1] == "igp":
		s.attrs.MED, s.attrs.MEDIGP = -1, true
	case len(w) == 2 && w[0] == "metric":
		v, err := strconv.Atoi(w[1])
		s.attrs.MED, s.attrs.MEDIGP = v, false
		return jFall, err
	case len(w) == 3 && w[0] == "community":
		cs, ok := c.comms[w[2]]
		if !ok {
			return 0, fmt.Errorf("no community %q", w[2])
		}
		switch w[1] {
		case "set":
			s.comms = map[string]bool{}
			fallthrough
		case "add":
			for _, x := range cs {
				s.comms[x] = true
			}
		case "delete":
			for _, x := range cs {
				delete(s.comms, x)
			}
		default:
			return 0, fmt.Errorf("community %q", w[1])
		}
	case len(w) == 2 && w[0] == "as-path-prepend":
		var as []types.ASN
		for _, x := range strings.Fields(unquote(w[1])) {
			a, err := parsePlainASN(x)
			if err != nil {
				return 0, err
			}
			as = append(as, a)
		}
		s.prepend(as)
	case len(w) == 2 && w[0] == "next-hop":
		s.attrs.NextHop = w[1]
	default:
		return 0, fmt.Errorf("action %q", strings.Join(w, " "))
	}
	return jFall, nil
}
