package cfgsim

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/rkolesnichenko/rpsl/types"
)

// xrConfig is a Cisco IOS-XR configuration: prefix-sets, as-path-sets and
// community-sets, route-policies in RPL, and the route-policies "router bgp"
// neighbours use.
type xrConfig struct {
	prefixSets map[string][]plEntry
	pathSets   map[string][]string // ios-regex expressions
	commSets   map[string][]string // a:b, or "*" for any community
	policies   map[string][]*xrStmt
	order      []string
	attached   map[attachKey]string
}

// xrStmt is one RPL statement: an if, with a condition per arm (if, then each
// elseif) and a body per arm (one more for an else), or a disposition (done,
// drop, pass) or action (set, delete, prepend), in words.
type xrStmt struct {
	conds []*xrCond
	arms  [][]*xrStmt
	words []string
}

// xrCond is an RPL condition: op is "and", "or" or "not" over kids, or "" for
// a test in words (destination in S, as-path in S, community matches-any S,
// community matches-every S).
type xrCond struct {
	op    string
	kids  []*xrCond
	words []string
}

type xrLine struct {
	n        int
	indented bool
	text     string
}

func xrErr(l xrLine, why string) error {
	return fmt.Errorf("cfgsim: xr line %d %q: %s", l.n, l.text, why)
}

// ParseXR reads a Cisco IOS-XR configuration: prefix-sets, as-path-sets,
// community-sets, route-policies, and "router bgp" neighbours' policies.
func ParseXR(text string) (Config, error) {
	c := &xrConfig{prefixSets: map[string][]plEntry{}, pathSets: map[string][]string{},
		commSets: map[string][]string{}, policies: map[string][]*xrStmt{}, attached: map[attachKey]string{}}
	var lines []xrLine
	for n, raw := range strings.Split(text, "\n") {
		t := strings.TrimSpace(raw)
		if t == "" || t == "!" || strings.HasPrefix(t, "Warning:") || strings.HasPrefix(t, "***") {
			continue
		}
		lines = append(lines, xrLine{n: n + 1, indented: raw[0] == ' ' || raw[0] == '\t', text: t})
	}
	inBGP := false
	var nb netip.Addr // the neighbour "router bgp" is configuring
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		f := strings.Fields(l.text)
		top := !l.indented
		switch {
		case top && len(f) == 2 && (f[0] == "prefix-set" || f[0] == "as-path-set" || f[0] == "community-set"):
			inBGP = false
			var body []string
			j := i + 1
			for ; j < len(lines) && lines[j].text != "end-set"; j++ {
				body = append(body, lines[j].text)
			}
			if j == len(lines) {
				return nil, xrErr(l, "no end-set")
			}
			if err := c.set(f[0], f[1], splitElements(strings.Join(body, " "))); err != nil {
				return nil, xrErr(l, err.Error())
			}
			i = j
		case top && len(f) == 2 && f[0] == "route-policy":
			inBGP = false
			j := i + 1
			for j < len(lines) && lines[j].text != "end-policy" {
				j++
			}
			if j == len(lines) {
				return nil, xrErr(l, "no end-policy")
			}
			body := lines[i+1 : j]
			stmts, k, err := parseXRBlock(body, 0)
			if err != nil {
				return nil, err
			}
			if k != len(body) {
				return nil, xrErr(body[k], "unexpected")
			}
			if _, ok := c.policies[f[1]]; !ok {
				c.order = append(c.order, f[1])
			}
			c.policies[f[1]] = stmts
			i = j
		case top && len(f) == 3 && f[0] == "router" && f[1] == "bgp":
			inBGP, nb = true, netip.Addr{}
		case f[0] == "exit":
		case inBGP && len(f) == 2 && f[0] == "neighbor":
			a, err := netip.ParseAddr(f[1])
			if err != nil {
				return nil, xrErr(l, "neighbour address")
			}
			nb = a
		case inBGP && len(f) == 3 && f[0] == "route-policy" && (f[2] == "in" || f[2] == "out"):
			if !nb.IsValid() {
				return nil, xrErr(l, "route-policy outside a neighbour")
			}
			c.attached[attachKey{nb, f[2] == "out"}] = f[1]
		case inBGP && (f[0] == "remote-as" || f[0] == "address-family"):
		default:
			return nil, xrErr(l, "unknown line")
		}
	}
	return c, nil
}

// splitElements splits a set's body at the commas outside single quotes.
func splitElements(body string) []string {
	var out []string
	quoted, start := false, 0
	for i := 0; i <= len(body); i++ {
		if i < len(body) && body[i] == '\'' {
			quoted = !quoted
		}
		if i == len(body) || body[i] == ',' && !quoted {
			if el := strings.TrimSpace(body[start:i]); el != "" {
				out = append(out, el)
			}
			start = i + 1
		}
	}
	return out
}

func (c *xrConfig) set(kind, name string, els []string) error {
	switch kind {
	case "prefix-set":
		var es []plEntry
		for _, el := range els {
			f := strings.Fields(el)
			p, err := netip.ParsePrefix(f[0])
			if err != nil || len(f)%2 == 0 {
				return fmt.Errorf("prefix-set element %q", el)
			}
			e := plEntry{permit: true, p: p}
			for i := 1; i < len(f); i += 2 {
				v, err := strconv.Atoi(f[i+1])
				if err != nil {
					return fmt.Errorf("prefix-set element %q", el)
				}
				switch f[i] {
				case "ge":
					e.ge = v
				case "le":
					e.le = v
				case "eq":
					e.ge, e.le = v, v
				default:
					return fmt.Errorf("prefix-set element %q", el)
				}
			}
			es = append(es, e)
		}
		c.prefixSets[name] = es
	case "as-path-set":
		var res []string
		for _, el := range els {
			re, ok := strings.CutPrefix(el, "ios-regex")
			re = strings.TrimSpace(re)
			if !ok || len(re) < 2 || re[0] != '\'' || re[len(re)-1] != '\'' {
				return fmt.Errorf("as-path-set element %q", el)
			}
			res = append(res, re[1:len(re)-1])
		}
		c.pathSets[name] = res
	default:
		var cs []string
		for _, el := range els {
			if el == "*" {
				cs = append(cs, el)
				continue
			}
			k, ok := CanonCommunity(el)
			if !ok {
				return fmt.Errorf("community-set element %q", el)
			}
			cs = append(cs, k)
		}
		c.commSets[name] = cs
	}
	return nil
}

// parseXRBlock reads statements from ls[i:] up to an elseif, else or endif,
// or the end, and returns them and where it stopped.
func parseXRBlock(ls []xrLine, i int) ([]*xrStmt, int, error) {
	var out []*xrStmt
	for i < len(ls) {
		f := strings.Fields(ls[i].text)
		switch f[0] {
		case "elseif", "else", "endif":
			return out, i, nil
		case "if":
			st := &xrStmt{}
			for {
				f = strings.Fields(ls[i].text)
				if len(f) < 3 || f[len(f)-1] != "then" {
					return nil, i, xrErr(ls[i], "condition without then")
				}
				cond, err := parseXRCond(f[1 : len(f)-1])
				if err != nil {
					return nil, i, xrErr(ls[i], err.Error())
				}
				body, j, err := parseXRBlock(ls, i+1)
				if err != nil {
					return nil, j, err
				}
				if j == len(ls) {
					return nil, j, xrErr(ls[i], "no endif")
				}
				st.conds, st.arms = append(st.conds, cond), append(st.arms, body)
				i = j
				if strings.Fields(ls[i].text)[0] != "elseif" {
					break
				}
			}
			if ls[i].text == "else" {
				body, j, err := parseXRBlock(ls, i+1)
				if err != nil {
					return nil, j, err
				}
				if j == len(ls) {
					return nil, j, xrErr(ls[i], "no endif")
				}
				st.arms = append(st.arms, body)
				i = j
			}
			if ls[i].text != "endif" {
				return nil, i, xrErr(ls[i], "expected endif")
			}
			out = append(out, st)
			i++
		case "done", "drop", "pass", "set", "delete", "prepend":
			out = append(out, &xrStmt{words: f})
			i++
		default:
			return nil, i, xrErr(ls[i], "unknown statement")
		}
	}
	return out, i, nil
}

// parseXRCond reads a condition; parentheses may touch the words they
// enclose.
func parseXRCond(words []string) (*xrCond, error) {
	var toks []string
	for _, w := range words {
		for strings.HasPrefix(w, "(") {
			toks, w = append(toks, "("), w[1:]
		}
		closes := 0
		for strings.HasSuffix(w, ")") {
			closes, w = closes+1, w[:len(w)-1]
		}
		if w != "" {
			toks = append(toks, w)
		}
		for ; closes > 0; closes-- {
			toks = append(toks, ")")
		}
	}
	p := &xrCondParser{toks: toks}
	c, err := p.binary("or")
	if err == nil && p.i != len(p.toks) {
		err = fmt.Errorf("condition: unexpected %q", p.toks[p.i])
	}
	return c, err
}

type xrCondParser struct {
	toks []string
	i    int
}

func (p *xrCondParser) peek() string {
	if p.i < len(p.toks) {
		return p.toks[p.i]
	}
	return ""
}

// binary reads op-separated operands: "or" over "and" over the rest.
func (p *xrCondParser) binary(op string) (*xrCond, error) {
	next := p.unary
	if op == "or" {
		next = func() (*xrCond, error) { return p.binary("and") }
	}
	c, err := next()
	for err == nil && p.peek() == op {
		p.i++
		var r *xrCond
		if r, err = next(); err == nil {
			c = &xrCond{op: op, kids: []*xrCond{c, r}}
		}
	}
	return c, err
}

func (p *xrCondParser) unary() (*xrCond, error) {
	switch p.peek() {
	case "not":
		p.i++
		c, err := p.unary()
		if err != nil {
			return nil, err
		}
		return &xrCond{op: "not", kids: []*xrCond{c}}, nil
	case "(":
		p.i++
		c, err := p.binary("or")
		if err != nil {
			return nil, err
		}
		if p.peek() != ")" {
			return nil, fmt.Errorf("condition: unclosed (")
		}
		p.i++
		return c, nil
	}
	if p.i+3 > len(p.toks) {
		return nil, fmt.Errorf("condition: short test")
	}
	w := p.toks[p.i : p.i+3]
	switch {
	case w[0] == "destination" && w[1] == "in", w[0] == "as-path" && w[1] == "in",
		w[0] == "community" && (w[1] == "matches-any" || w[1] == "matches-every"):
	default:
		return nil, fmt.Errorf("condition: test %q", strings.Join(w, " "))
	}
	p.i += 3
	return &xrCond{words: w}, nil
}

func (c *xrConfig) Policies() []string { return append([]string(nil), c.order...) }

func (c *xrConfig) Attached(n netip.Addr, export bool) (string, bool) {
	name, ok := c.attached[attachKey{n, export}]
	return name, ok
}

const (
	xrFall = iota
	xrDone
	xrDrop
)

func (c *xrConfig) Policy(name string, r Route) (bool, Attrs, error) {
	stmts, ok := c.policies[name]
	if !ok {
		return false, Attrs{}, fmt.Errorf("cfgsim: xr: no route-policy %q", name)
	}
	s := newState(r)
	passed := false
	d, err := c.exec(stmts, s, &passed)
	if err != nil {
		return false, Attrs{}, err
	}
	if d == xrDone || d == xrFall && passed {
		return true, s.finish(), nil
	}
	return false, Attrs{}, nil
}

func (c *xrConfig) exec(stmts []*xrStmt, s *state, passed *bool) (int, error) {
	for _, st := range stmts {
		if st.words == nil { // an if
			for k, arm := range st.arms {
				take := k >= len(st.conds) // the else arm
				if !take {
					ok, err := c.test(st.conds[k], s)
					if err != nil {
						return 0, err
					}
					take = ok
				}
				if take {
					if d, err := c.exec(arm, s, passed); err != nil || d != xrFall {
						return d, err
					}
					break
				}
			}
			continue
		}
		switch st.words[0] {
		case "done":
			return xrDone, nil
		case "drop":
			return xrDrop, nil
		case "pass":
			*passed = true
		default:
			if err := c.act(st.words, s); err != nil {
				return 0, err
			}
			*passed = true // a modified route is passed
		}
	}
	return xrFall, nil
}

func (c *xrConfig) test(cd *xrCond, s *state) (bool, error) {
	switch cd.op {
	case "and", "or":
		l, err := c.test(cd.kids[0], s)
		if err != nil || l == (cd.op == "or") {
			return l, err
		}
		return c.test(cd.kids[1], s)
	case "not":
		v, err := c.test(cd.kids[0], s)
		return !v, err
	}
	name := cd.words[2]
	switch cd.words[0] {
	case "destination":
		set, ok := c.prefixSets[name]
		if !ok {
			return false, fmt.Errorf("cfgsim: xr: no prefix-set %q", name)
		}
		for _, e := range set {
			if e.covers(s.r.Prefix) {
				return true, nil
			}
		}
		return false, nil
	case "as-path":
		set, ok := c.pathSets[name]
		if !ok {
			return false, fmt.Errorf("cfgsim: xr: no as-path-set %q", name)
		}
		for _, re := range set {
			if ok, err := MatchIOS(re, s.r.Path); err != nil || ok {
				return ok, err
			}
		}
		return false, nil
	}
	set, ok := c.commSets[name]
	if !ok {
		return false, fmt.Errorf("cfgsim: xr: no community-set %q", name)
	}
	matches := func(el string) bool {
		if el == "*" {
			return len(s.comms) > 0
		}
		return s.comms[el]
	}
	every := cd.words[1] == "matches-every"
	for _, el := range set {
		if matches(el) != every {
			return !every, nil
		}
	}
	return every, nil
}

// xrList reads "(a:b, c:d)".
func xrList(s string) ([]string, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "(") || !strings.HasSuffix(s, ")") {
		return nil, fmt.Errorf("cfgsim: xr: community list %q", s)
	}
	var vals []string
	for _, v := range strings.Split(s[1:len(s)-1], ",") {
		vals = append(vals, strings.TrimSpace(v))
	}
	return canonList(vals)
}

func (c *xrConfig) act(w []string, s *state) error {
	switch {
	case len(w) == 3 && w[0] == "set" && w[1] == "local-preference":
		v, err := strconv.Atoi(w[2])
		s.attrs.LocalPref = v
		return err
	case len(w) == 3 && w[0] == "set" && w[1] == "med" && w[2] == "igp-cost":
		s.attrs.MED, s.attrs.MEDIGP = -1, true
	case len(w) == 3 && w[0] == "set" && w[1] == "med":
		v, err := strconv.Atoi(w[2])
		s.attrs.MED, s.attrs.MEDIGP = v, false
		return err
	case len(w) >= 3 && w[0] == "set" && w[1] == "community":
		vals, additive := w[2:], false
		if vals[len(vals)-1] == "additive" {
			vals, additive = vals[:len(vals)-1], true
		}
		cs, err := xrList(strings.Join(vals, " "))
		if err != nil {
			return err
		}
		if !additive {
			s.comms = map[string]bool{}
		}
		for _, x := range cs {
			s.comms[x] = true
		}
	case len(w) == 3 && w[0] == "delete" && w[1] == "community" && w[2] == "all":
		s.comms = map[string]bool{}
	case len(w) >= 4 && w[0] == "delete" && w[1] == "community" && w[2] == "in":
		cs, err := xrList(strings.Join(w[3:], " "))
		if err != nil {
			return err
		}
		for _, x := range cs {
			delete(s.comms, x)
		}
	case (len(w) == 3 || len(w) == 4) && w[0] == "prepend" && w[1] == "as-path":
		a, err := strconv.ParseUint(w[2], 10, 32)
		if err != nil {
			return fmt.Errorf("cfgsim: xr: prepend %q", w[2])
		}
		n := 1
		if len(w) == 4 {
			if n, err = strconv.Atoi(w[3]); err != nil || n < 1 || n > 64 {
				return fmt.Errorf("cfgsim: xr: prepend count %q", w[3])
			}
		}
		as := make([]types.ASN, n)
		for i := range as {
			as[i] = types.ASN(a)
		}
		s.prepend(as)
	case len(w) == 3 && w[0] == "set" && w[1] == "next-hop":
		s.attrs.NextHop = w[2]
	default:
		return fmt.Errorf("cfgsim: xr: statement %q", strings.Join(w, " "))
	}
	return nil
}
