package cfgsim

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/rkolesnichenko/rpsl/types"
)

// birdConfig is a BIRD 2 configuration: filters, and the bgp protocols whose
// channels name them.
type birdConfig struct {
	filters  map[string][]*bStmt
	order    []string
	attached map[attachKey]string
}

// bTok is a word, an operator, or a whole literal: a set "[ … ]" or a path
// mask "[= … =]".
type bTok struct {
	s   string
	lit bool
}

// bStmt is an if (cond, then, els) or another statement in words: accept,
// reject, "attr = value", or a method and its argument.
type bStmt struct {
	cond      *bExpr
	then, els []*bStmt
	words     []string
}

// bExpr is an operator over kids ("&&", "||", "=", "~", "!"), a count of the
// route's communities outside a pair set ("outside", with the set in leaf),
// or a leaf.
type bExpr struct {
	op   string
	kids []*bExpr
	leaf bTok
}

func isBIRDWord(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("_.:/-", c) >= 0
}

func birdTokens(text string) ([]bTok, error) {
	var out []bTok
	for i := 0; i < len(text); {
		c := text[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '#':
			for i < len(text) && text[i] != '\n' {
				i++
			}
		case c == '[':
			end, from := "]", i+1
			if strings.HasPrefix(text[i:], "[=") {
				end, from = "=]", i+2
			}
			j := strings.Index(text[from:], end)
			if j < 0 {
				return nil, fmt.Errorf("cfgsim: bird: unclosed %q", text[i:from])
			}
			j += from + len(end)
			out = append(out, bTok{s: text[i:j], lit: true})
			i = j
		case strings.HasPrefix(text[i:], "&&") || strings.HasPrefix(text[i:], "||"):
			out = append(out, bTok{s: text[i : i+2]})
			i += 2
		case strings.IndexByte("{}();,!=~", c) >= 0:
			out = append(out, bTok{s: text[i : i+1]})
			i++
		case isBIRDWord(c):
			j := i
			for j < len(text) && isBIRDWord(text[j]) {
				j++
			}
			out = append(out, bTok{s: text[i:j]})
			i = j
		default:
			return nil, fmt.Errorf("cfgsim: bird: unexpected %q", c)
		}
	}
	return out, nil
}

type bParser struct {
	toks []bTok
	i    int
}

func (p *bParser) peek() string {
	if p.i < len(p.toks) {
		return p.toks[p.i].s
	}
	return ""
}

func (p *bParser) next() bTok {
	var t bTok
	if p.i < len(p.toks) {
		t = p.toks[p.i]
		p.i++
	}
	return t
}

func (p *bParser) expect(s string) error {
	if t := p.next(); t.s != s || t.lit {
		return fmt.Errorf("cfgsim: bird: expected %q, got %q", s, t.s)
	}
	return nil
}

// ParseBIRD reads a BIRD 2 configuration: filters and bgp protocols.
func ParseBIRD(text string) (Config, error) {
	toks, err := birdTokens(text)
	if err != nil {
		return nil, err
	}
	c := &birdConfig{filters: map[string][]*bStmt{}, attached: map[attachKey]string{}}
	p := &bParser{toks: toks}
	protocols := map[string]bool{}
	for p.i < len(p.toks) {
		switch w := p.next().s; w {
		case "router": // router id X;
			if err := p.expect("id"); err != nil {
				return nil, err
			}
			p.next()
			if err := p.expect(";"); err != nil {
				return nil, err
			}
		case "filter":
			name := p.next().s
			if err := p.expect("{"); err != nil {
				return nil, err
			}
			stmts, err := p.stmts()
			if err != nil {
				return nil, fmt.Errorf("cfgsim: bird: filter %s: %w", name, err)
			}
			if _, ok := c.filters[name]; ok {
				return nil, fmt.Errorf("cfgsim: bird: filter %s defined twice", name)
			}
			c.order = append(c.order, name)
			c.filters[name] = stmts
		case "protocol":
			name, err := c.protocol(p)
			if err != nil {
				return nil, err
			}
			if protocols[name] {
				return nil, fmt.Errorf("cfgsim: bird: protocol %s defined twice", name)
			}
			protocols[name] = true
		default:
			return nil, fmt.Errorf("cfgsim: bird: unexpected %q", w)
		}
	}
	return c, nil
}

// stmts reads statements up to and including the "}" that ends them.
func (p *bParser) stmts() ([]*bStmt, error) {
	var out []*bStmt
	for {
		switch p.peek() {
		case "":
			return nil, fmt.Errorf("unclosed {")
		case "}":
			p.i++
			return out, nil
		}
		st, err := p.stmt()
		if err != nil {
			return nil, err
		}
		out = append(out, st)
	}
}

// body reads a block, or a single statement.
func (p *bParser) body() ([]*bStmt, error) {
	if p.peek() == "{" {
		p.i++
		return p.stmts()
	}
	st, err := p.stmt()
	return []*bStmt{st}, err
}

func (p *bParser) stmt() (*bStmt, error) {
	t := p.next()
	if t.s == "" {
		return nil, fmt.Errorf("unexpected end")
	}
	switch {
	case t.s == "if" && !t.lit:
		cond, err := p.expr()
		if err != nil {
			return nil, err
		}
		if err := p.expect("then"); err != nil {
			return nil, err
		}
		st := &bStmt{cond: cond}
		if st.then, err = p.body(); err != nil {
			return nil, err
		}
		if p.peek() == "else" {
			p.i++
			if st.els, err = p.body(); err != nil {
				return nil, err
			}
		}
		return st, nil
	case (t.s == "accept" || t.s == "reject") && !t.lit:
		return &bStmt{words: []string{t.s}}, p.expect(";")
	case !t.lit && isBIRDWord(t.s[0]) && p.peek() == "=":
		p.i++
		v := p.next()
		return &bStmt{words: []string{t.s, "=", v.s}}, p.expect(";")
	case !t.lit && isBIRDWord(t.s[0]) && p.peek() == "(":
		p.i++ // a method call: its argument is the tokens inside the parentheses
		var arg strings.Builder
		for depth := 1; ; {
			a := p.next()
			switch a.s {
			case "":
				return nil, fmt.Errorf("unclosed (")
			case "(":
				depth++
			case ")":
				depth--
			}
			if depth == 0 {
				break
			}
			arg.WriteString(a.s)
		}
		return &bStmt{words: []string{t.s, arg.String()}}, p.expect(";")
	}
	return nil, fmt.Errorf("statement %q", t.s)
}

// expr reads an expression as BIRD 2's grammar does: "&&", "||", "=" and "~"
// share one precedence and associate left, so writers must parenthesize.
func (p *bParser) expr() (*bExpr, error) {
	l, err := p.unary()
	for err == nil {
		op := p.peek()
		if op != "&&" && op != "||" && op != "=" && op != "~" {
			break
		}
		p.i++
		var r *bExpr
		if r, err = p.unary(); err == nil {
			l = &bExpr{op: op, kids: []*bExpr{l, r}}
		}
	}
	return l, err
}

func (p *bParser) unary() (*bExpr, error) {
	switch p.peek() {
	case "!":
		p.i++
		x, err := p.unary()
		if err != nil {
			return nil, err
		}
		return &bExpr{op: "!", kids: []*bExpr{x}}, nil
	case "(":
		if p.i+4 < len(p.toks) && p.toks[p.i+2].s == "," && p.toks[p.i+4].s == ")" { // a pair
			pair := "(" + p.toks[p.i+1].s + "," + p.toks[p.i+3].s + ")"
			p.i += 5
			return &bExpr{leaf: bTok{s: pair, lit: true}}, nil
		}
		p.i++
		x, err := p.expr()
		if err != nil {
			return nil, err
		}
		return x, p.expect(")")
	case "delete": // delete(bgp_community, [ pairs ]).len
		p.i++
		if err := p.expect("("); err != nil {
			return nil, err
		}
		if err := p.expect("bgp_community"); err != nil {
			return nil, err
		}
		if err := p.expect(","); err != nil {
			return nil, err
		}
		set := p.next()
		if !set.lit || strings.HasPrefix(set.s, "[=") {
			return nil, fmt.Errorf("cfgsim: bird: delete from %q", set.s)
		}
		if err := p.expect(")"); err != nil {
			return nil, err
		}
		if err := p.expect(".len"); err != nil {
			return nil, err
		}
		return &bExpr{op: "outside", leaf: set}, nil
	}
	t := p.next()
	if t.s == "" || !t.lit && !isBIRDWord(t.s[0]) {
		return nil, fmt.Errorf("cfgsim: bird: expression at %q", t.s)
	}
	return &bExpr{leaf: t}, nil
}

// protocol reads "protocol bgp [NAME] { … }" and returns its name.
func (c *birdConfig) protocol(p *bParser) (string, error) {
	if err := p.expect("bgp"); err != nil {
		return "", err
	}
	name := ""
	if p.peek() != "{" {
		name = p.next().s
	}
	if err := p.expect("{"); err != nil {
		return "", err
	}
	var nb netip.Addr
	type channel struct{ dir, filter string }
	var chans []channel
	skip := func() { // to the end of the statement
		for p.peek() != ";" && p.peek() != "" {
			p.i++
		}
		p.i++
	}
	for p.peek() != "}" {
		switch w := p.next().s; w {
		case "":
			return "", fmt.Errorf("cfgsim: bird: unclosed protocol")
		case "local":
			skip()
		case "neighbor":
			a, err := netip.ParseAddr(p.next().s)
			if err != nil {
				return "", fmt.Errorf("cfgsim: bird: neighbour address")
			}
			nb = a
			skip()
		case "ipv4", "ipv6":
			if err := p.expect("{"); err != nil {
				return "", err
			}
			for p.peek() != "}" {
				dir := p.next().s
				if dir != "import" && dir != "export" {
					return "", fmt.Errorf("cfgsim: bird: channel %q", dir)
				}
				switch v := p.next().s; v {
				case "filter":
					chans = append(chans, channel{dir, p.next().s})
				case "none", "all":
				default:
					return "", fmt.Errorf("cfgsim: bird: %s %q", dir, v)
				}
				if err := p.expect(";"); err != nil {
					return "", err
				}
			}
			p.i++
			if err := p.expect(";"); err != nil {
				return "", err
			}
		default:
			return "", fmt.Errorf("cfgsim: bird: protocol %q", w)
		}
	}
	p.i++
	if !nb.IsValid() {
		return "", fmt.Errorf("cfgsim: bird: protocol without a neighbor")
	}
	for _, ch := range chans {
		c.attached[attachKey{nb, ch.dir == "export"}] = ch.filter
	}
	return name, nil
}

func (c *birdConfig) Policies() []string { return append([]string(nil), c.order...) }

func (c *birdConfig) Attached(n netip.Addr, export bool) (string, bool) {
	name, ok := c.attached[attachKey{n, export}]
	return name, ok
}

const (
	bFall = iota
	bAccept
	bReject
)

func (c *birdConfig) Policy(name string, r Route) (bool, Attrs, error) {
	stmts, ok := c.filters[name]
	if !ok {
		return false, Attrs{}, fmt.Errorf("cfgsim: bird: no filter %q", name)
	}
	s := newState(r)
	d, err := c.run(stmts, s)
	if err != nil || d != bAccept { // running off the end rejects
		return false, Attrs{}, err
	}
	return true, s.finish(), nil
}

func (c *birdConfig) run(stmts []*bStmt, s *state) (int, error) {
	for _, st := range stmts {
		if st.cond != nil {
			v, err := c.eval(st.cond, s)
			if err != nil {
				return 0, err
			}
			if v.kind != 'b' {
				return 0, fmt.Errorf("cfgsim: bird: if over a %c", v.kind)
			}
			arm := st.els
			if v.b {
				arm = st.then
			}
			if d, err := c.run(arm, s); err != nil || d != bFall {
				return d, err
			}
			continue
		}
		switch st.words[0] {
		case "accept":
			return bAccept, nil
		case "reject":
			return bReject, nil
		}
		if err := c.act(st.words, s); err != nil {
			return 0, err
		}
	}
	return bFall, nil
}

// bVal is a value: kind 'b' a bool, 'i' a number, 'n' the route's prefix,
// 'p' its path, 'c' its communities, 'q' a pair (s, as a:b), 's' a prefix set
// and 'm' a path mask (s, the literal).
type bVal struct {
	kind byte
	b    bool
	i    int
	s    string
}

func (c *birdConfig) eval(x *bExpr, s *state) (bVal, error) {
	switch x.op {
	case "":
		return leafValue(x.leaf, s)
	case "outside":
		pairs, err := birdPairs(x.leaf.s)
		if err != nil {
			return bVal{}, err
		}
		n := 0
		for k := range s.comms {
			if !pairs[k] {
				n++
			}
		}
		return bVal{kind: 'i', i: n}, nil
	case "!":
		v, err := c.eval(x.kids[0], s)
		if err != nil || v.kind != 'b' {
			return bVal{}, fmt.Errorf("cfgsim: bird: ! over a %c: %v", v.kind, err)
		}
		return bVal{kind: 'b', b: !v.b}, nil
	}
	l, err := c.eval(x.kids[0], s)
	if err != nil {
		return l, err
	}
	r, err := c.eval(x.kids[1], s)
	if err != nil {
		return r, err
	}
	switch {
	case x.op == "&&" && l.kind == 'b' && r.kind == 'b':
		return bVal{kind: 'b', b: l.b && r.b}, nil
	case x.op == "||" && l.kind == 'b' && r.kind == 'b':
		return bVal{kind: 'b', b: l.b || r.b}, nil
	case x.op == "=" && l.kind == 'i' && r.kind == 'i':
		return bVal{kind: 'b', b: l.i == r.i}, nil
	case x.op == "~" && l.kind == 'n' && r.kind == 's':
		ok, err := birdSetHas(r.s, s.r.Prefix)
		return bVal{kind: 'b', b: ok}, err
	case x.op == "~" && l.kind == 'p' && r.kind == 'm':
		ok, err := MatchBIRD(r.s, s.r.Path)
		return bVal{kind: 'b', b: ok}, err
	case x.op == "~" && l.kind == 'q' && r.kind == 'c':
		return bVal{kind: 'b', b: s.comms[l.s]}, nil
	}
	return bVal{}, fmt.Errorf("cfgsim: bird: type error: %c %s %c", l.kind, x.op, r.kind)
}

func leafValue(t bTok, s *state) (bVal, error) {
	switch {
	case strings.HasPrefix(t.s, "[="):
		return bVal{kind: 'm', s: t.s}, nil
	case strings.HasPrefix(t.s, "["):
		return bVal{kind: 's', s: t.s}, nil
	case strings.HasPrefix(t.s, "("):
		k, ok := CanonCommunity(t.s)
		if !ok {
			return bVal{}, fmt.Errorf("cfgsim: bird: pair %s", t.s)
		}
		return bVal{kind: 'q', s: k}, nil
	case t.s == "net":
		return bVal{kind: 'n'}, nil
	case t.s == "bgp_path":
		return bVal{kind: 'p'}, nil
	case t.s == "bgp_community":
		return bVal{kind: 'c'}, nil
	case t.s == "bgp_community.len":
		return bVal{kind: 'i', i: len(s.comms)}, nil
	case t.s == "true", t.s == "false":
		return bVal{kind: 'b', b: t.s == "true"}, nil
	}
	n, err := strconv.Atoi(t.s)
	if err != nil {
		return bVal{}, fmt.Errorf("cfgsim: bird: value %q", t.s)
	}
	return bVal{kind: 'i', i: n}, nil
}

// birdSetHas reports whether a prefix set "[ p, p+, p{a,b}, … ]" holds p.
func birdSetHas(set string, p netip.Prefix) (bool, error) {
	body := set[1 : len(set)-1]
	depth, start := 0, 0
	for i := 0; i <= len(body); i++ {
		switch {
		case i == len(body) || body[i] == ',' && depth == 0:
			if el := strings.TrimSpace(body[start:i]); el != "" {
				q, lo, hi, err := birdElement(el)
				if err != nil {
					return false, err
				}
				if q.Addr().Is4() == p.Addr().Is4() && p.Bits() >= q.Bits() && q.Contains(p.Addr()) &&
					p.Bits() >= lo && p.Bits() <= hi {
					return true, nil
				}
			}
			start = i + 1
		case body[i] == '{':
			depth++
		case body[i] == '}':
			depth--
		}
	}
	return false, nil
}

// birdElement reads a prefix-set element: p (p only), p+ (p and every more
// specific) or p{a,b} (lengths a to b).
func birdElement(el string) (netip.Prefix, int, int, error) {
	i := strings.IndexAny(el, "{+")
	s := el
	if i >= 0 {
		s = el[:i]
	}
	p, err := netip.ParsePrefix(strings.TrimSpace(s))
	if err != nil {
		return p, 0, 0, fmt.Errorf("cfgsim: bird: set element %q", el)
	}
	bits, max := p.Bits(), p.Addr().BitLen()
	switch {
	case i < 0:
		return p, bits, bits, nil
	case el[i:] == "+":
		return p, bits, max, nil
	}
	var lo, hi int
	if _, err := fmt.Sscanf(el[i:], "{%d,%d}", &lo, &hi); err != nil || lo < bits || hi < lo || hi > max {
		return p, 0, 0, fmt.Errorf("cfgsim: bird: set element %q", el)
	}
	return p, lo, hi, nil
}

// birdPairs reads a pair set "[ (a,b), … ]" as canonical a:b.
func birdPairs(set string) (map[string]bool, error) {
	out := map[string]bool{}
	body := set[1 : len(set)-1]
	for {
		open := strings.IndexByte(body, '(')
		if open < 0 {
			break
		}
		end := strings.IndexByte(body[open:], ')')
		if end < 0 {
			return nil, fmt.Errorf("cfgsim: bird: pair set %q", set)
		}
		k, ok := CanonCommunity(body[open : open+end+1])
		if !ok {
			return nil, fmt.Errorf("cfgsim: bird: pair set %q", set)
		}
		out[k] = true
		body = body[open+end+1:]
	}
	return out, nil
}

func (c *birdConfig) act(w []string, s *state) error {
	switch {
	case len(w) == 3 && w[0] == "bgp_local_pref":
		v, err := strconv.Atoi(w[2])
		s.attrs.LocalPref = v
		return err
	case len(w) == 3 && w[0] == "bgp_med":
		v, err := strconv.Atoi(w[2])
		s.attrs.MED, s.attrs.MEDIGP = v, false
		return err
	case len(w) == 3 && w[0] == "bgp_next_hop":
		if _, err := netip.ParseAddr(w[2]); err != nil {
			return fmt.Errorf("cfgsim: bird: next hop %q", w[2])
		}
		s.attrs.NextHop = w[2]
	case len(w) == 3 && w[0] == "bgp_community" && w[2] == "-empty-":
		s.comms = map[string]bool{}
	case len(w) == 2 && (w[0] == "bgp_community.add" || w[0] == "bgp_community.delete"):
		k, ok := CanonCommunity(w[1])
		if !ok {
			return fmt.Errorf("cfgsim: bird: pair %q", w[1])
		}
		if w[0] == "bgp_community.add" {
			s.comms[k] = true
		} else {
			delete(s.comms, k)
		}
	case len(w) == 2 && w[0] == "bgp_path.prepend":
		a, err := strconv.ParseUint(w[1], 10, 32)
		if err != nil {
			return fmt.Errorf("cfgsim: bird: prepend %q", w[1])
		}
		s.prepend([]types.ASN{types.ASN(a)})
	default:
		return fmt.Errorf("cfgsim: bird: statement %q", strings.Join(w, " "))
	}
	return nil
}

// ErrNoBIRD is BIRDSyntax's answer when no bird binary is installed.
var ErrNoBIRD = errors.New("cfgsim: bird is not installed")

var birdChecked sync.Map // text → string: "" when bird -p accepted it, its complaint otherwise

// BIRDSyntax runs "bird -p" (parse the configuration and exit) over text with
// a router id added, and returns its complaint. The answer for a text is
// cached, since tests simulate one configuration many times.
func BIRDSyntax(text string) error {
	bin, err := exec.LookPath("bird")
	if err != nil {
		return ErrNoBIRD
	}
	if v, ok := birdChecked.Load(text); ok {
		if v.(string) == "" {
			return nil
		}
		return errors.New(v.(string))
	}
	dir, err := os.MkdirTemp("", "cfgsim-bird")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	conf := filepath.Join(dir, "bird.conf")
	if err := os.WriteFile(conf, []byte("router id 10.0.0.1;\n"+text), 0o600); err != nil {
		return err
	}
	complaint := ""
	if out, err := exec.Command(bin, "-p", "-c", conf).CombinedOutput(); err != nil {
		complaint = fmt.Sprintf("bird -p: %v: %s", err, strings.TrimSpace(string(out)))
	}
	birdChecked.Store(text, complaint)
	if complaint == "" {
		return nil
	}
	return errors.New(complaint)
}
