// Package irrtest is an in-memory IRR for tests: RPSL objects from several
// sources, served over the IRRd query protocol and over whois the way an IRRd
// server answers them. It implements IRRd's membership rules itself — straight
// from the objects' attributes, not through the resolve package — so tests can
// hold the backends, and bgpq4, against an independent server.
//
// "!i<set>,1" resolves recursively as IRRd does (see Recursive); "!a" is
// refused, so a client falls back to building prefix lists itself.
package irrtest

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/types"
)

// DB is a set of RPSL objects, in load order.
type DB struct {
	objs     []entry
	extra    []string            // sources that exist without objects
	byKey    map[string][]int    // class + " " + key -> objects, in load order
	byOrigin map[types.ASN][]int // origin -> route and route6 objects
	claims   map[string][]int    // upper-case set name -> objects naming it in member-of

	mu   sync.Mutex
	cmds []string
}

type entry struct {
	text   string // "" when loaded without it: obj.String() then
	obj    *ast.Object
	class  string
	key    string // upper-case
	source string // upper-case
}

// New loads RPSL objects, one per text.
func New(texts ...string) *DB {
	db := &DB{byKey: map[string][]int{}, byOrigin: map[types.ASN][]int{}, claims: map[string][]int{}}
	for _, text := range texts {
		o, _ := rpsl.ParseObject(text)
		db.Add(o, text)
	}
	return db
}

// Add loads one parsed object, whose text is text; "" saves memory, and the
// object's own String() is served instead.
func (db *DB) Add(o *ast.Object, text string) {
	if o.Class() == "" {
		return
	}
	src := ""
	if a, ok := o.GetFirst("source"); ok {
		src = strings.ToUpper(strings.TrimSpace(strings.SplitN(a.Value, "#", 2)[0]))
	}
	i := len(db.objs)
	if text != "" {
		text = strings.TrimRight(text, "\n") + "\n"
	}
	e := entry{text: text, obj: o, class: o.Class(),
		key: strings.ToUpper(strings.TrimSpace(o.Key())), source: src}
	db.objs = append(db.objs, e)
	db.byKey[e.class+" "+e.key] = append(db.byKey[e.class+" "+e.key], i)
	if e.class == "route" || e.class == "route6" {
		if a, ok := o.GetFirst("origin"); ok {
			if as, err := types.ParseASN(strings.TrimSpace(a.Value)); err == nil {
				db.byOrigin[as] = append(db.byOrigin[as], i)
			}
		}
	}
	for _, n := range items(o, "member-of") {
		n = strings.ToUpper(n)
		db.claims[n] = append(db.claims[n], i)
	}
}

// WithSources declares sources that exist even if no object is in them, as on
// a server configured with empty sources, and returns db.
func (db *DB) WithSources(names ...string) *DB {
	for _, n := range names {
		db.extra = append(db.extra, strings.ToUpper(n))
	}
	return db
}

// String returns the object's text.
func (e entry) String() string {
	if e.text != "" {
		return e.text
	}
	return strings.TrimRight(e.obj.String(), "\n") + "\n"
}

// Commands returns the IRRd commands received so far, in order.
func (db *DB) Commands() []string {
	db.mu.Lock()
	defer db.mu.Unlock()
	return append([]string(nil), db.cmds...)
}

func (db *DB) record(cmd string) {
	db.mu.Lock()
	db.cmds = append(db.cmds, cmd)
	db.mu.Unlock()
}

// sources returns the distinct sources, in load order.
func (db *DB) sources() []string {
	var out []string
	for _, e := range db.objs {
		if e.source != "" && !contains(out, e.source) {
			out = append(out, e.source)
		}
	}
	for _, s := range db.extra {
		if !contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// find returns the first object of class with key among the selected sources,
// in their priority order.
func (db *DB) find(sel []string, class, key string) (entry, bool) {
	idx := db.byKey[class+" "+strings.ToUpper(key)]
	if len(sel) == 0 && len(idx) > 0 {
		return db.objs[idx[0]], true
	}
	for _, s := range sel {
		for _, i := range idx {
			if db.objs[i].source == s {
				return db.objs[i], true
			}
		}
	}
	return entry{}, false
}

// items returns the items of every name attribute of o, split at commas and
// line breaks as IRRd splits them (see ast.Attribute.List).
func items(o *ast.Object, name string) []string {
	var out []string
	for _, a := range o.GetAll(name) {
		for _, it := range a.List() {
			if it.Value != "" {
				out = append(out, it.Value)
			}
		}
	}
	return out
}

// Members answers "!i<set>" as IRRd does: the set's members: and mp-members:
// items as written, and — when the set has mbrs-by-ref — the key of every
// aut-num (for an as-set) or route/route6 (for a route-set) of the set's own
// source that names the set in member-of and is maintained by one of the
// mbrs-by-ref maintainers (or any, for ANY). The set is taken from the first
// selected source that has it. ok is false when there is no such set.
func (db *DB) Members(sel []string, name string) (members []string, ok bool) {
	class := "as-set"
	if n, err := types.ParseSetName(name); err == nil && n.Class() == types.ClassRouteSet {
		class = "route-set"
	}
	set, ok := db.find(sel, class, name)
	if !ok {
		return nil, false
	}
	members = append(items(set.obj, "members"), items(set.obj, "mp-members")...)
	refs := items(set.obj, "mbrs-by-ref")
	if len(refs) == 0 {
		return members, true
	}
	for _, i := range db.claims[strings.ToUpper(name)] {
		e := db.objs[i]
		if e.source != set.source {
			continue
		}
		switch {
		case class == "as-set" && e.class == "aut-num":
		case class == "route-set" && (e.class == "route" || e.class == "route6"):
		default:
			continue
		}
		if !containsFold(items(e.obj, "member-of"), name) {
			continue
		}
		mnts := items(e.obj, "mnt-by")
		allowed := containsFold(refs, "ANY")
		for _, m := range mnts {
			allowed = allowed || containsFold(refs, m)
		}
		if allowed {
			members = append(members, e.key)
		}
	}
	return members, true
}

// Recursive answers "!i<set>,1" as IRRd does: the set's members, resolved
// through nested sets. Nested sets of the classes the set may include (as-sets
// in an as-set; route-sets and as-sets in a route-set) are resolved, each once,
// with their indirect members. In a route-set an AS number becomes the prefixes
// its route and route6 objects hold; in an as-set it stays an AS number. A
// prefix member stays as written, range operator included. Anything else — a
// set that is not found, a set or AS number with a range operator, junk — is a
// leaf and comes back unchanged. ok is false when the set itself is not found.
func (db *DB) Recursive(sel []string, name string) (members []string, ok bool) {
	root, err := types.ParseSetName(name)
	if err != nil {
		return nil, false
	}
	if _, ok := db.Members(sel, name); !ok {
		return nil, false
	}
	seen, out := map[string]bool{}, map[string]bool{}
	var walk func(set string)
	walk = func(set string) {
		if seen[strings.ToUpper(set)] {
			return
		}
		seen[strings.ToUpper(set)] = true
		ms, found := db.Members(sel, set)
		if !found {
			out[set] = true // a leaf
			return
		}
		for _, m := range ms {
			if strings.Contains(m, "/") {
				if root.Class() == types.ClassRouteSet {
					out[m] = true
				}
				continue
			}
			if as, err := types.ParseASN(m); err == nil && !strings.Contains(m, "^") {
				if root.Class() == types.ClassAsSet {
					out[as.String()] = true
					continue
				}
				for _, v6 := range []bool{false, true} {
					for _, p := range db.Routes(sel, as, v6) {
						out[p.String()] = true
					}
				}
				continue
			}
			if n, err := types.ParseSetName(m); err == nil && !strings.Contains(m, "^") &&
				(n.Class() == types.ClassAsSet || root.Class() == types.ClassRouteSet && n.Class() == types.ClassRouteSet) {
				walk(m)
				continue
			}
			out[m] = true // a leaf
		}
	}
	walk(name)
	for m := range out {
		members = append(members, m)
	}
	sort.Strings(members)
	return members, true
}

// Routes answers "!g"/"!6": the distinct prefixes of the route (v4) or route6
// (v6) objects of the selected sources originated by as.
func (db *DB) Routes(sel []string, as types.ASN, v6 bool) []netip.Prefix {
	class := "route"
	if v6 {
		class = "route6"
	}
	seen := map[netip.Prefix]bool{}
	var out []netip.Prefix
	for _, i := range db.byOrigin[as] {
		e := db.objs[i]
		if e.class != class || len(sel) > 0 && !contains(sel, e.source) {
			continue
		}
		p, err := types.ParsePrefix(e.key) // as IRRd reads route keys: padded or abbreviated IPv4 too
		if err != nil || seen[p.Masked()] {
			continue
		}
		seen[p.Masked()] = true
		out = append(out, p.Masked())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// IRRd serves db over the IRRd query protocol on a localhost port until the
// test ends, and returns its address. Like IRRd, it answers one command and
// closes unless the client sends "!!" first.
func (db *DB) IRRd(t testing.TB) string {
	t.Helper()
	return serve(t, db.irrdConn)
}

func (db *DB) irrdConn(c net.Conn) {
	br := bufio.NewReader(c)
	persistent := false
	var sel []string
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.TrimRight(line, "\r\n")
		if cmd == "" {
			continue
		}
		db.record(cmd)
		switch {
		case cmd == "!!":
			persistent = true
			continue
		case cmd == "!q":
			return
		case strings.HasPrefix(cmd, "!n"):
			fmt.Fprint(c, "C\n")
		case cmd == "!v":
			frame(c, "irrtest")
		case cmd == "!s-lc":
			if len(sel) > 0 {
				frame(c, strings.Join(sel, ","))
			} else {
				frame(c, strings.Join(db.sources(), ","))
			}
		case strings.HasPrefix(cmd, "!s"):
			var next []string
			known := db.sources()
			bad := ""
			for _, s := range strings.Split(cmd[2:], ",") {
				s = strings.ToUpper(strings.TrimSpace(s))
				if !contains(known, s) {
					bad = s
				}
				next = append(next, s)
			}
			if bad != "" {
				fmt.Fprintf(c, "F Unknown source %s\n", bad)
			} else {
				sel = next
				fmt.Fprint(c, "C\n")
			}
		case strings.HasPrefix(cmd, "!i"):
			name := cmd[2:]
			members, ok := []string(nil), false
			if base, recursive := strings.CutSuffix(name, ",1"); recursive {
				members, ok = db.Recursive(sel, base)
			} else {
				members, ok = db.Members(sel, name)
			}
			if !ok || len(members) == 0 {
				fmt.Fprint(c, "D\n") // IRRd answers an empty set like a missing one
			} else {
				frame(c, strings.Join(members, " "))
			}
		case strings.HasPrefix(cmd, "!g"), strings.HasPrefix(cmd, "!6"):
			as, err := types.ParseASN(cmd[2:])
			if err != nil {
				fmt.Fprintf(c, "F invalid AS %q\n", cmd[2:])
				break
			}
			var ps []string
			for _, p := range db.Routes(sel, as, cmd[1] == '6') {
				ps = append(ps, p.String())
			}
			if len(ps) == 0 {
				fmt.Fprint(c, "D\n")
			} else {
				frame(c, strings.Join(ps, " "))
			}
		case strings.HasPrefix(cmd, "!m"):
			class, key, _ := strings.Cut(cmd[2:], ",")
			if e, ok := db.find(sel, strings.ToLower(class), key); ok {
				frame(c, strings.TrimRight(e.String(), "\n"))
			} else {
				fmt.Fprint(c, "D\n")
			}
		default:
			fmt.Fprintf(c, "F unsupported command %q\n", cmd)
		}
		if !persistent {
			return
		}
	}
}

// frame writes an IRRd data response: "A<len>", the payload and its newline,
// then "C".
func frame(c net.Conn, payload string) {
	payload += "\n"
	fmt.Fprintf(c, "A%d\n%sC\n", len(payload), payload)
}

// Whois serves db over whois on a localhost port until the test ends, and
// returns its address. It reads a query as IRRd's whois parser does: flags left
// to right ("-s" sources, "-T" classes, "-r" ignored), and "-i attr value" ends
// the query; otherwise the last token is a primary key. Each query gets one
// answer, then the connection closes.
func (db *DB) Whois(t testing.TB) string {
	t.Helper()
	return serve(t, func(c net.Conn) {
		line, err := bufio.NewReader(c).ReadString('\n')
		if err != nil {
			return
		}
		fmt.Fprint(c, db.whoisAnswer(strings.Fields(line)))
	})
}

func (db *DB) whoisAnswer(tokens []string) string {
	var classes, sel []string
	var attr, value string
query:
	for i := 0; i < len(tokens); i++ {
		switch tokens[i] {
		case "-r", "-B", "-G":
		case "-T", "-s":
			if i+1 >= len(tokens) {
				return "%ERROR:106: no search key specified\n"
			}
			list := strings.Split(tokens[i+1], ",")
			if tokens[i] == "-T" {
				classes = list
			} else {
				for _, s := range list {
					sel = append(sel, strings.ToUpper(s))
				}
			}
			i++
		case "-i":
			if i+2 >= len(tokens) {
				return "%% ERROR: Missing argument for inverse query.\n"
			}
			attr, value = tokens[i+1], tokens[i+2]
			break query
		default:
			value = tokens[i]
		}
	}
	var out []string
	for _, e := range db.objs { // load order, not priority: the client picks
		if len(sel) > 0 && !contains(sel, e.source) || len(classes) > 0 && !containsFold(classes, e.class) {
			continue
		}
		if attr == "" && strings.EqualFold(e.key, value) ||
			attr != "" && containsFold(items(e.obj, attr), value) {
			out = append(out, e.String())
		}
	}
	if len(out) == 0 {
		return "%ERROR:101: no entries found\n"
	}
	return "% irrtest\n\n" + strings.Join(out, "\n")
}

// serve accepts connections on a localhost listener until the test ends.
func serve(t testing.TB, handle func(net.Conn)) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("irrtest: listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				handle(c)
			}()
		}
	}()
	return ln.Addr().String()
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func containsFold(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(strings.TrimSpace(x), strings.TrimSpace(s)) {
			return true
		}
	}
	return false
}
