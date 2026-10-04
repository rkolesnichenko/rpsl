package irrdq

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

func init() {
	commands['e'] = notServed("e")
	commands['J'] = notServed("J")
	commands['o'] = func(context.Context, *Session, *Snapshot, string) Reply { return Fail(mntByNotServed) }
	commands['f'] = filterSwitch('f')
	commands['F'] = filterSwitch('F')
}

// noEntries is IRRd's RIPE-style answer when nothing matches.
const noEntries = "%  No entries found for the selected source(s).\n\n\n"

// internalErrorText is IRRd's message when a query fails for a reason of the
// server's own (a Source's error): the cause is never sent, but kept beside
// the reply (Reply.Cause) for the server to log.
const internalErrorText = "An internal error occurred while processing this query."

// ripeError is IRRd's RIPE-style error answer.
func ripeError(msg string) Reply { return Reply{text: "%% ERROR: " + msg + "\n\n\n"} }

// notServed answers an IRRd command the mirror does not serve (Refinement
// 10): "!e" (set exclusion) and "!J" (database status).
func notServed(cmd string) func(context.Context, *Session, *Snapshot, string) Reply {
	return func(context.Context, *Session, *Snapshot, string) Reply {
		return Fail("Command !" + cmd + " is not served by this mirror")
	}
}

// filterSwitches are the "!f" commands IRRd 4.5.3 answers, matched as it
// matches them (case-insensitively, whole): each turns a filter off for the
// connection. The mirror has no scope or route-preference filter, and hides
// RPKI-invalid routes without a per-connection exception.
var filterSwitches = []string{"fno-rpki-filter", "fno-scope-filter", "fno-route-preference-filter"}

// filterSwitch answers "!" + cmd: one of filterSwitches, refused, or IRRd's
// answer to an unknown command.
func filterSwitch(cmd rune) func(context.Context, *Session, *Snapshot, string) Reply {
	return func(_ context.Context, _ *Session, _ *Snapshot, arg string) Reply {
		for _, f := range filterSwitches {
			if strings.EqualFold(string(cmd)+arg, f) {
				return Fail("Command !" + f + " is not served by this mirror")
			}
		}
		return Fail("Unrecognised command: " + string(cmd))
	}
}

// inverseServed are the -i attributes the mirror answers whole.
var inverseServed = []string{"origin", "member-of", "mbrs-by-ref", "members", "mp-members"}

// inverseNotServed are the other -i attributes IRRd 4.5.3 searches: they
// name objects of classes the mirror does not keep, so no answer would be
// whole.
var inverseNotServed = map[string]bool{"mnt-by": true, "admin-c": true, "tech-c": true, "zone-c": true, "person": true, "role": true}

// inverseRefused is the refusal of an inverse search on attr, one of
// inverseNotServed.
func inverseRefused(attr string) string {
	return "Inverse search on " + attr + " is not served by this mirror: it keeps the routing classes only"
}

// mntByNotServed answers "!o<mntner>", IRRd's inverse search on mnt-by.
var mntByNotServed = inverseRefused("mnt-by")

// ripeQuery is the search a RIPE-style query line asks, with the flags in
// effect when it was read.
type ripeQuery struct {
	kind    byte     // 't' a text search, 'i' an inverse search, 'x', 'l', 'L', 'M' a route search
	attr    string   // -i's attribute
	key     string   // the value searched for
	classes []string // -T's classes, as given (nil: every class)
	keys    bool     // -K
	sources []string // the selection
}

// ripe answers a RIPE-style query (no "!") as IRRd 4.5.3's
// handle_ripe_command reads it: the line split at runs of spaces and read
// left to right. A word is a text search; -T restricts the next search
// only; -K and the selection in effect when a search is read apply to it;
// -i, -x, -l, -L and -M search and end the query; the last search answers.
// -s selects registries for the rest of the session (as soon as it is read,
// whatever follows), -k keeps the connection open, -r, -F and -V change
// nothing. Flags are whole words: "-rK" is no flag.
func (s *Session) ripe(ctx context.Context, snap *Snapshot, line string) Reply {
	words := strings.FieldsFunc(line, func(r rune) bool { return r == ' ' })
	var (
		q       *ripeQuery
		classes []string
		keys    bool
	)
	search := func(kind byte, attr, key string) {
		q = &ripeQuery{kind: kind, attr: attr, key: key, classes: classes, keys: keys, sources: s.sources(snap)}
		classes = nil
	}
read:
	for i := 0; i < len(words); i++ {
		w := words[i]
		if !strings.HasPrefix(w, "-") {
			search('t', "", w)
			continue
		}
		flag := w[1:]
		next := func() (string, bool) {
			if i+1 >= len(words) {
				return "", false
			}
			i++
			return words[i], true
		}
		missing := ripeError("Missing argument for flag/search: " + flag)
		switch flag {
		case "k":
			s.persistent = true
		case "K":
			keys = true
		case "r", "F":
		case "V":
			if _, ok := next(); !ok {
				return missing
			}
		case "s":
			v, ok := next()
			if !ok {
				return missing
			}
			sel, ok := snap.selection(v)
			if !ok {
				return ripeError(unavailable)
			}
			s.sel = sel // for good, as IRRd's -s (golden ripe/s-flag-sticks)
		case "T":
			v, ok := next()
			if !ok {
				return missing
			}
			classes = strings.Split(v, ",")
		case "x", "l", "L", "M":
			v, ok := next()
			if !ok {
				return missing
			}
			search(flag[0], "", v)
			break read
		case "i":
			attr, ok := next()
			if !ok {
				return missing
			}
			v, ok := next()
			if !ok {
				return missing
			}
			search('i', attr, v)
			break read
		case "a", "t", "q", "g":
			return ripeError("Flag -" + flag + " is not served by this mirror")
		default:
			return ripeError("Unrecognised flag/search: " + flag)
		}
	}
	if q == nil {
		return Reply{text: noEntries}
	}
	return snap.answerRIPE(ctx, *q, s.newAnswer())
}

// answerRIPE answers one search, built in a.
func (snap *Snapshot) answerRIPE(ctx context.Context, q ripeQuery, a *answer) Reply {
	if q.kind == 'i' && !slices.Contains(inverseServed, q.attr) {
		if inverseNotServed[q.attr] {
			return ripeError(inverseRefused(q.attr))
		}
		return ripeError("Inverse attribute search not supported for " + q.attr +
			", only supported for attributes: " + strings.Join(inverseServed, ", "))
	}
	for _, c := range q.classes {
		if !kept[c] && knownClass(c) {
			return ripeError("Class " + c + " is not kept by this mirror")
		}
	}
	want := func(class string) bool { return len(q.classes) == 0 || slices.Contains(q.classes, class) }
	regs := snap.selected(q.sources)
	// emit adds one object, its text or (-K) its key block, each distinct
	// block once, objects separated by a blank line.
	found, refused := false, ""
	seenRoute, seenBlock := map[routeKey]bool{}, map[string]bool{}
	emit := func(e entry) bool {
		if q.keys {
			// A route's block is its prefix and origin, so it is told
			// apart by them, and written without being built apart.
			if e.obj == nil {
				k := routeKey{e.rt.prefix, e.rt.origin}
				if seenRoute[k] {
					return true
				}
				seenRoute[k] = true
			} else {
				block := keyBlock(e)
				if seenBlock[block] {
					return true
				}
				seenBlock[block] = true
			}
			if found {
				a.add("\n")
			}
			found = true
			return addKeyBlock(a, e)
		}
		if found {
			a.add("\n")
		}
		found = true
		if !snap.addText(a, e) {
			refused = textNotKept
			return false
		}
		return true // past the budget too, for addText's check
	}
	emitAll := func(es []entry) {
		for _, e := range es {
			if !emit(e) {
				return
			}
		}
	}
	var (
		es  []entry
		err error
	)
	switch q.kind {
	case 't':
		if len(q.classes) == 0 {
			return ripeError(lookupRefused(q.key))
		}
		es, err = snap.textSearch(ctx, regs, q.key, want)
		emitAll(es)
	case 'i':
		es, err = snap.inverse(ctx, regs, q.attr, q.key, want)
		emitAll(es)
	default:
		p, ok := parseSearchPrefix(q.key)
		if !ok {
			return ripeError("Invalid input for route search: " + q.key)
		}
		mode := q.kind
		if mode == 'x' {
			mode = 0
		}
		err = snap.search(ctx, regs, p, mode, func(e entry) bool {
			return !want(e.class()) || emit(e)
		})
	}
	switch {
	case err != nil:
		r := ripeError(internalErrorText)
		r.cause = err
		return r
	case refused != "":
		return ripeError(refused)
	case !found:
		return Reply{text: noEntries}
	}
	a.add("\n\n")
	return a.plain()
}

// wanted is the entries of es whose class want admits.
func wanted(es []entry, want func(string) bool) []entry {
	out := es[:0:0]
	for _, e := range es {
		if want(e.class()) {
			out = append(out, e)
		}
	}
	return out
}

// lookupRefused is the refusal of a plain lookup without -T.
func lookupRefused(key string) string {
	return "This mirror keeps only the routing classes, so it cannot answer a lookup of " + key +
		" whole; ask with -T and any of " + strings.Join(keptClasses, ", ")
}

// textSearch answers a plain key under a -T that names only classes the
// mirror keeps (want), as IRRd's text_search does: an AS number, its
// aut-num; a prefix or an address, the routes of it and of every less
// specific prefix; otherwise the objects whose primary key is the key — a
// set, a route ("192.0.2.0/24AS1") or an inet-rtr — from every selected
// registry (no precedence).
//
// Without -T IRRd's text_search also answers with classes the mirror lacks —
// an AS number with the as-blocks covering it, an address with inetnums and
// inet6nums, any other key with persons and roles whose name holds it — so
// such a lookup is refused (lookupRefused): every answer would be partial,
// and "No entries" possibly false.
func (snap *Snapshot) textSearch(ctx context.Context, regs []*Registry, key string, want func(string) bool) ([]entry, error) {
	if as, msg := parseAS(key); msg == "" {
		if !want("aut-num") {
			return nil, nil
		}
		var out []entry
		for _, r := range regs {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			an, err := r.src.AutNum(ctx, as, "")
			if errors.Is(err, resolve.ErrNotFound) {
				continue
			}
			if err != nil {
				return nil, err
			}
			if an.Raw() != nil {
				out = append(out, entry{reg: r, obj: an.Raw()})
			}
		}
		return out, nil
	}
	if p, ok := parseSearchPrefix(key); ok {
		es, err := snap.searchAll(ctx, regs, p, 'L')
		return wanted(es, want), err
	}
	pk := strings.ToUpper(key)
	if n, err := types.ParseSetName(pk); err == nil && n.String() == pk {
		if !want(n.Class().String()) {
			return nil, nil
		}
		return snap.lookup(ctx, regs, n.Class().String(), pk, false)
	}
	var out []entry
	if p, as, ok := parseRouteKey(pk); ok {
		es, err := snap.routesByKey(ctx, regs, p, as, false)
		if err != nil {
			return nil, err
		}
		out = append(out, wanted(es, want)...)
	}
	if want("inet-rtr") {
		es, err := snap.lookup(ctx, regs, "inet-rtr", pk, false)
		if err != nil {
			return nil, err
		}
		out = append(out, es...)
	}
	return out, nil
}

// inverse answers "-i attr value" for an attribute the mirror serves, as
// IRRd's lookup_attr matches it: the value upper-cased against the values
// IRRd stores (an origin in its canonical form; members: items normalized on
// both sides, normMember). member-of lists every object naming the set,
// without the mbrs-by-ref check (golden ripe/-i member-of AS-REF).
func (snap *Snapshot) inverse(ctx context.Context, regs []*Registry, attr, value string, want func(string) bool) ([]entry, error) {
	var out []entry
	switch attr {
	case "origin":
		as, msg := parseAS(value)
		if msg != "" || as.String() != strings.ToUpper(value) {
			return nil, nil
		}
		for _, r := range regs {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			ps, err := r.src.OriginatedRoutes(ctx, as, types.AFIAny)
			if err != nil {
				return nil, err
			}
			var idx []int
			for _, p := range ps {
				for _, i := range r.byPrefix[p.Masked()] {
					if r.routes[i].origin == as {
						idx = append(idx, i)
					}
				}
			}
			slices.Sort(idx)
			for _, i := range slices.Compact(idx) {
				if e := (entry{reg: r, rt: r.routes[i]}); snap.served(e) && want(e.class()) {
					out = append(out, e)
				}
			}
		}
	case "member-of", "members", "mp-members", "mbrs-by-ref":
		// The indexes list objects in load order, which a mirror's delta
		// changes; the answer is ordered by class, primary key, then the
		// registries' order, so that it does not.
		rank := map[*Registry]int{}
		for i, r := range regs {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			rank[r] = i
			var objs []object.Object
			switch attr {
			case "member-of":
				objs = r.claims[strings.ToUpper(value)]
			case "mbrs-by-ref":
				objs = r.byMbrRef[strings.ToUpper(value)]
			default:
				objs = r.byMember[attr+" "+normMember(value)]
			}
			for _, o := range objs {
				if e := objectEntry(r, o); snap.served(e) && want(e.class()) {
					out = append(out, e)
				}
			}
		}
		slices.SortStableFunc(out, func(x, y entry) int {
			if c := strings.Compare(x.class(), y.class()); c != 0 {
				return c
			}
			if x.obj == nil && y.obj == nil {
				if c := prefixCmp(x.rt.prefix, y.rt.prefix); c != 0 {
					return c
				}
				if c := cmpASN(x.rt.origin, y.rt.origin); c != 0 {
					return c
				}
			} else if x.obj != nil && y.obj != nil {
				if c := strings.Compare(objectKey(x.class(), x.obj), objectKey(y.class(), y.obj)); c != 0 {
					return c
				}
			}
			if c := rank[x.reg] - rank[y.reg]; c != 0 {
				return c
			}
			return strings.Compare(x.rt.text, y.rt.text) // two spellings of one route
		})
	}
	return out, ctx.Err()
}

func cmpASN(a, b types.ASN) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// objectKey is an object's primary key as IRRd stores it: a set's or an
// inet-rtr's name upper-case, an aut-num's AS number.
func objectKey(class string, obj *ast.Object) string {
	key := strings.ToUpper(strings.TrimSpace(obj.Key()))
	if as, err := types.ParseASN(key); err == nil && class == "aut-num" {
		return as.String()
	}
	if n, err := types.ParseSetName(key); err == nil {
		return n.String()
	}
	return key
}

// routeKey is a route's primary key.
type routeKey struct {
	prefix netip.Prefix
	origin types.ASN
}

// addKeyBlock adds keyBlock(e) to a; a route's without building it apart.
func addKeyBlock(a *answer, e entry) bool {
	if e.obj != nil {
		return a.add(keyBlock(e))
	}
	return a.add(e.class(), ": ") && a.addPrefix(e.rt.prefix) && a.add("\norigin: ") &&
		a.addAS(e.rt.origin) && a.add("\n")
}

// keyBlock is an entry in IRRd's -K form: its primary key attributes as IRRd
// stores them (a route's canonical prefix and its origin, objectKey for any
// other), then each members: and mp-members: item — normalized for an
// as-set or route-set (normMember), upper-cased for an rtr-set, whose
// members are router names and addresses. A route needs no text for it.
func keyBlock(e entry) string {
	class := e.class()
	if e.obj == nil {
		return class + ": " + e.rt.prefix.String() + "\norigin: " + e.rt.origin.String() + "\n"
	}
	var b strings.Builder
	b.WriteString(class + ": " + objectKey(class, e.obj) + "\n")
	for _, attr := range []string{"members", "mp-members"} {
		for _, a := range e.obj.GetAll(attr) {
			for _, it := range a.List() {
				if it.Value == "" {
					continue
				}
				v := normMember(it.Value)
				if class == "rtr-set" {
					v = strings.ToUpper(it.Value)
				}
				b.WriteString(attr + ": " + v + "\n")
			}
		}
	}
	return b.String()
}
