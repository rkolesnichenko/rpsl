package irrdq

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

func init() {
	commands['e'] = notServed("e")
	commands['J'] = notServed("J")
	commands['f'] = filterSwitch('f')
	commands['F'] = filterSwitch('F')
}

// noEntries is IRRd's RIPE-style answer when nothing matches.
const noEntries = "%  No entries found for the selected source(s).\n\n\n"

// internalErrorText is IRRd's message when a query fails for a reason of the
// server's own (a Source's error): the cause is logged there, never sent.
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
			var sel []string
			for _, n := range strings.Split(v, ",") {
				name, err := types.ParseSourceName(n)
				if err != nil || snap.byName[name] == nil {
					return ripeError("One or more selected sources are unavailable.")
				}
				sel = append(sel, name)
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
	return snap.answerRIPE(ctx, *q)
}

// answerRIPE answers one search.
func (snap *Snapshot) answerRIPE(ctx context.Context, q ripeQuery) Reply {
	if q.kind == 'i' && !slices.Contains(inverseServed, q.attr) {
		if inverseNotServed[q.attr] {
			return ripeError("Inverse search on " + q.attr + " is not served by this mirror: it keeps the routing classes only")
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
	var (
		es      []entry
		refused string
		err     error
	)
	switch q.kind {
	case 't':
		es, refused, err = snap.textSearch(ctx, regs, q.key, want, len(q.classes) > 0)
	case 'i':
		es, err = snap.inverse(ctx, regs, q.attr, q.key, want)
	default:
		p, ok := parseSearchPrefix(q.key)
		if !ok {
			return ripeError("Invalid input for route search: " + q.key)
		}
		mode := q.kind
		if mode == 'x' {
			mode = 0
		}
		es, err = snap.search(ctx, regs, p, mode)
		es = wanted(es, want)
	}
	switch {
	case err != nil:
		return ripeError(internalErrorText)
	case refused != "":
		return ripeError(refused)
	case len(es) == 0:
		return Reply{text: noEntries}
	}
	var blocks []string
	if q.keys {
		blocks = keyBlocks(es)
	} else if blocks, refused = snap.texts(es); refused != "" {
		return ripeError(refused)
	}
	return Reply{text: strings.Join(blocks, "\n") + "\n\n"}
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

// textSearch answers a plain key, as IRRd's text_search: an AS number, its
// aut-num; a prefix or an address, the routes of it and of every less
// specific prefix; otherwise the objects whose primary key is the key — a
// set, a route ("192.0.2.0/24AS1") or an inet-rtr — from every selected
// registry (no precedence). IRRd's last case also matches persons and roles
// by part of their name and objects of every class the mirror lacks, so a
// key that names no set and no route or inet-rtr held is refused, unless -T
// asked for classes the mirror keeps (restricted), which makes the answer
// certain.
func (snap *Snapshot) textSearch(ctx context.Context, regs []*Registry, key string, want func(string) bool, restricted bool) ([]entry, string, error) {
	if as, msg := parseAS(key); msg == "" {
		if !want("aut-num") {
			return nil, "", nil
		}
		var out []entry
		for _, r := range regs {
			an, err := r.src.AutNum(ctx, as, "")
			if errors.Is(err, resolve.ErrNotFound) {
				continue
			}
			if err != nil {
				return nil, "", err
			}
			if an.Raw() != nil {
				out = append(out, entry{reg: r, obj: an.Raw()})
			}
		}
		return out, "", ctx.Err()
	}
	if p, ok := parseSearchPrefix(key); ok {
		es, err := snap.search(ctx, regs, p, 'L')
		return wanted(es, want), "", err
	}
	pk := strings.ToUpper(key)
	if n, err := types.ParseSetName(pk); err == nil && n.String() == pk {
		if !want(n.Class().String()) {
			return nil, "", nil
		}
		es, err := snap.lookup(ctx, regs, n.Class().String(), pk, false)
		return es, "", err
	}
	var out []entry
	if p, as, ok := parseRouteKey(pk); ok {
		es, err := snap.routesByKey(ctx, regs, p, as, false)
		if err != nil {
			return nil, "", err
		}
		out = append(out, wanted(es, want)...)
	}
	if want("inet-rtr") {
		es, err := snap.lookup(ctx, regs, "inet-rtr", pk, false)
		if err != nil {
			return nil, "", err
		}
		out = append(out, es...)
	}
	if len(out) == 0 && !restricted {
		return nil, "This mirror keeps only the routing classes; it cannot answer a lookup of " + key, nil
	}
	return out, "", nil
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
		for _, r := range regs {
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
	}
	return out, ctx.Err()
}

// keyBlocks reduces each entry to IRRd's -K form, each distinct block once,
// in order: its primary key attributes as IRRd stores them (a route's
// canonical prefix and its origin; a set's or an inet-rtr's name
// upper-case; an aut-num's AS number), then each members: and mp-members:
// item — normalized for an as-set or route-set (normMember), upper-cased
// for an rtr-set, whose members are router names and addresses. A route
// needs no text for it.
func keyBlocks(es []entry) []string {
	var out []string
	seen := map[string]bool{}
	for _, e := range es {
		var b strings.Builder
		class := e.class()
		if e.obj == nil {
			b.WriteString(class + ": " + e.rt.prefix.String() + "\norigin: " + e.rt.origin.String() + "\n")
		} else {
			key := strings.ToUpper(strings.TrimSpace(e.obj.Key()))
			if as, err := types.ParseASN(key); err == nil && class == "aut-num" {
				key = as.String()
			} else if n, err := types.ParseSetName(key); err == nil {
				key = n.String()
			}
			b.WriteString(class + ": " + key + "\n")
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
		}
		if block := b.String(); !seen[block] {
			seen[block] = true
			out = append(out, block)
		}
	}
	return out
}
