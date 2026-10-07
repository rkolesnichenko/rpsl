package irrdq

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/rpki"
	"github.com/rkolesnichenko/rpsl/types"
)

func init() {
	commands['m'] = cmdObject
	commands['r'] = cmdRouteSearch
}

// textNotKept is the refusal of a query that needs a route's text from a
// registry that does not keep it.
const textNotKept = "Route text is not kept by this mirror (rpsld -keep-route-text)"

// keptClasses are the classes a registry holds, in the order a refusal
// names them; kept is the same set.
var (
	keptClasses = []string{"as-set", "route-set", "rtr-set", "filter-set", "peering-set", "aut-num", "inet-rtr", "route", "route6"}
	kept        = func() map[string]bool {
		m := map[string]bool{}
		for _, c := range keptClasses {
			m[c] = true
		}
		return m
	}()
)

// knownClass reports whether class is an RPSL class either profile lists,
// matched case-sensitively, as IRRd matches a class.
func knownClass(class string) bool {
	_, ripe := object.RIPE.Class(class)
	_, irrd := object.IRRd.Class(class)
	return ripe || irrd
}

// objectText is raw's text as its registry published it (ast.Object.Text:
// without the blank and comment lines a dump stream attached around it),
// ending in a newline.
func objectText(raw *ast.Object) string {
	text := raw.Text()
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	return text
}

// An entry is one object of an answer: a route or route6 of a registry (obj
// nil), or another object the registry holds.
type entry struct {
	reg *Registry
	rt  route
	obj *ast.Object
}

// class is the entry's object class; a route's follows its prefix's family.
func (e entry) class() string {
	if e.obj != nil {
		return e.obj.Class()
	}
	if e.rt.prefix.Addr().Is4() {
		return "route"
	}
	return "route6"
}

// addText adds the entry's text as served, ending in a newline, to a; false
// for a route whose text the registry does not keep. Once a is over its
// budget nothing is built, but a route's text is still checked, so that a
// refusal for text not kept comes first whatever the answer's size.
func (snap *Snapshot) addText(a *answer, e entry) bool {
	if e.obj != nil {
		if !a.over {
			a.add(objectText(e.obj))
		}
		return true
	}
	if e.rt.text == "" {
		return false
	}
	a.add(e.rt.text, snap.ovState(e.reg, e.rt))
	return true
}

// objectEntry is the entry for o, an object r keeps whole: a route claimant
// becomes a route entry, so that it is served (and hidden) as routes are.
func objectEntry(r *Registry, o object.Object) entry {
	var p netip.Prefix
	var origin types.ASN
	switch t := o.(type) {
	case *object.Route:
		p, origin = t.Prefix, t.Origin
	case *object.Route6:
		p, origin = t.Prefix, t.Origin
	default:
		return entry{reg: r, obj: o.Raw()}
	}
	if !p.IsValid() {
		return entry{reg: r, obj: o.Raw()}
	}
	return entry{reg: r, rt: route{prefix: p.Masked(), origin: origin, text: objectText(o.Raw())}}
}

// served reports whether an entry is in answers (a hidden route is not).
func (snap *Snapshot) served(e entry) bool {
	return e.obj != nil || snap.visible(e.reg, e.rt)
}

// pyUpperStrip is a key as IRRd compares a primary key: Python's
// str.upper(), then str.strip().
func pyUpperStrip(key string) string {
	return strings.TrimFunc(strings.ToUpper(key), pySpace)
}

// parseRouteKey reads a route's primary key, upper-case ("192.0.2.0/24AS1"):
// the prefix and the origin, each in its canonical form, run together.
// Anything else — a prefix with zero-padded octets, "2001:0DB8::/32", an
// origin "AS065001" — is no route's key.
func parseRouteKey(pk string) (netip.Prefix, types.ASN, bool) {
	i := strings.LastIndex(pk, "AS")
	if i <= 0 {
		return netip.Prefix{}, 0, false
	}
	p, err := netip.ParsePrefix(strings.ToLower(pk[:i]))
	if err != nil || strings.ToUpper(p.String()) != pk[:i] {
		return netip.Prefix{}, 0, false
	}
	as, msg := parseAS(pk[i:])
	if msg != "" || as.String() != pk[i:] {
		return netip.Prefix{}, 0, false
	}
	return p, as, true
}

// routeKeyOf is "!m route"'s key as IRRd's handle_irrd_exact_key reads it:
// upper-cased with every space and "-" removed, then stripped.
func routeKeyOf(key string) string {
	return pyUpperStrip(strings.NewReplacer(" ", "", "-", "").Replace(strings.ToUpper(key)))
}

// cmdObject answers "!m<class>,<key>": the object of that class and primary
// key in the first selected registry that holds it.
func cmdObject(ctx context.Context, s *Session, snap *Snapshot, arg string) Reply {
	class, key, found := strings.Cut(arg, ",")
	if !found {
		return Fail("Invalid argument for object lookup: " + arg)
	}
	switch class { // IRRToolSet's legacy names (Refinement 12)
	case "an":
		class = "aut-num"
	case "ir":
		class = "inet-rtr"
	case "rt":
		class = "route"
	}
	if !kept[class] {
		if knownClass(class) {
			return Fail("Class " + class + " is not kept by this mirror")
		}
		return notFound
	}
	es, err := snap.lookup(ctx, snap.selected(s.sources(snap)), class, key, true)
	switch {
	case err != nil:
		return internalErr(err)
	case len(es) == 0:
		return notFound
	}
	a := s.newAnswer()
	if !snap.addText(a, es[0]) {
		return Fail(textNotKept)
	}
	return a.frame()
}

// lookup is the objects of class (one the mirror keeps) whose primary key is
// key, as "!m" matches it, in regs' order: only the first found when
// firstOnly. err is a Source's error other than resolve.ErrNotFound, or
// ctx's.
func (snap *Snapshot) lookup(ctx context.Context, regs []*Registry, class, key string, firstOnly bool) ([]entry, error) {
	var out []entry
	done := func() bool { return firstOnly && len(out) > 0 }
	switch class {
	case "route", "route6":
		p, as, ok := parseRouteKey(routeKeyOf(key))
		if !ok || (class == "route") != p.Addr().Is4() {
			return nil, nil
		}
		return snap.routesByKey(ctx, regs, p, as, firstOnly)
	case "aut-num":
		pk := pyUpperStrip(key)
		as, msg := parseAS(pk)
		if msg != "" || as.String() != pk {
			return nil, nil
		}
		for _, r := range regs {
			if done() {
				break
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			an, err := r.src.AutNum(ctx, as, "")
			if errors.Is(err, resolve.ErrNotFound) || err == nil && an == nil { // nil is not found (resolve.PolicySource)
				continue
			}
			if err != nil {
				return nil, err
			}
			if an.Raw() != nil {
				out = append(out, entry{reg: r, obj: an.Raw()})
			}
		}
	case "inet-rtr":
		pk := pyUpperStrip(key)
		if pk == "" {
			return nil, nil
		}
		for _, r := range regs {
			if done() {
				break
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			rtr, err := r.src.InetRtr(ctx, pk, "")
			if errors.Is(err, resolve.ErrNotFound) || err == nil && rtr == nil { // nil is not found (resolve.PolicySource)
				continue
			}
			if err != nil {
				return nil, err
			}
			if rtr.Raw() != nil {
				out = append(out, entry{reg: r, obj: rtr.Raw()})
			}
		}
	default: // the set classes
		pk := pyUpperStrip(key)
		n, err := types.ParseSetName(pk)
		if err != nil || n.String() != pk || n.Class().String() != class {
			return nil, nil
		}
		for _, r := range regs {
			if done() {
				break
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			set, err := r.src.GetSet(ctx, types.Ref(n))
			if errors.Is(err, resolve.ErrNotFound) {
				continue
			}
			if err != nil {
				return nil, err
			}
			if set.Class() == class && set.Raw() != nil {
				out = append(out, entry{reg: r, obj: set.Raw()})
			}
		}
	}
	return out, nil
}

// routesByKey is the served routes of prefix p and origin as in regs, in
// regs' order (only the first when firstOnly). The pseudo registry's routes
// are never among them: IRRd keys each by its prefix, origin and maximum
// length ("192.0.2.0/24AS65001/ML24"), so a prefix and an origin name none
// (golden rpki/pseudo).
func (snap *Snapshot) routesByKey(ctx context.Context, regs []*Registry, p netip.Prefix, as types.ASN, firstOnly bool) ([]entry, error) {
	var out []entry
	for _, r := range regs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if r.name == rpki.PseudoSource {
			continue
		}
		for _, i := range r.byPrefix[p] {
			if e := (entry{reg: r, rt: r.routes[i]}); e.rt.origin == as && snap.served(e) {
				out = append(out, e)
				if firstOnly {
					return out, nil
				}
			}
		}
	}
	return out, nil
}

// parseSearchPrefix reads a route search's prefix as IRRd's IPy reads it: a
// prefix (zero-padded or abbreviated IPv4 read as IRRd reads them) with no
// host bits, or an address, its host prefix.
func parseSearchPrefix(s string) (netip.Prefix, bool) {
	if strings.Contains(s, "/") {
		p, err := types.ParsePrefix(s)
		if err != nil || p.Masked() != p {
			return netip.Prefix{}, false
		}
		return p, true
	}
	a, err := types.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(a, a.BitLen()), true
}

// checkEvery is how many routes a scan reads between looks at its context.
const checkEvery = 4096

// search yields the served routes of regs that mode selects for p — 0 the
// exact prefix, 'L' it and every less specific one, 'l' the most specific
// less specific prefix that any of regs holds a served route of (IRRd sizes
// it over every selected source at once), 'M' every more specific one — in
// regs' order, each registry's sorted (routeCmp), until yield returns false.
// Nothing is collected: an answer of every route of a registry is built only
// as far as its budget allows. err is ctx's.
func (snap *Snapshot) search(ctx context.Context, regs []*Registry, p netip.Prefix, mode byte, yield func(entry) bool) error {
	exact := func(r *Registry, q netip.Prefix) bool {
		for _, i := range r.byPrefix[q] {
			if e := (entry{reg: r, rt: r.routes[i]}); snap.served(e) && !yield(e) {
				return false
			}
		}
		return true
	}
	switch mode {
	case 0:
		for _, r := range regs {
			if err := ctx.Err(); err != nil {
				return err
			}
			if !exact(r, p) {
				return nil
			}
		}
	case 'L':
		for _, r := range regs {
			if err := ctx.Err(); err != nil {
				return err
			}
			var idx []int
			for bits := 0; bits <= p.Bits(); bits++ {
				q, _ := p.Addr().Prefix(bits)
				for _, i := range r.byPrefix[q] {
					if snap.visible(r, r.routes[i]) {
						idx = append(idx, i)
					}
				}
			}
			slices.Sort(idx)
			for _, i := range idx {
				if !yield(entry{reg: r, rt: r.routes[i]}) {
					return nil
				}
			}
		}
	case 'l':
		best := -1
		for _, r := range regs {
			if err := ctx.Err(); err != nil {
				return err
			}
			for bits := p.Bits() - 1; bits > best; bits-- {
				q, _ := p.Addr().Prefix(bits)
				if slices.ContainsFunc(r.byPrefix[q], func(i int) bool { return snap.visible(r, r.routes[i]) }) {
					best = bits
					break
				}
			}
		}
		if best >= 0 {
			q, _ := p.Addr().Prefix(best)
			for _, r := range regs {
				if !exact(r, q) {
					return nil
				}
			}
		}
	case 'M':
		for _, r := range regs {
			if err := ctx.Err(); err != nil {
				return err
			}
			// Routes are sorted by family, address and length, so p's more
			// specifics follow the first route not before p, up to the first
			// address outside p.
			lo := sort.Search(len(r.routes), func(i int) bool { return prefixCmp(r.routes[i].prefix, p) >= 0 })
			for i := lo; i < len(r.routes); i++ {
				if (i-lo)%checkEvery == checkEvery-1 {
					if err := ctx.Err(); err != nil {
						return err
					}
				}
				q := r.routes[i].prefix
				if q.Addr().Is4() != p.Addr().Is4() || !p.Contains(q.Addr()) {
					break
				}
				if e := (entry{reg: r, rt: r.routes[i]}); q.Bits() > p.Bits() && snap.served(e) && !yield(e) {
					return nil
				}
			}
		}
	}
	return ctx.Err()
}

// searchAll is search's routes, collected: for the searches whose answer is
// a few prefixes' routes.
func (snap *Snapshot) searchAll(ctx context.Context, regs []*Registry, p netip.Prefix, mode byte) ([]entry, error) {
	var out []entry
	err := snap.search(ctx, regs, p, mode, func(e entry) bool {
		out = append(out, e)
		return true
	})
	return out, err
}

// cmdRouteSearch answers "!r<prefix>[,o|l|L|M]": route objects (origins with
// "o"), from every selected registry.
func cmdRouteSearch(ctx context.Context, s *Session, snap *Snapshot, arg string) Reply {
	addr, opt, hasOpt := strings.Cut(arg, ",")
	p, ok := parseSearchPrefix(addr)
	if !ok {
		return Fail("Invalid input for route search: " + arg) // IRRd names the whole parameter
	}
	var mode byte
	switch {
	case !hasOpt, opt == "o":
	case opt == "l", opt == "L", opt == "M":
		mode = opt[0]
	default:
		return Fail("Invalid route search option: " + opt)
	}
	a := s.newAnswer()
	found, refused := false, ""
	err := snap.search(ctx, snap.selected(s.sources(snap)), p, mode, func(e entry) bool {
		switch {
		case opt == "o":
			// One per object, duplicates kept, as IRRd lists them.
			if found {
				a.add(" ")
			}
			found = true
			return a.addAS(e.rt.origin)
		case found:
			a.add("\n")
		}
		found = true
		if !snap.addText(a, e) {
			refused = textNotKept
			return false
		}
		return true // past the budget too, for addText's check
	})
	switch {
	case err != nil:
		return internalErr(err)
	case refused != "":
		return Fail(refused)
	case !found:
		return notFound
	}
	if opt == "o" {
		a.add("\n")
	}
	return a.frame()
}
