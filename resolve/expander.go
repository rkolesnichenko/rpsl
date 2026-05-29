package resolve

import (
	"context"
	"errors"
	"net/netip"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/types"
)

const (
	defaultMaxDepth    = 32
	defaultMaxPrefixes = 1 << 20
)

// Expander expands set references into concrete ASNs and prefixes. It is pure:
// all I/O is delegated to Src, all limits are explicit, and every traversal is
// context-cancellable. A zero Expander (except Src) uses the default limits.
type Expander struct {
	Src         Source
	MaxDepth    int       // set-nesting depth cap (default 32)
	MaxPrefixes int       // hard cap on prefix output (default 1<<20)
	AFI         types.AFI // address-family constraint; Unspecified/Any = both
	Sources     []string  // IRR source precedence (advisory; Source decides)
}

func (e *Expander) maxDepth() int {
	if e.MaxDepth > 0 {
		return e.MaxDepth
	}
	return defaultMaxDepth
}

func (e *Expander) maxPrefixes() int {
	if e.MaxPrefixes > 0 {
		return e.MaxPrefixes
	}
	return defaultMaxPrefixes
}

// afiAllows reports whether a prefix is admitted under the configured AFI.
func (e *Expander) afiAllows(p netip.Prefix) bool {
	switch e.AFI {
	case types.AFIv4:
		return p.Addr().Is4()
	case types.AFIv6:
		return p.Addr().Is6()
	default: // Unspecified / Any
		return true
	}
}

// ExpandAS returns the transitive set of ASNs denoted by an as-set, following
// nested set references and indirect (mbrs-by-ref) membership. Cycles are
// skipped; missing sets expand to nothing.
func (e *Expander) ExpandAS(ctx context.Context, n types.SetName) (ASSet, error) {
	r := &asRun{e: e, ctx: ctx, out: newASSet(), visited: map[string]bool{}}
	if err := r.walk(n, 0); err != nil {
		return ASSet{}, err
	}
	return *r.out, nil
}

type asRun struct {
	e       *Expander
	ctx     context.Context
	out     *ASSet
	visited map[string]bool
}

func (r *asRun) walk(name types.SetName, depth int) error {
	if err := r.ctx.Err(); err != nil {
		return err
	}
	if depth > r.e.maxDepth() {
		return nil // bgpq4-style: stop descending, do not error
	}
	key := name.Canonical()
	if r.visited[key] {
		return nil // cycle or shared sub-set already covered
	}
	r.visited[key] = true

	set, err := r.e.Src.GetSet(r.ctx, name)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	}

	for _, m := range set.SetMembers() {
		switch m.Kind {
		case object.MemberAS:
			r.out.add(m.AS)
		case object.MemberSet:
			if m.Set.Class == types.AsSet {
				if err := r.walk(m.Set, depth+1); err != nil {
					return err
				}
			}
			// route-set/other members do not contribute ASNs.
		}
	}

	if refs := set.RefMntners(); len(refs) > 0 {
		objs, err := r.e.Src.MembersByRef(r.ctx, name, refs)
		if err != nil {
			return err
		}
		for _, o := range objs {
			switch t := o.(type) {
			case object.AutNum:
				r.out.add(t.AS)
			case object.AsSet:
				if err := r.walk(t.Name, depth+1); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// ExpandPrefixes returns the concrete prefixes denoted by a route-set (its
// prefix-range members, nested sets, and member ASNs' originated routes) or an
// as-set (the union of its member ASNs' originated routes). Enforces MaxPrefixes
// during enumeration and the AFI constraint throughout.
func (e *Expander) ExpandPrefixes(ctx context.Context, n types.SetName) (PrefixSet, error) {
	r := &pfxRun{e: e, ctx: ctx, top: n, out: newPrefixSet(), visited: map[string]bool{}}
	if err := r.walk(n, 0); err != nil {
		return PrefixSet{}, err
	}
	return *r.out, nil
}

type pfxRun struct {
	e       *Expander
	ctx     context.Context
	top     types.SetName
	out     *PrefixSet
	visited map[string]bool
}

func (r *pfxRun) addPrefix(p netip.Prefix) error {
	if !r.e.afiAllows(p) {
		return nil
	}
	r.out.add(p)
	if r.out.Len() > r.e.maxPrefixes() {
		return ErrSetTooLarge{Name: r.top, Count: r.out.Len()}
	}
	return nil
}

func (r *pfxRun) addOriginated(as types.ASN) error {
	routes, err := r.e.Src.OriginatedRoutes(r.ctx, as, r.e.AFI)
	if err != nil {
		return err
	}
	for _, p := range routes {
		if err := r.addPrefix(p); err != nil {
			return err
		}
	}
	return nil
}

func (r *pfxRun) materialize(pr types.PrefixRange) error {
	if !r.e.afiAllows(pr.Prefix) {
		return nil
	}
	ps, err := pr.Materialize(r.e.maxPrefixes())
	if err != nil { // ErrTooManyPrefixes: a single range blew the budget
		return ErrSetTooLarge{Name: r.top, Count: r.e.maxPrefixes()}
	}
	for _, p := range ps {
		if err := r.addPrefix(p); err != nil {
			return err
		}
	}
	return nil
}

func (r *pfxRun) walk(name types.SetName, depth int) error {
	if err := r.ctx.Err(); err != nil {
		return err
	}
	if depth > r.e.maxDepth() {
		return nil
	}
	key := name.Canonical()
	if r.visited[key] {
		return nil
	}
	r.visited[key] = true

	set, err := r.e.Src.GetSet(r.ctx, name)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	}

	// Member kinds map uniformly across as-set and route-set: an ASN yields its
	// originated routes, a nested set recurses, a prefix-range materializes.
	for _, m := range set.SetMembers() {
		switch m.Kind {
		case object.MemberAS:
			if err := r.addOriginated(m.AS); err != nil {
				return err
			}
		case object.MemberSet:
			if err := r.walk(m.Set, depth+1); err != nil {
				return err
			}
		case object.MemberPrefixRange:
			if err := r.materialize(m.Range); err != nil {
				return err
			}
		}
	}

	if refs := set.RefMntners(); len(refs) > 0 {
		objs, err := r.e.Src.MembersByRef(r.ctx, name, refs)
		if err != nil {
			return err
		}
		for _, o := range objs {
			switch t := o.(type) {
			case object.Route:
				if err := r.addPrefix(t.Prefix); err != nil {
					return err
				}
			case object.Route6:
				if err := r.addPrefix(t.Prefix); err != nil {
					return err
				}
			case object.AutNum:
				if err := r.addOriginated(t.AS); err != nil {
					return err
				}
			case object.AsSet:
				if err := r.walk(t.Name, depth+1); err != nil {
					return err
				}
			case object.RouteSet:
				if err := r.walk(t.Name, depth+1); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
