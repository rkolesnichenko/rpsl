package irrdq

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

// multiSource is a resolve.Source over a snapshot's selected registries in
// precedence order: an unscoped set is the first held, routes are the union,
// a set's claimants come from its own registry, and a scoped reference is
// looked up in its registry whether selected or not. In RPKI-aware mode it
// leaves out the routes and route claimants IRRd hides (visible), registry
// by registry, so the pseudo registry's routes stay as they do in IRRd mode.
// It reads only immutable data and is safe for concurrent use.
type multiSource struct {
	snap *Snapshot
	regs []*Registry
}

var _ resolve.Source = multiSource{}

func (m multiSource) GetSet(ctx context.Context, ref types.SetRef) (object.NamedSet, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if ref.IsScoped() {
		r := m.snap.byName[ref.Source()]
		if r == nil {
			return nil, resolve.ErrNotFound
		}
		return r.src.GetSet(ctx, types.Ref(ref.Name()))
	}
	for _, r := range m.regs {
		set, err := r.src.GetSet(ctx, ref)
		if errors.Is(err, resolve.ErrNotFound) {
			continue
		}
		return set, err
	}
	return nil, resolve.ErrNotFound
}

func (m multiSource) OriginatedRoutes(ctx context.Context, as types.ASN, afi types.AFI) ([]netip.Prefix, error) {
	seen := map[netip.Prefix]bool{}
	var out []netip.Prefix
	for _, r := range m.regs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ps, err := r.src.OriginatedRoutes(ctx, as, afi)
		if err != nil {
			return nil, err
		}
		for _, p := range ps {
			p = p.Masked()
			if !seen[p] && m.snap.routeVisible(r, p, as) {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out, nil
}

func (m multiSource) MembersByRef(ctx context.Context, set object.NamedSet) ([]object.Object, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r := m.snap.byName[strings.ToUpper(strings.TrimSpace(set.SetSource()))]
	if r == nil {
		return nil, nil
	}
	objs, err := r.src.MembersByRef(ctx, set)
	if err != nil {
		return nil, err
	}
	out := make([]object.Object, 0, len(objs))
	for _, o := range objs {
		switch t := o.(type) {
		case object.Route:
			if !m.snap.routeVisible(r, t.Prefix, t.Origin) {
				continue
			}
		case object.Route6:
			if !m.snap.routeVisible(r, t.Prefix, t.Origin) {
				continue
			}
		}
		out = append(out, o)
	}
	return out, nil
}

// expander is the snapshot's Expander over regs, for afi. Concurrency is
// cleared: the registries are in memory, so there is no latency to hide,
// and an answer starts no goroutines.
func (snap *Snapshot) expander(regs []*Registry, afi types.AFI) *resolve.Expander {
	e := snap.opts.Expander
	e.Src = multiSource{snap, regs}
	e.AFI = afi
	e.Concurrency = 0
	return &e
}

// rfcMembers is "!i<name>,1" in RFC mode: a route-set's prefix ranges (in
// RPSL notation) or an as-set's AS numbers, sorted as strings; refused is
// why it was not expanded, or "" (nothing for a missing set, a set of
// another class, or a name of neither class).
func (snap *Snapshot) rfcMembers(ctx context.Context, regs []*Registry, name string) (out []string, refused string) {
	n, err := types.ParseSetName(name)
	if err != nil {
		return nil, ""
	}
	e := snap.expander(regs, types.AFIAny)
	switch n.Class() {
	case types.ClassRouteSet:
		rs, err := e.ExpandPrefixRanges(ctx, types.Ref(n))
		if err != nil {
			return nil, rfcRefusal(err)
		}
		for _, r := range rs.List() {
			out = append(out, r.String())
		}
	case types.ClassAsSet:
		as, err := e.ExpandAS(ctx, types.Ref(n))
		if err != nil {
			return nil, rfcRefusal(err)
		}
		for _, a := range as.List() {
			out = append(out, a.String())
		}
	}
	slices.Sort(out)
	return out, ""
}

// rfcPrefixes is "!a" in RFC mode: the prefixes of afi an as-set expands to,
// sorted (prefixCmp); refused as for rfcMembers.
func (snap *Snapshot) rfcPrefixes(ctx context.Context, regs []*Registry, name string, afi types.AFI) (out []netip.Prefix, refused string) {
	n, err := types.ParseSetName(name)
	if err != nil || n.Class() != types.ClassAsSet {
		return nil, ""
	}
	ps, err := snap.expander(regs, afi).ExpandPrefixes(ctx, types.Ref(n))
	if err != nil {
		return nil, rfcRefusal(err)
	}
	out = ps.List()
	slices.SortFunc(out, prefixCmp)
	return out, ""
}

// rfcRefusal is the F message for an expansion error: "" for one that means
// "nothing" (a missing set, a set of another class), internalErrorText for a
// Source's error or a cancelled context.
func rfcRefusal(err error) string {
	var anySet *resolve.AnySetError
	var big *resolve.SetTooLargeError
	switch {
	case err == nil, errors.Is(err, resolve.ErrNotFound), errors.Is(err, resolve.ErrSetClass):
		return ""
	case errors.As(err, &anySet):
		return anySet.Name.String() + " denotes the whole registry: not expanded in RFC mode"
	case errors.As(err, &big):
		return big.Error()
	}
	return internalErrorText
}
