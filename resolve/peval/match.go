package peval

import (
	"context"
	"errors"
	"net/netip"
	"sort"
	"strings"

	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

// verdict is whether a peering covers the session.
type verdict uint8

const (
	noMatch verdict = iota
	match
	undecided
)

func (v verdict) String() string { return [...]string{"noMatch", "match", "undecided"}[v] }

// call is one evaluation: the session, the Expanders it expands with, what it
// has fetched and what it found missing. Nothing here outlives the call.
type call struct {
	ctx     context.Context
	src     resolve.PolicySource
	e       resolve.Expander // for clause filters: the template's Exclude applies
	m       resolve.Expander // for peering and router matching: Exclude cleared
	s       Session
	asns    map[types.SetName]asMembers
	prngs   map[types.SetName]*resolve.PeeringSet // nil: not found
	rtrSets map[types.SetName]*resolve.RouterSet  // nil: not found
	rtrs    map[string][]netip.Addr               // inet-rtr addresses, by upper-cased name
	missing map[types.SetRef]bool
	noRtr   map[string]bool // inet-rtr names not found, lower-cased
}

type asMembers struct {
	set resolve.ASNSet
	any bool // the set reaches AS-ANY
}

func (c *call) note(r types.SetRef) { c.missing[r] = true }

// missingLists returns the sets and inet-rtr names found missing, sorted.
func (c *call) missingLists() ([]types.SetRef, []string) {
	var sets []types.SetRef
	for r := range c.missing {
		sets = append(sets, r)
	}
	sort.Slice(sets, func(i, j int) bool { return sets[i].String() < sets[j].String() })
	var rtrs []string
	for n := range c.noRtr {
		rtrs = append(rtrs, n)
	}
	sort.Strings(rtrs)
	return sets, rtrs
}

// peering decides whether p covers the session. For undecided it also says why.
func (c *call) peering(p policy.Peering) (verdict, string, error) {
	switch x := p.(type) {
	case policy.PeeringAS:
		ok, err := c.asExpr(x.AS)
		if err != nil || !ok {
			return noMatch, "", err
		}
		v, why := match, ""
		for _, side := range []struct {
			expr policy.RouterExpr
			addr netip.Addr
			why  string
		}{
			{x.Router, c.s.PeerRtr, "peer router not given"},
			{x.AtRouter, c.s.LocalRtr, "local router not given"},
		} {
			if side.expr == nil {
				continue
			}
			if !side.addr.IsValid() {
				if v != undecided {
					v, why = undecided, side.why
				}
				continue
			}
			ok, err := c.router(side.expr, side.addr)
			if err != nil {
				return noMatch, "", err
			}
			if !ok {
				return noMatch, "", nil
			}
		}
		return v, why, nil
	case policy.PeeringSetRef:
		ps, err := c.peeringSet(x.Name)
		if err != nil || ps == nil {
			return noMatch, "", err
		}
		v, why := noMatch, ""
		for _, q := range ps.List() {
			if _, nested := q.(policy.PeeringSetRef); nested {
				continue // ExpandPeerings has replaced every nested set already
			}
			qv, qwhy, err := c.peering(q)
			if err != nil {
				return noMatch, "", err
			}
			switch qv {
			case match:
				return match, "", nil
			case undecided:
				if v == noMatch {
					v, why = undecided, qwhy
				}
			}
		}
		return v, why, nil
	case policy.PeeringRegexp:
		return undecided, "peering regexp", nil
	}
	return undecided, "unknown peering", nil
}

// asExpr reports whether the session's peer is in the AS expression.
func (c *call) asExpr(e policy.ASExpr) (bool, error) {
	switch x := e.(type) {
	case policy.ASNum:
		return x.AS == c.s.Peer, nil
	case policy.ASSetRef:
		return c.inASSet(x.Name)
	case policy.ASSetTemplate:
		return c.inASSet(x.Template.Instantiate(c.s.Peer))
	case policy.ASExprBinary:
		l, err := c.asExpr(x.L)
		if err != nil {
			return false, err
		}
		r, err := c.asExpr(x.R)
		if err != nil {
			return false, err
		}
		switch x.Op {
		case policy.ASOr:
			return l || r, nil
		case policy.ASAnd:
			return l && r, nil
		case policy.ASExcept:
			return l && !r, nil
		}
	}
	return false, nil
}

// inASSet reports whether the peer is a member of the as-set, expanding it
// once per call, with Exclude cleared (see Evaluator). AS-ANY, and a set
// reaching it, hold every AS.
func (c *call) inASSet(n types.SetName) (bool, error) {
	if strings.EqualFold(n.String(), "AS-ANY") {
		return true, nil
	}
	m, ok := c.asns[n]
	if !ok {
		s, err := c.m.ExpandAS(c.ctx, types.Ref(n))
		var anySet *resolve.AnySetError
		switch {
		case errors.As(err, &anySet):
			m = asMembers{any: true}
		case errors.Is(err, resolve.ErrNotFound):
			c.note(types.Ref(n))
		case err != nil:
			return false, err
		default:
			m = asMembers{set: s}
			for _, r := range s.Missing() {
				c.note(r)
			}
		}
		c.asns[n] = m
	}
	return m.any || m.set.Has(c.s.Peer), nil
}

// router reports whether a denotes one of the routers of the expression.
func (c *call) router(e policy.RouterExpr, a netip.Addr) (bool, error) {
	a = a.Unmap()
	switch x := e.(type) {
	case policy.RouterAddr:
		return x.Addr.Unmap() == a, nil
	case policy.RouterName:
		return c.rtrHas(x.Name, a)
	case policy.RouterSetRef:
		rs, err := c.routerSet(x.Name)
		if err != nil || rs == nil {
			return false, err
		}
		for _, id := range rs.List() {
			if ra, ok := id.Addr(); ok {
				if ra.Unmap() == a {
					return true, nil
				}
				continue
			}
			if ok, err := c.rtrHas(id.Name(), a); err != nil || ok {
				return ok, err
			}
		}
		return false, nil
	case policy.RouterExprBinary:
		l, err := c.router(x.L, a)
		if err != nil {
			return false, err
		}
		r, err := c.router(x.R, a)
		if err != nil {
			return false, err
		}
		switch x.Op {
		case policy.RouterAnd:
			return l && r, nil
		case policy.RouterOr:
			return l || r, nil
		case policy.RouterExcept:
			return l && !r, nil
		}
	}
	return false, nil
}

// rtrHas reports whether the inet-rtr named name has the address a, among its
// ifaddr: and interface: addresses. It is looked up once per call; one not
// found has no address and is recorded.
func (c *call) rtrHas(name string, a netip.Addr) (bool, error) {
	key := strings.ToUpper(strings.TrimSpace(name))
	addrs, ok := c.rtrs[key]
	if !ok {
		ir, err := c.src.InetRtr(c.ctx, name, "")
		switch {
		case errors.Is(err, resolve.ErrNotFound):
			c.noRtr[strings.ToLower(key)] = true
		case err != nil:
			return false, err
		default:
			for _, x := range ir.Ifaddr {
				addrs = append(addrs, x.Addr.Unmap())
			}
			for _, x := range ir.Interface {
				addrs = append(addrs, x.Addr.Unmap())
			}
		}
		c.rtrs[key] = addrs
	}
	for _, x := range addrs {
		if x == a {
			return true, nil
		}
	}
	return false, nil
}

func (c *call) peeringSet(n types.SetName) (*resolve.PeeringSet, error) {
	if ps, ok := c.prngs[n]; ok {
		return ps, nil
	}
	ps, err := c.m.ExpandPeerings(c.ctx, types.Ref(n))
	var out *resolve.PeeringSet
	switch {
	case errors.Is(err, resolve.ErrNotFound):
		c.note(types.Ref(n))
	case err != nil:
		return nil, err
	default:
		out = &ps
		for _, r := range ps.Missing() {
			c.note(r)
		}
	}
	c.prngs[n] = out
	return out, nil
}

func (c *call) routerSet(n types.SetName) (*resolve.RouterSet, error) {
	if rs, ok := c.rtrSets[n]; ok {
		return rs, nil
	}
	rs, err := c.m.ExpandRouters(c.ctx, types.Ref(n))
	var out *resolve.RouterSet
	switch {
	case errors.Is(err, resolve.ErrNotFound):
		c.note(types.Ref(n))
	case err != nil:
		return nil, err
	default:
		out = &rs
		for _, r := range rs.Missing() {
			c.note(r)
		}
	}
	c.rtrSets[n] = out
	return out, nil
}

// filter normalizes a term's filter with PeerAS bound to peer (0: unbound).
func (c *call) filter(f policy.Filter, peer types.ASN) (resolve.NormalFilter, error) {
	e := c.e
	e.Peer = peer
	nf, err := e.NormalizeFilter(c.ctx, f)
	if err != nil {
		return resolve.NormalFilter{}, err
	}
	for _, r := range nf.Missing() {
		c.note(r)
	}
	return nf, nil
}
