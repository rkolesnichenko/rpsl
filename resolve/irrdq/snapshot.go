package irrdq

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/rpki"
	"github.com/rkolesnichenko/rpsl/types"
)

// A Registry is one source's data, immutable once built.
type Registry struct {
	name     string
	serial   uint64
	src      *resolve.MemSource     // sets, claims, aut-nums, inet-rtrs, routes by origin
	routes   []route                // every route and route6, sorted (routeCmp)
	byPrefix map[netip.Prefix][]int // exact prefix -> indexes into routes
	text     bool                   // route text kept (Corpus.KeepRouteText)
}

// route is one route or route6 object of a registry.
type route struct {
	prefix netip.Prefix
	origin types.ASN
	text   string // "" unless kept
}

// NewRegistry builds a registry named name (an IRR source name, canonical
// upper-case) from c, which must hold that one source alone: splitting a
// dump or mirror by source is the loader's job, and objects of any other
// source in c are not this registry's data. They are not removed, either:
// the registry's routes and its unscoped lookups (c.SourceOf(name)) see only
// name's objects, but a scoped lookup or a set's claims built from c would
// still see the others. c must keep policy (Corpus.KeepPolicy or
// IndexPeers): a registry answers "!maut-num" and "!minet-rtr", and a corpus
// that dropped its aut-nums would answer them "not found".
//
// The registry shares nothing mutable with c: c may change afterwards.
func NewRegistry(name string, serial uint64, c *resolve.Corpus) (*Registry, error) {
	n, err := types.ParseSourceName(name)
	if err != nil {
		return nil, fmt.Errorf("irrdq: registry %q: %w", name, err)
	}
	if c == nil {
		return nil, fmt.Errorf("irrdq: registry %s: no Corpus", n)
	}
	if !c.KeepPolicy && !c.IndexPeers {
		return nil, fmt.Errorf("irrdq: registry %s: its Corpus must keep policy (KeepPolicy)", n)
	}
	r := &Registry{name: n, serial: serial, src: c.SourceOf(n), text: c.KeepRouteText, byPrefix: map[netip.Prefix][]int{}}
	for cr := range c.Routes() {
		if cr.Source == n {
			r.routes = append(r.routes, route{cr.Prefix, cr.Origin, cr.Text})
		}
	}
	slices.SortFunc(r.routes, routeCmp)
	for i, rt := range r.routes {
		r.byPrefix[rt.prefix] = append(r.byPrefix[rt.prefix], i)
	}
	return r, nil
}

// routeCmp orders routes IPv4 first, then by address, length and origin. A
// registry holds one route per prefix and origin, so the order is total.
func routeCmp(a, b route) int {
	if c := prefixCmp(a.prefix, b.prefix); c != 0 {
		return c
	}
	switch {
	case a.origin < b.origin:
		return -1
	case a.origin > b.origin:
		return 1
	}
	return 0
}

// prefixCmp orders prefixes IPv4 first, then by address, then length.
func prefixCmp(a, b netip.Prefix) int {
	if a.Addr().Is4() != b.Addr().Is4() {
		if a.Addr().Is4() {
			return -1
		}
		return 1
	}
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c
	}
	return a.Bits() - b.Bits()
}

// Name is the registry's source name, upper-case.
func (r *Registry) Name() string { return r.name }

// Serial is the registry's serial, as "!j" reports it (0: none).
func (r *Registry) Serial() uint64 { return r.serial }

// KeepsRouteText reports whether the registry holds every route's text, so
// that it can answer route objects ("!r", "!mroute").
func (r *Registry) KeepsRouteText() bool { return r.text }

// SnapshotOptions configures a Snapshot.
type SnapshotOptions struct {
	// Default is the registries a session selects until it sends "!s", in
	// precedence order — IRRd's sources_default. nil: every registry, in
	// order.
	Default []string
	// VRPs puts the snapshot in IRRd 4's RPKI-aware mode.
	VRPs *rpki.VRPs
	// RFC answers "!i…,1" and "!a" by resolve.Expander.
	RFC bool
	// Expander holds the limits for RFC mode; its Src is set per query.
	Expander resolve.Expander
	// Version follows "IRRd -- version 4.5.3" in the "!v" answer, in
	// parentheses after "rpsld"; "" leaves just "rpsld".
	Version string
}

// A Snapshot is everything one answer is computed from: registries in
// precedence order and the options. It is immutable.
type Snapshot struct {
	regs   []*Registry
	byName map[string]*Registry
	dflt   []string
	opts   SnapshotOptions
}

// NewSnapshot builds a snapshot of regs, which must have distinct names.
func NewSnapshot(regs []*Registry, opts SnapshotOptions) (*Snapshot, error) {
	s := &Snapshot{regs: slices.Clone(regs), byName: map[string]*Registry{}, opts: opts}
	for _, r := range regs {
		if r == nil {
			return nil, errors.New("irrdq: a nil registry")
		}
		if s.byName[r.name] != nil {
			return nil, fmt.Errorf("irrdq: two registries named %s", r.name)
		}
		s.byName[r.name] = r
	}
	if opts.Default == nil {
		for _, r := range regs {
			s.dflt = append(s.dflt, r.name)
		}
	} else {
		s.dflt = []string{}
		for _, d := range opts.Default {
			n, err := types.ParseSourceName(d)
			if err != nil || s.byName[n] == nil {
				return nil, fmt.Errorf("irrdq: default source %q is no registry", d)
			}
			s.dflt = append(s.dflt, n)
		}
	}
	s.opts.Default = slices.Clone(s.dflt)
	return s, nil
}

// With returns a snapshot whose registry of r's name is r; s is unchanged.
func (s *Snapshot) With(r *Registry) (*Snapshot, error) {
	if r == nil {
		return nil, errors.New("irrdq: With a nil registry")
	}
	if s.byName[r.name] == nil {
		return nil, fmt.Errorf("irrdq: no registry %s to replace", r.name)
	}
	regs := slices.Clone(s.regs)
	for i := range regs {
		if regs[i].name == r.name {
			regs[i] = r
		}
	}
	return NewSnapshot(regs, s.opts)
}

// Registries returns the registries in precedence order.
func (s *Snapshot) Registries() []*Registry { return slices.Clone(s.regs) }
