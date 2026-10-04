package irrdq

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/object"
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

	// The inverse indexes RIPE-style "-i" reads, over the objects the
	// corpus keeps whole (Corpus.Whole), each list in load order.
	claims   map[string][]object.Object // upper-case set name in member-of -> objects
	byMember map[string][]object.Object // "members " or "mp-members " + normalized item -> sets
	byMbrRef map[string][]object.Object // upper-case mbrs-by-ref maintainer -> sets
}

// route is one route or route6 object of a registry.
type route struct {
	prefix netip.Prefix // its network: host bits, which the decoder warns of, cleared
	origin types.ASN
	text   string // "" unless kept; otherwise ending in a newline
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
			text := cr.Text
			if text != "" && !strings.HasSuffix(text, "\n") {
				text += "\n" // the last object of a dump with no final newline
			}
			r.routes = append(r.routes, route{cr.Prefix.Masked(), cr.Origin, text})
		}
	}
	slices.SortFunc(r.routes, routeCmp)
	for i, rt := range r.routes {
		r.byPrefix[rt.prefix] = append(r.byPrefix[rt.prefix], i)
	}
	r.index(c)
	return r, nil
}

// index builds the inverse indexes from the objects c keeps whole whose
// source is the registry's. An object is listed once under a value however
// often it names it ("member-of: AS-X, AS-X"), as IRRd's SQL search returns
// each object once.
func (r *Registry) index(c *resolve.Corpus) {
	r.claims, r.byMember, r.byMbrRef = map[string][]object.Object{}, map[string][]object.Object{}, map[string][]object.Object{}
	var seen map[string]bool // the object's index entries so far
	add := func(m map[string][]object.Object, k string, o object.Object) {
		id := fmt.Sprintf("%p %s", m, k)
		if k != "" && !seen[id] {
			seen[id] = true
			m[k] = append(m[k], o)
		}
	}
	for o := range c.Whole() {
		raw := o.Raw()
		if raw == nil || sourceOfRaw(raw) != r.name {
			continue
		}
		seen = map[string]bool{}
		for _, a := range raw.GetAll("member-of") {
			for _, it := range a.List() {
				add(r.claims, strings.ToUpper(it.Value), o)
			}
		}
		if _, isSet := o.(object.NamedSet); !isSet {
			continue
		}
		for _, attr := range []string{"members", "mp-members"} {
			for _, a := range raw.GetAll(attr) {
				for _, it := range a.List() {
					if it.Value != "" {
						add(r.byMember, attr+" "+normMember(it.Value), o)
					}
				}
			}
		}
		for _, a := range raw.GetAll("mbrs-by-ref") {
			for _, it := range a.List() {
				add(r.byMbrRef, strings.ToUpper(it.Value), o)
			}
		}
	}
}

// sourceOfRaw is an object's source:, upper-case. Attribute.Value has its
// comment stripped already.
func sourceOfRaw(raw *ast.Object) string {
	a, ok := raw.GetFirst("source")
	if !ok {
		return ""
	}
	return strings.ToUpper(strings.TrimSpace(a.Value))
}

// routeCmp orders routes IPv4 first, then by address, length and origin. A
// registry holds one route per prefix and origin, except where two spellings
// of one network ("192.0.2.1/24", "192.0.2.0/24") are two objects; their text
// breaks the tie, so the order is total and answers deterministic.
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
	return strings.Compare(a.text, b.text)
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
	// precedence order — IRRd's sources_default; a repeated name counts
	// once, where it first appears. nil: every registry, in order.
	Default []string
	// VRPs puts the snapshot in IRRd 4's RPKI-aware mode: every route and
	// route6 of a registry other than rpki.PseudoSource that VRPs.Validate
	// finds Invalid is hidden, and a served one gains IRRd's rpki-ov-state:
	// line. A *rpki.VRPs is immutable, so every snapshot built from these
	// options (With included) shares it.
	VRPs *rpki.VRPs
	// RFC answers "!i…,1" and "!a" by resolve.Expander.
	RFC bool
	// Expander holds the limits (and Exclude) for RFC mode; its Src, AFI and
	// Concurrency are set per query (Concurrency to 0: the registries are in
	// memory). NewSnapshot copies its Exclude lists.
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
			if !slices.Contains(s.dflt, n) { // a repeated name, once (selection)
				s.dflt = append(s.dflt, n)
			}
		}
	}
	s.opts.Default = slices.Clone(s.dflt)
	// The caller's Exclude lists are not the snapshot's: it is immutable.
	s.opts.Expander.Src = nil
	s.opts.Expander.Exclude.Sets = slices.Clone(opts.Expander.Exclude.Sets)
	s.opts.Expander.Exclude.ASNs = slices.Clone(opts.Expander.Exclude.ASNs)
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

// selected is the registries named by names (a session's selection), in
// that order, each once. A name with no registry is skipped: a selection is
// checked when it is made, and With never removes a registry.
func (s *Snapshot) selected(names []string) []*Registry {
	regs := make([]*Registry, 0, len(names))
	for _, n := range names {
		if r := s.byName[n]; r != nil && !slices.Contains(regs, r) {
			regs = append(regs, r)
		}
	}
	return regs
}

// WithSerial returns r's data under serial; r is unchanged.
func (r *Registry) WithSerial(serial uint64) *Registry {
	c := *r
	c.serial = serial
	return &c
}
