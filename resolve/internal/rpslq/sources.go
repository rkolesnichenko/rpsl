package rpslq

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"time"

	rpslobj "github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

// topSource is bgpq4's SOURCE::SET: the set named and its indirect members
// are looked up in one registry (own), and everything its expansion reaches
// from there — nested sets, the routes of its ASes — in the default sources,
// as bgpq4 sends "!sSOURCE" for that one set and its default "!s" for the rest.
type topSource struct {
	resolve.Source
	top types.SetName
	own resolve.Source
}

func (s *topSource) GetSet(ctx context.Context, n types.SetName) (rpslobj.NamedSet, error) {
	if n == s.top {
		return s.own.GetSet(ctx, n)
	}
	return s.Source.GetSet(ctx, n)
}

func (s *topSource) MembersByRef(ctx context.Context, set rpslobj.NamedSet) ([]rpslobj.Object, error) {
	if set.SetName() == s.top {
		return s.own.MembersByRef(ctx, set)
	}
	return s.Source.MembersByRef(ctx, set)
}

// tracer writes -d's trace: each question rpslq asks its sources, what came
// back and how long it took, and a count at the end.
type tracer struct {
	mu    sync.Mutex
	w     io.Writer
	n     int
	start time.Time
}

func newTracer(w io.Writer) *tracer { return &tracer{w: w, start: time.Now()} }

func (t *tracer) logf(since time.Time, format string, args ...any) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.n++
	fmt.Fprintf(t.w, "rpslq: debug: "+format+" in %s\n", append(args, time.Since(since).Round(time.Millisecond))...)
}

// summary writes the count of questions asked and the time since the start.
func (t *tracer) summary() {
	t.mu.Lock()
	defer t.mu.Unlock()
	fmt.Fprintf(t.w, "rpslq: debug: %s in %s\n", plural(t.n, "query", "queries"), time.Since(t.start).Round(time.Millisecond))
}

// traceSource is a Source whose every call is traced; label names the
// registry a restricted source asks (" [RIPE]"), or is empty.
type traceSource struct {
	src   resolve.Source
	label string
	t     *tracer
}

func (s *traceSource) GetSet(ctx context.Context, n types.SetName) (rpslobj.NamedSet, error) {
	start := time.Now()
	set, err := s.src.GetSet(ctx, n)
	switch {
	case err != nil:
		s.t.logf(start, "GetSet %s%s: %v", n, s.label, err)
	default:
		s.t.logf(start, "GetSet %s%s: %s", n, s.label, describeSet(set))
	}
	return set, err
}

func (s *traceSource) OriginatedRoutes(ctx context.Context, as types.ASN, afi types.AFI) ([]netip.Prefix, error) {
	start := time.Now()
	ps, err := s.src.OriginatedRoutes(ctx, as, afi)
	if err != nil {
		s.t.logf(start, "OriginatedRoutes %s %s%s: %v", as, afi, s.label, err)
	} else {
		s.t.logf(start, "OriginatedRoutes %s %s%s: %s", as, afi, s.label, plural(len(ps), "prefix", "prefixes"))
	}
	return ps, err
}

func (s *traceSource) MembersByRef(ctx context.Context, set rpslobj.NamedSet) ([]rpslobj.Object, error) {
	start := time.Now()
	objs, err := s.src.MembersByRef(ctx, set)
	if err != nil {
		s.t.logf(start, "MembersByRef %s%s: %v", set.SetName(), s.label, err)
	} else {
		s.t.logf(start, "MembersByRef %s%s: %s", set.SetName(), s.label, plural(len(objs), "claimant", "claimants"))
	}
	return objs, err
}

// traceASet traces --server-expand's "!a" queries.
func (t *tracer) traceASet(f func(context.Context, types.SetName, types.AFI) ([]netip.Prefix, error)) func(context.Context, types.SetName, types.AFI) ([]netip.Prefix, error) {
	return func(ctx context.Context, n types.SetName, afi types.AFI) ([]netip.Prefix, error) {
		start := time.Now()
		ps, err := f(ctx, n, afi)
		if err != nil {
			t.logf(start, "ASSetPrefixes %s %s: %v", n, afi, err)
		} else {
			t.logf(start, "ASSetPrefixes %s %s: %s", n, afi, plural(len(ps), "prefix", "prefixes"))
		}
		return ps, err
	}
}

// describeSet says what a fetched set holds: its class, and for an as-set or
// route-set how many members, of them how many nested sets.
func describeSet(set rpslobj.NamedSet) string {
	class := set.SetName().Class().String()
	s, ok := set.(rpslobj.Set)
	if !ok {
		return class
	}
	members, nested := s.SetMembers(), 0
	for _, m := range members {
		if m.Kind == rpslobj.MemberSet {
			nested++
		}
	}
	return fmt.Sprintf("%s, %s (%s)", class, plural(len(members), "member", "members"), plural(nested, "nested set", "nested sets"))
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}
