package resolve_test

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

// refSource answers GetSet from sets keyed by SetRef.String(): "RIPE::RS-B"
// answers only the scoped lookup, "RS-B" only the unscoped one. It records
// every lookup, and serves routes from a fixed table.
type refSource struct {
	sets   map[string]object.NamedSet
	routes map[types.ASN][]netip.Prefix
	calls  []string
}

func newRefSource(t *testing.T, sets map[string]string, routes map[types.ASN]string) *refSource {
	t.Helper()
	s := &refSource{sets: map[string]object.NamedSet{}, routes: map[types.ASN][]netip.Prefix{}}
	for key, text := range sets {
		objs := decodeAll(t, []string{text})
		s.sets[key] = objs[0].(object.NamedSet)
	}
	for as, p := range routes {
		s.routes[as] = append(s.routes[as], netip.MustParsePrefix(p))
	}
	return s
}

func (s *refSource) GetSet(_ context.Context, ref types.SetRef) (object.NamedSet, error) {
	s.calls = append(s.calls, ref.String())
	if set, ok := s.sets[ref.String()]; ok {
		return set, nil
	}
	return nil, resolve.ErrNotFound
}

func (s *refSource) OriginatedRoutes(_ context.Context, as types.ASN, _ types.AFI) ([]netip.Prefix, error) {
	return s.routes[as], nil
}

func (s *refSource) MembersByRef(context.Context, object.NamedSet) ([]object.Object, error) {
	return nil, nil
}

func mustRef(t *testing.T, s string) types.SetRef {
	t.Helper()
	r, err := types.ParseSetRef(s)
	if err != nil {
		t.Fatalf("ParseSetRef(%q): %v", s, err)
	}
	return r
}

func refStrings(rs []types.SetRef) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.String()
	}
	return out
}

// The draft's Figure 1: RS-FIRST resolves to AS65000's and AS65001's routes,
// and OTHER's RS-SECOND is never looked up.
func TestDraftFigure1Engine(t *testing.T) {
	src := newRefSource(t, map[string]string{
		"RS-FIRST":        "route-set: RS-FIRST\nmembers: RS-SECOND\nmp-members: RS-LEGACY\nsrc-members: RIPE::RS-SECOND\nsource: EXAMPLE\n",
		"RIPE::RS-SECOND": "route-set: RS-SECOND\nmembers: RS-THIRD\nsource: RIPE\n",
		"RS-SECOND":       "route-set: RS-SECOND\nmembers: AS65002\nsource: OTHER\n",
		"RS-THIRD":        "route-set: RS-THIRD\nmembers: AS65000\nsource: OTHER\n",
		"RS-LEGACY":       "route-set: RS-LEGACY\nmembers: AS65001\nsource: OTHER\n",
	}, map[types.ASN]string{65000: "10.0.0.0/24", 65001: "10.0.1.0/24", 65002: "10.0.2.0/24"})
	got, err := (&resolve.Expander{Src: src}).ExpandPrefixes(context.Background(), mustRef(t, "RS-FIRST"))
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "[10.0.0.0/24 10.0.1.0/24]" {
		t.Errorf("RS-FIRST = %v, want [10.0.0.0/24 10.0.1.0/24]", got)
	}
	if slices.Contains(src.calls, "RS-SECOND") {
		t.Errorf("OTHER's RS-SECOND was looked up: %v", src.calls)
	}
}

// Review Focus 1: a scoped miss never falls back to the unscoped copy.
func TestScopedMissDoesNotFallBack(t *testing.T) {
	src := newRefSource(t, map[string]string{
		"RS-TOP": "route-set: RS-TOP\nmembers: RS-B\nsrc-members: RIPE::RS-B\nsource: EXAMPLE\n",
		"RS-B":   "route-set: RS-B\nmembers: 10.0.0.0/8\nsource: OTHER\n",
	}, nil)
	got, err := (&resolve.Expander{Src: src}).ExpandPrefixRanges(context.Background(), mustRef(t, "RS-TOP"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Len() != 0 || !slices.Equal(refStrings(got.Missing()), []string{"RIPE::RS-B"}) {
		t.Errorf("RS-TOP = %v missing %v; want nothing, missing [RIPE::RS-B]", got, got.Missing())
	}
	if slices.Contains(src.calls, "RS-B") {
		t.Errorf("the unscoped RS-B was looked up: %v", src.calls)
	}
}

// Review Focus 2: a Source that answers a scoped lookup from another registry
// fails the expansion.
func TestCheckSetRefusesWrongRegistry(t *testing.T) {
	src := newRefSource(t, map[string]string{
		"AS-TOP":     "as-set: AS-TOP\nmembers: AS-B\nsrc-members: RIPE::AS-B\nsource: EXAMPLE\n",
		"RIPE::AS-B": "as-set: AS-B\nmembers: AS1\nsource: OTHER\n", // wrong registry
	}, nil)
	_, err := (&resolve.Expander{Src: src}).ExpandAS(context.Background(), mustRef(t, "AS-TOP"))
	if err == nil || !strings.Contains(err.Error(), "RIPE::AS-B") || !strings.Contains(err.Error(), "OTHER") {
		t.Fatalf("err = %v; want a refusal naming RIPE::AS-B and OTHER", err)
	}
	if errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("a wrong-registry answer is a Source fault, not a missing set: %v", err)
	}
}

// Review Focus 5: one name reached scoped and unscoped is two nodes.
func TestSameNameTwoScopes(t *testing.T) {
	// RS-TOP reaches RS-A scoped (src-members:) and, through RS-B, unscoped.
	src := newRefSource(t, map[string]string{
		"RS-TOP":     "route-set: RS-TOP\nmembers: RS-A, RS-B\nsrc-members: RIPE::RS-A\nsource: EXAMPLE\n",
		"RIPE::RS-A": "route-set: RS-A\nmembers: 10.0.0.0/8\nsource: RIPE\n",
		"RS-A":       "route-set: RS-A\nmembers: 172.16.0.0/12\nsource: RADB\n",
		"RS-B":       "route-set: RS-B\nmembers: RS-A\nsource: RADB\n",
	}, nil)
	e := &resolve.Expander{Src: src}
	got, err := e.ExpandPrefixRanges(context.Background(), mustRef(t, "RS-TOP"))
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "[10.0.0.0/8 172.16.0.0/12]" {
		t.Errorf("RS-TOP = %v; want both copies of RS-A", got)
	}
	delete(src.sets, "RS-A")
	got, err = e.ExpandPrefixRanges(context.Background(), mustRef(t, "RS-TOP"))
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "[10.0.0.0/8]" || !slices.Equal(refStrings(got.Missing()), []string{"RS-A"}) {
		t.Errorf("RS-TOP = %v missing %v; want [10.0.0.0/8] missing [RS-A]", got, got.Missing())
	}
}

func TestScopedTop(t *testing.T) {
	src := newRefSource(t, map[string]string{
		"AS-X":       "as-set: AS-X\nmembers: AS2\nsource: RADB\n",
		"RIPE::AS-X": "as-set: AS-X\nmembers: AS1, AS-Y\nsource: RIPE\n",
		"AS-Y":       "as-set: AS-Y\nmembers: AS3\nsource: RADB\n",
	}, nil)
	e := &resolve.Expander{Src: src}
	got, err := e.ExpandAS(context.Background(), mustRef(t, "RIPE::AS-X"))
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "[AS1 AS3]" {
		t.Errorf("RIPE::AS-X = %v, want [AS1 AS3]", got)
	}
	if slices.Contains(src.calls, "RIPE::AS-Y") || !slices.Contains(src.calls, "AS-Y") {
		t.Errorf("the scope cascaded: %v", src.calls)
	}
	_, err = e.ExpandAS(context.Background(), mustRef(t, "ARIN::AS-X"))
	if !errors.Is(err, resolve.ErrNotFound) || !strings.Contains(err.Error(), "ARIN::AS-X") {
		t.Errorf("missing scoped top: err = %v", err)
	}
}

func TestCacheKeysScopes(t *testing.T) {
	src := newRefSource(t, map[string]string{
		"AS-X":       "as-set: AS-X\nmembers: AS2\nsource: RADB\n",
		"RIPE::AS-X": "as-set: AS-X\nmembers: AS1\nsource: RIPE\n",
	}, nil)
	c := resolve.NewCache(src, 0)
	a, _ := c.GetSet(context.Background(), mustRef(t, "RIPE::AS-X"))
	b, _ := c.GetSet(context.Background(), mustRef(t, "AS-X"))
	if a.SetSource() != "RIPE" || b.SetSource() != "RADB" {
		t.Errorf("Cache mixed scopes: %q, %q", a.SetSource(), b.SetSource())
	}
}
