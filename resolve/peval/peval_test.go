package peval

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

var v6 = types.AddrFamily{AFI: types.AFIv6, SAFI: types.SAFIUnicast}

// summary renders a policy for comparison: each clause as "index: actions |
// filter", then each undecided term as "index? why".
func summary(p Policy) string {
	var parts []string
	for _, c := range p.Clauses {
		var acts []string
		for _, a := range c.Actions {
			acts = append(acts, a.String())
		}
		parts = append(parts, fmt.Sprintf("%d: %s | %s", c.Index, strings.Join(acts, "; "), c.Filter))
	}
	for _, u := range p.Undecided {
		parts = append(parts, fmt.Sprintf("%d? %s", u.Index, u.Why))
	}
	return strings.Join(parts, "\n")
}

func TestImport(t *testing.T) {
	v := &Evaluator{Src: fixtureSource(t)}
	for _, c := range []struct {
		s    Session
		want string
	}{
		{Session{Local: 1, Peer: 2, AF: v4},
			"0: pref = 10 | {10.2.0.0/16}\n6:  | {10.2.0.0/16^+}\n4? protocol OSPF"},
		{Session{Local: 1, Peer: 3, AF: v4},
			"1:  | {10.3.0.0/16, 10.4.0.0/16}\n2? peer router not given\n4? protocol OSPF"},
		{Session{Local: 1, Peer: 3, PeerRtr: addr("10.0.0.3"), LocalRtr: addr("10.0.0.1"), AF: v4},
			"1:  | {10.3.0.0/16, 10.4.0.0/16}\n2:  | ANY\n4? protocol OSPF"},
		{Session{Local: 1, Peer: 3, PeerRtr: addr("10.0.0.9"), AF: v4},
			"1:  | {10.3.0.0/16, 10.4.0.0/16}\n4? protocol OSPF"},
		{Session{Local: 1, Peer: 4, PeerRtr: addr("10.0.0.4"), LocalRtr: addr("10.0.0.1"), AF: v4},
			"1:  | {10.3.0.0/16, 10.4.0.0/16}\n7:  | {10.4.0.0/16}\n4? protocol OSPF"},
		{Session{Local: 1, Peer: 5, AF: v4},
			"3:  | {10.99.0.0/16}\n4? protocol OSPF"},
	} {
		p, err := v.Import(context.Background(), c.s)
		if err != nil || summary(p) != c.want {
			t.Errorf("Import(%+v) =\n%s\n(err %v); want\n%s", c.s, summary(p), err, c.want)
		}
	}
}

// An IPv6 session takes nothing from a legacy import:, which is IPv4 only, and
// an IPv4 session nothing from an IPv6 mp-import:.
func TestImportIPv6SessionIgnoresLegacyImport(t *testing.T) {
	v := &Evaluator{Src: fixtureSource(t)}
	p, err := v.Import(context.Background(), Session{Local: 1, Peer: 2, AF: v6})
	if want := "5:  | {2001:db8:2::/48}"; err != nil || summary(p) != want {
		t.Errorf("Import for IPv6 =\n%s\n(err %v); want\n%s", summary(p), err, want)
	}
	p, _ = v.Import(context.Background(), Session{Local: 1, Peer: 2, AF: v4})
	for _, c := range p.Clauses {
		if c.Index == 5 {
			t.Errorf("an IPv4 session took the IPv6 mp-import: %s", summary(p))
		}
	}
}

func TestExportAndDefault(t *testing.T) {
	v := &Evaluator{Src: fixtureSource(t)}
	s := Session{Local: 1, Peer: 2, AF: v4}
	p, err := v.Export(context.Background(), s)
	if want := "0:  | {10.1.0.0/16}"; err != nil || summary(p) != want {
		t.Errorf("Export =\n%s\n(err %v); want %s", summary(p), err, want)
	}
	d, err := v.Default(context.Background(), s)
	if err != nil || len(d.Clauses) != 1 || d.Clauses[0].Actions[0].String() != "pref = 5" ||
		d.Clauses[0].Networks == nil || d.Clauses[0].Networks.String() != "ANY" {
		t.Errorf("Default = %+v, %v; want one clause, pref = 5, networks ANY", d, err)
	}
	if d, _ := v.Default(context.Background(), Session{Local: 1, Peer: 3, AF: v4}); len(d.Clauses) != 0 {
		t.Errorf("Default for AS3 = %+v, want none", d)
	}
}

func TestMissing(t *testing.T) {
	v := &Evaluator{Src: fixtureSource(t)}
	p, err := v.Import(context.Background(), Session{Local: 9, Peer: 2, PeerRtr: addr("10.0.0.2"), AF: v4})
	if err != nil || len(p.Clauses) != 0 {
		t.Fatalf("Import for AS9 = %s, %v; want no clauses", summary(p), err)
	}
	if m := p.Missing(); len(m) != 1 || m[0].String() != "AS-GONE" {
		t.Errorf("Missing() = %v, want [AS-GONE]", m)
	}
	if r := p.MissingRouters(); !reflect.DeepEqual(r, []string{"rtr-gone.example.net"}) {
		t.Errorf("MissingRouters() = %v", r)
	}
}

// nilMisses is a PolicySource that answers what it lacks with no object and
// no error — AutNum and InetRtr with nil, GetSet with a typed nil — as a
// map-backed source written the natural way does. The contracts of
// resolve.PolicySource and resolve.Source treat each as not found.
type nilMisses struct{ resolve.PolicySource }

func (s nilMisses) GetSet(ctx context.Context, ref types.SetRef) (object.NamedSet, error) {
	set, err := s.PolicySource.GetSet(ctx, ref)
	if errors.Is(err, resolve.ErrNotFound) {
		return (*object.AsSet)(nil), nil
	}
	return set, err
}

func (s nilMisses) AutNum(ctx context.Context, as types.ASN, source string) (*object.AutNum, error) {
	an, err := s.PolicySource.AutNum(ctx, as, source)
	if errors.Is(err, resolve.ErrNotFound) {
		return nil, nil
	}
	return an, err
}

func (s nilMisses) InetRtr(ctx context.Context, name, source string) (*object.InetRtr, error) {
	ir, err := s.PolicySource.InetRtr(ctx, name, source)
	if errors.Is(err, resolve.ErrNotFound) {
		return nil, nil
	}
	return ir, err
}

// A nil answer with a nil error is not found, as an error wrapping
// resolve.ErrNotFound is, never a panic: a missing aut-num, set and router.
func TestNilAnswerIsNotFound(t *testing.T) {
	v := &Evaluator{Src: nilMisses{fixtureSource(t)}}
	for _, call := range []func(context.Context, Session) (Policy, error){v.Import, v.Export, v.ImportVia, v.ExportVia} {
		if _, err := call(context.Background(), Session{Local: 77, Peer: 2, AF: v4}); !errors.Is(err, resolve.ErrNotFound) {
			t.Errorf("a missing aut-num: err %v, want ErrNotFound", err)
		}
	}
	if _, err := v.Default(context.Background(), Session{Local: 77, Peer: 2, AF: v4}); !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("Default for a missing aut-num: err %v, want ErrNotFound", err)
	}
	p, err := v.Import(context.Background(), Session{Local: 9, Peer: 2, PeerRtr: addr("10.0.0.2"), AF: v4})
	if err != nil || len(p.Clauses) != 0 {
		t.Fatalf("Import for AS9 = %s, %v; want no clauses", summary(p), err)
	}
	if m := p.Missing(); len(m) != 1 || m[0].String() != "AS-GONE" {
		t.Errorf("Missing() = %v, want [AS-GONE]", m)
	}
	if r := p.MissingRouters(); !reflect.DeepEqual(r, []string{"rtr-gone.example.net"}) {
		t.Errorf("MissingRouters() = %v", r)
	}
}

func TestImportVia(t *testing.T) {
	v := &Evaluator{Src: fixtureSource(t)}
	p, err := v.ImportVia(context.Background(), Session{Local: 10, Peer: 6777, AF: v4})
	want := "0:  | {10.2.0.0/16}\n1? PeerAS beyond a via peering names no single AS"
	if err != nil || summary(p) != want {
		t.Fatalf("ImportVia =\n%s\n(err %v); want\n%s", summary(p), err, want)
	}
	if r := p.Clauses[0].Remote; r == nil || fmt.Sprint(r) != "AS2" {
		t.Errorf("Remote = %v, want AS2", r)
	}
	if p, _ := v.Import(context.Background(), Session{Local: 10, Peer: 6777, AF: v4}); len(p.Clauses) != 0 {
		t.Errorf("Import saw an import-via: %s", summary(p))
	}
}

func TestEvaluatorErrors(t *testing.T) {
	v := &Evaluator{Src: fixtureSource(t)}
	if _, err := v.Import(context.Background(), Session{Local: 77, Peer: 2, AF: v4}); !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("Import for a missing aut-num: err %v, want ErrNotFound", err)
	}
	if _, err := (&Evaluator{}).Import(context.Background(), Session{Local: 1, Peer: 2, AF: v4}); err == nil {
		t.Errorf("Import with no Src: no error")
	}
	if _, err := v.Import(context.Background(), Session{Local: 1, Peer: 2}); err == nil {
		t.Errorf("Import with no AF: no error")
	}
	if _, err := v.Import(context.Background(), Session{Local: 1, AF: v4}); err == nil {
		t.Errorf("Import with no Peer: no error")
	}
}

func TestFilter(t *testing.T) {
	v := &Evaluator{Src: fixtureSource(t)}
	f, diags := policy.ParseFilter("PeerAS OR AS3")
	for _, d := range diags {
		if d.Severity >= ast.Error {
			t.Fatal(d)
		}
	}
	nf, err := v.Filter(context.Background(), f, types.AFIv4, 2)
	if err != nil || nf.String() != "{10.2.0.0/16, 10.3.0.0/16}" {
		t.Errorf("Filter(PeerAS OR AS3, AS2) = %s, %v", nf, err)
	}
}

// One Evaluator serves concurrent calls: each gets what a serial call gets.
func TestEvaluatorConcurrentCalls(t *testing.T) {
	v := &Evaluator{Src: fixtureSource(t), Expander: resolve.Expander{Concurrency: 4}}
	sessions := []Session{
		{Local: 1, Peer: 2, AF: v4}, {Local: 1, Peer: 3, AF: v4}, {Local: 1, Peer: 4, PeerRtr: addr("10.0.0.4"), LocalRtr: addr("10.0.0.1"), AF: v4},
		{Local: 1, Peer: 5, AF: v4}, {Local: 1, Peer: 2, AF: v6},
	}
	want := make([]string, len(sessions))
	for i, s := range sessions {
		p, err := v.Import(context.Background(), s)
		if err != nil {
			t.Fatal(err)
		}
		want[i] = summary(p)
	}
	var wg sync.WaitGroup
	for n := 0; n < 8; n++ {
		for i, s := range sessions {
			wg.Add(1)
			go func() {
				defer wg.Done()
				p, err := v.Import(context.Background(), s)
				if err != nil || summary(p) != want[i] {
					t.Errorf("concurrent Import(%+v) = %s, %v; serially %s", s, summary(p), err, want[i])
				}
			}()
		}
	}
	wg.Wait()
}
