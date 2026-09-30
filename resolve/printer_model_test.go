package resolve_test

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/internal/cfgsim"
	"github.com/rkolesnichenko/rpsl/resolve/internal/routemodel"
	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/resolve/rtconfig"
	"github.com/rkolesnichenko/rpsl/types"
)

// printerActions are the actions the printer model's clauses draw from: the
// policy model's, an AS-path prepend of two ASes (so its order shows), and a
// next-hop. The policy texts carry the IPv4 next-hop; a session of IPv6 is
// evaluated over texts carrying nextHop6 in its place, so every clause's
// next-hop is of its session's family (one of the other family is refused,
// a unit test's business).
var printerActions = append(append([]string(nil), modelActions...),
	"aspath.prepend(AS64500, AS64501)", "next-hop = "+nextHop4)

const (
	nextHop4 = "192.0.2.1"
	nextHop6 = "2001:db8::1"
)

// pevalDecides is what a peval Policy does with a route: the first clause
// whose filter accepts it, and the attributes its actions give the route
// (the model's actions: printerActions).
func pevalDecides(t *testing.T, p peval.Policy, rt routemodel.Route) (bool, cfgsim.Attrs) {
	t.Helper()
	for _, c := range p.Clauses {
		ok, err := routemodel.Match(c.Filter, rt)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			continue
		}
		a := cfgsim.Attrs{LocalPref: -1, MED: -1}
		comms := map[string]bool{}
		for _, x := range rt.Communities {
			if k, ok := cfgsim.CanonCommunity(x); ok {
				comms[k] = true
			}
		}
		for _, act := range c.Actions {
			switch s := act.String(); s {
			case "pref = 10":
				a.LocalPref = 990 // rtconfig's cisco_max_preference, 1000, less 10
			case "med = 5":
				a.MED = 5
			case "community.append(1:3)":
				comms["1:3"] = true
			case "aspath.prepend(AS64500, AS64501)":
				// Each prepend goes in front of what the ones before left.
				a.Prepended = append([]types.ASN{64500, 64501}, a.Prepended...)
			case "next-hop = " + nextHop4, "next-hop = " + nextHop6:
				a.NextHop = strings.TrimPrefix(s, "next-hop = ")
			default:
				t.Fatalf("an action pevalDecides does not know: %q", s)
			}
		}
		for k := range comms {
			a.Communities = append(a.Communities, k)
		}
		sort.Strings(a.Communities)
		return true, a
	}
	return false, cfgsim.Attrs{}
}

func TestPrintersMatchPeval(t *testing.T) {
	ctx := context.Background()
	sessions := 0
	rendered := map[rtconfig.Vendor]int{}
	refused := map[rtconfig.Vendor]map[string]int{}
	prepended, nextHops := map[rtconfig.Vendor]int{}, map[rtconfig.Vendor]map[bool]int{} // accepted routes compared with each; next-hops by family (true: IPv4)
	for _, v := range rtconfig.Vendors() {
		refused[v] = map[string]int{}
		nextHops[v] = map[bool]int{}
	}
	for seed := uint64(0); seed < 200; seed++ {
		r := rand.New(rand.NewPCG(seed, 41))
		texts, _, pol := randomPolicyWith(t, r, seed, printerActions)
		if pol.kind != "import" && pol.kind != "export" {
			continue
		}
		export := pol.kind == "export"
		texts6 := make([]string, len(texts))
		for i, x := range texts {
			texts6[i] = strings.ReplaceAll(x, "next-hop = "+nextHop4, "next-hop = "+nextHop6)
		}
		ev4 := &peval.Evaluator{Src: resolve.NewMemSource(decodeAll(t, texts), "RIPE", "RADB")}
		ev6 := &peval.Evaluator{Src: resolve.NewMemSource(decodeAll(t, texts6), "RIPE", "RADB")}
		for k := 0; k < 4; k++ {
			s := peval.Session{Local: localAS, Peer: types.ASN(firstAS + r.IntN(4)), AF: families[r.IntN(2)]}
			ev := ev4
			if s.AF.AFI == types.AFIv6 {
				ev = ev6
			}
			if s.AF.AFI == types.AFIv4 {
				s.PeerRtr = netip.MustParseAddr(peerRtrs[1+r.IntN(len(peerRtrs)-1)])
				s.LocalRtr = netip.MustParseAddr(localRtrs[1+r.IntN(len(localRtrs)-1)])
			} else {
				s.PeerRtr, s.LocalRtr = netip.MustParseAddr("2001:db8::2"), netip.MustParseAddr("2001:db8::1")
			}
			evaluate := ev.Import
			if export {
				evaluate = ev.Export
			}
			p, err := evaluate(ctx, s)
			if err != nil {
				t.Fatalf("seed %d: %+v: %v", seed, s, err)
			}
			sessions++
			var routes []routemodel.Route
			for tries := 0; len(routes) < 40 && tries < 2000; tries++ {
				if rt := randomRoute(r, s.Peer); prefixAFI(rt.Prefix) == s.AF.AFI {
					routes = append(routes, rt)
				}
			}
			for _, v := range rtconfig.Vendors() {
				label := fmt.Sprintf("seed %d, %v, session %+v", seed, v, s)
				g := &rtconfig.Generator{Vendor: v}
				var b strings.Builder
				write := g.WriteImport
				if export {
					write = g.WriteExport
				}
				err := write(&b, s, p)
				var ue *rtconfig.UnsupportedError
				if errors.As(err, &ue) {
					refused[v][ue.Cause]++
					continue
				}
				if err == nil {
					err = g.WriteSessions(&b)
				}
				if err != nil {
					t.Fatalf("%s: %v", label, err)
				}
				text := b.String()
				if v == rtconfig.BIRD2 {
					if err := cfgsim.BIRDSyntax(text); err != nil && !errors.Is(err, cfgsim.ErrNoBIRD) {
						t.Fatalf("%s: %v\n%s", label, err, text)
					}
				}
				c, err := cfgsim.Parse(v.String(), text)
				if err != nil {
					t.Fatalf("%s: %v\n%s", label, err, text)
				}
				name, ok := c.Attached(s.PeerRtr, export)
				if !ok {
					t.Fatalf("%s: no policy attached\n%s", label, text)
				}
				rendered[v]++
				for _, rt := range routes {
					want, wantAttrs := pevalDecides(t, p, rt)
					got, gotAttrs, err := c.Policy(name, rt)
					if err != nil {
						t.Fatalf("%s: %v\n%s", label, err, text)
					}
					if got != want || want && !reflect.DeepEqual(gotAttrs, wantAttrs) {
						t.Fatalf("%s: route %v: the config gives %v %+v, peval %v %+v\n%s",
							label, rt, got, gotAttrs, want, wantAttrs, text)
					}
					if want && len(wantAttrs.Prepended) > 0 {
						prepended[v]++
					}
					if want && wantAttrs.NextHop != "" {
						nextHops[v][wantAttrs.NextHop == nextHop4]++
					}
				}
			}
		}
	}
	for _, v := range rtconfig.Vendors() {
		t.Logf("%v: rendered %d of %d sessions; refused %v; accepted routes compared with a prepend %d, an IPv4 next-hop %d, an IPv6 next-hop %d",
			v, rendered[v], sessions, refused[v], prepended[v], nextHops[v][true], nextHops[v][false])
		if prepended[v] == 0 || nextHops[v][true] == 0 {
			t.Errorf("%v: no accepted route compared with a prepend (%d) or an IPv4 next-hop (%d)", v, prepended[v], nextHops[v][true])
		}
		if rendered[v]*5 < sessions {
			t.Errorf("%v rendered only %d of %d sessions; refused %v", v, rendered[v], sessions, refused[v])
		}
	}
	// Few seeds give a sampled route an IPv6 next-hop, and BIRD refuses those
	// seeds' regexps; TestBIRDCommunitiesAndActions writes one for BIRD.
	if nextHops[rtconfig.IOS][false]+nextHops[rtconfig.Junos][false]+nextHops[rtconfig.IOSXR][false] == 0 {
		t.Errorf("no accepted route compared with an IPv6 next-hop")
	}
}
