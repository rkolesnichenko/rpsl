package peval

import (
	"context"
	"net/netip"
	"testing"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/types"
)

var v4 = types.AddrFamily{AFI: types.AFIv4, SAFI: types.SAFIUnicast}

func peering(t *testing.T, s string) policy.Peering {
	t.Helper()
	p, diags := policy.ParsePeering(s)
	for _, d := range diags {
		if d.Severity >= ast.Error {
			t.Fatalf("%q: %v", s, d)
		}
	}
	return p
}

func addr(s string) netip.Addr {
	if s == "" {
		return netip.Addr{}
	}
	return netip.MustParseAddr(s)
}

func TestPeeringAS(t *testing.T) {
	v := &Evaluator{Src: fixtureSource(t)}
	for _, c := range []struct {
		peering string
		peer    types.ASN
		want    verdict
	}{
		{"AS2", 2, match},
		{"AS2", 3, noMatch},
		{"AS-PEERS", 3, match},
		{"AS-PEERS", 2, noMatch},
		{"AS-ANY", 42, match},
		{"AS2 OR AS3", 3, match},
		{"AS-PEERS EXCEPT AS3", 3, noMatch},
		{"AS-PEERS EXCEPT AS3", 4, match},
		{"AS-PEERS AND AS4", 4, match},
		{"PRNG-X", 5, match},
		{"PRNG-X", 2, noMatch},
		{"AS-GONE", 2, noMatch},
	} {
		c1 := v.newCall(context.Background(), Session{Local: 1, Peer: c.peer, AF: v4})
		got, _, err := c1.peering(peering(t, c.peering))
		if err != nil || got != c.want {
			t.Errorf("%s for peer AS%d = %v, %v; want %v", c.peering, c.peer, got, err, c.want)
		}
	}
}

// A router constraint decides a match only when the session gives that
// router: an AS that does not match is no match whatever the routers; a
// given router that does not match is no match even if the other side's is
// unknown; a router that is not given leaves the term undecided — never a
// match.
func TestPeeringRouters(t *testing.T) {
	v := &Evaluator{Src: fixtureSource(t)}
	for _, c := range []struct {
		peering           string
		peer              types.ASN
		peerRtr, localRtr string
		want              verdict
		why               string
	}{
		{"AS3 10.0.0.3 at 10.0.0.1", 3, "10.0.0.3", "10.0.0.1", match, ""},
		{"AS3 10.0.0.3 at 10.0.0.1", 3, "", "", undecided, "peer router not given"},
		{"AS3 10.0.0.3 at 10.0.0.1", 3, "10.0.0.3", "", undecided, "local router not given"},
		{"AS3 10.0.0.3 at 10.0.0.1", 3, "10.0.0.9", "", noMatch, ""},
		{"AS3 10.0.0.3 at 10.0.0.1", 2, "", "", noMatch, ""},
		{"AS4 rtr4.example.net at RTRS-LOCAL", 4, "10.0.0.4", "10.0.0.1", match, ""},
		{"AS4 rtr4.example.net at RTRS-LOCAL", 4, "10.0.0.4", "10.0.0.2", noMatch, ""},
		{"AS4 rtr4.example.net", 4, "10.0.0.5", "", noMatch, ""},
		{"AS4 10.0.0.4 OR 10.0.0.8", 4, "10.0.0.8", "", match, ""},
		{"AS4 rtr4.example.net EXCEPT 10.0.0.4", 4, "10.0.0.4", "", noMatch, ""},
		{"AS2 rtr-gone.example.net", 2, "10.0.0.2", "", noMatch, ""},
	} {
		s := Session{Local: 1, Peer: c.peer, PeerRtr: addr(c.peerRtr), LocalRtr: addr(c.localRtr), AF: v4}
		call := v.newCall(context.Background(), s)
		got, why, err := call.peering(peering(t, c.peering))
		if err != nil || got != c.want || why != c.why {
			t.Errorf("%s for %+v = %v %q, %v; want %v %q", c.peering, s, got, why, err, c.want, c.why)
		}
	}
	call := v.newCall(context.Background(), Session{Local: 1, Peer: 2, PeerRtr: addr("10.0.0.2"), AF: v4})
	call.peering(peering(t, "AS2 rtr-gone.example.net"))
	call.peering(peering(t, "AS-GONE"))
	sets, rtrs := call.missingLists()
	if len(sets) != 1 || sets[0].String() != "AS-GONE" || len(rtrs) != 1 || rtrs[0] != "rtr-gone.example.net" {
		t.Errorf("missing = %v, %v; want [AS-GONE], [rtr-gone.example.net]", sets, rtrs)
	}
}

func TestPeeringRegexpIsUndecided(t *testing.T) {
	v := &Evaluator{Src: fixtureSource(t)}
	call := v.newCall(context.Background(), Session{Local: 1, Peer: 2, AF: v4})
	got, why, err := call.peering(policy.PeeringRegexp{Raw: "AS2"})
	if err != nil || got != undecided || why != "peering regexp" {
		t.Errorf("a peering regexp = %v %q, %v; want undecided", got, why, err)
	}
}
