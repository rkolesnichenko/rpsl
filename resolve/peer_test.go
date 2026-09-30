package resolve

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/types"
)

func peerCorpus(t *testing.T) *MemSource {
	return corpus(t,
		"route: 10.1.0.0/16\norigin: AS1\nsource: TEST\n",
		"route: 10.2.0.0/16\norigin: AS2\nsource: TEST\n",
		"route: 10.3.0.0/16\norigin: AS3\nsource: TEST\n",
		asSet("AS1:AS-CUST:AS2", "AS1"),
		fltrSet("FLTR-PEER", "PeerAS"),
	)
}

// With a peer bound, PeerAS denotes the peer's routes and a template the set
// it names for the peer, in a filter and inside a filter-set.
func TestPeerBinding(t *testing.T) {
	src := peerCorpus(t)
	ctx := context.Background()
	e := &Expander{Src: src, Peer: 2}
	for filter, want := range map[string]string{
		"PeerAS":             "10.2.0.0/16",
		"PeerAS^+":           "10.2.0.0/16^+",
		"AS1:AS-CUST:PeerAS": "10.1.0.0/16",
		"FLTR-PEER":          "10.2.0.0/16",
		"PeerAS OR AS3":      "10.2.0.0/16 10.3.0.0/16",
	} {
		got, err := e.EvalFilter(ctx, mustFilter(t, filter))
		if err != nil || strings.Join(rangeList(got), " ") != want {
			t.Errorf("EvalFilter(%s) with Peer AS2 = %v, %v; want %s", filter, rangeList(got), err, want)
		}
	}
	tmpl, err := policy.ParseSetNameTemplate("AS1:AS-CUST:PeerAS")
	if err != nil {
		t.Fatal(err)
	}
	expr := policy.FilterASExpr{AS: policy.ASExprBinary{Op: policy.ASOr, L: policy.ASNum{AS: 3}, R: policy.ASSetTemplate{Template: tmpl}}}
	got, err := e.EvalFilter(ctx, expr)
	if want := "10.1.0.0/16 10.3.0.0/16"; err != nil || strings.Join(rangeList(got), " ") != want {
		t.Errorf("EvalFilter(AS3 OR AS1:AS-CUST:PeerAS) = %v, %v; want %s", rangeList(got), err, want)
	}
}

// Unbound, a peer-dependent term is not enumerable, and says why in a way a
// caller can test for.
func TestPeerUnbound(t *testing.T) {
	e := &Expander{Src: peerCorpus(t)}
	for _, filter := range []string{"PeerAS", "AS1:AS-CUST:PeerAS", "FLTR-PEER"} {
		_, err := e.EvalFilter(context.Background(), mustFilter(t, filter))
		var ne *NotEnumerableError
		if !errors.As(err, &ne) || !errors.Is(err, ErrUnboundPeer) {
			t.Errorf("EvalFilter(%s) unbound: err %v, want a *NotEnumerableError wrapping ErrUnboundPeer", filter, err)
		}
	}
	_, err := e.EvalFilter(context.Background(), mustFilter(t, "NOT AS1"))
	if errors.Is(err, ErrUnboundPeer) {
		t.Errorf("EvalFilter(NOT AS1): %v wraps ErrUnboundPeer", err)
	}
}

// Exclude reaches a bound peer only inside a filter-set, as it reaches any AS.
func TestPeerExcluded(t *testing.T) {
	e := &Expander{Src: peerCorpus(t), Peer: 2, Exclude: Exclusion{ASNs: []types.ASN{2}}}
	ctx := context.Background()
	if got, err := e.EvalFilter(ctx, mustFilter(t, "PeerAS")); err != nil || len(rangeList(got)) != 1 {
		t.Errorf("EvalFilter(PeerAS) with the peer excluded = %v, %v; the caller's own term is not excluded", rangeList(got), err)
	}
	if got, err := e.EvalFilter(ctx, mustFilter(t, "FLTR-PEER")); err != nil || len(rangeList(got)) != 0 {
		t.Errorf("EvalFilter(FLTR-PEER) with the peer excluded = %v, %v; want nothing", rangeList(got), err)
	}
}
