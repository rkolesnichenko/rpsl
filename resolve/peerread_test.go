package resolve

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/types"
)

// normalize reports whether the answer read Expander.Peer, at any depth:
// PeerAS, a set template in a filter or an AS expression, a regexp naming
// the peer, inside filter-sets too, and with no peer bound as well.
func TestNormalizeReportsPeerRead(t *testing.T) {
	src := corpus(t,
		"as-set: AS-A\nmembers: AS65001\nsource: TEST\n",
		"route: 10.1.0.0/16\norigin: AS65001\nsource: TEST\n",
		"filter-set: FLTR-INNER\nfilter: PeerAS OR AS-A\nsource: TEST\n",
		"filter-set: FLTR-OUTER\nfilter: FLTR-INNER AND {10.0.0.0/8^+}\nsource: TEST\n",
		"filter-set: FLTR-PLAIN\nfilter: AS-A\nsource: TEST\n",
		"as-set: AS65001:AS-T:AS65002\nmembers: AS65001\nsource: TEST\n",
	)
	for _, c := range []struct {
		filter string
		peer   bool
	}{
		{"ANY", false},
		{"AS-A", false},
		{"{10.0.0.0/8^+}", false},
		{"FLTR-PLAIN", false},
		{"<^AS65001>", false},
		{"PeerAS", true},
		{"AS65001:AS-T:PeerAS", true},
		{"<^PeerAS>", true},
		{"FLTR-INNER", true},
		{"FLTR-OUTER", true},
		{"AS-A OR NOT PeerAS", true},
	} {
		f, _ := policy.ParseFilter(c.filter)
		for _, peer := range []types.ASN{0, 65002} {
			e := &Expander{Src: src, Peer: peer}
			_, _, used, err := e.normalize(context.Background(), f)
			if used != c.peer {
				t.Errorf("%s (peer %d): read the peer %v, want %v", c.filter, peer, used, c.peer)
			}
			if !c.peer && err != nil {
				t.Errorf("%s (peer %d): %v", c.filter, peer, err)
			}
		}
	}
}

// Every read of Expander.Peer in the evaluator goes through filterEval.peer,
// which records it; a direct read would let FilterMemo share an answer that
// depends on the peer.
func TestPeerReadsGoThroughAccessor(t *testing.T) {
	direct := regexp.MustCompile(`\bev\.e\.Peer\b|\bn\.ev\.e\.Peer\b|\bn\.noEx\.e\.Peer\b`)
	for _, name := range []string{"expand_more.go", "normalize.go"} {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			if direct.MatchString(line) && !strings.Contains(line, "ev.usedPeer = true") {
				t.Errorf("%s:%d reads Expander.Peer directly: %s", name, i+1, strings.TrimSpace(line))
			}
		}
	}
}
