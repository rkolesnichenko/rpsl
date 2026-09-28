package resolve_test

import (
	"context"
	"slices"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/internal/irrtest"
	"github.com/rkolesnichenko/rpsl/resolve/irrd"
	"github.com/rkolesnichenko/rpsl/resolve/whois"
	"github.com/rkolesnichenko/rpsl/types"
)

// figure1 is draft-ietf-grow-rpsl-registry-scoped-members-00's Figure 1, with
// the routes that make its sets' ASes visible as prefixes.
var figure1 = []string{
	"route-set: RS-FIRST\nmembers: RS-SECOND\nmp-members: RS-LEGACY\nsrc-members: RIPE::RS-SECOND\nsource: EXAMPLE\n",
	"route-set: RS-SECOND\nmembers: RS-THIRD\nsource: RIPE\n",
	"route-set: RS-SECOND\nmembers: AS65002\nsource: OTHER\n",
	"route-set: RS-THIRD\nmembers: AS65000\nsource: OTHER\n",
	"route-set: RS-LEGACY\nmembers: AS65001\nsource: OTHER\n",
	"route: 10.0.0.0/24\norigin: AS65000\nsource: OTHER\n",
	"route: 10.0.1.0/24\norigin: AS65001\nsource: OTHER\n",
	"route: 10.0.2.0/24\norigin: AS65002\nsource: OTHER\n",
}

// fetchLog records the set references an expansion asks its Source for.
type fetchLog struct {
	resolve.Source
	mu   sync.Mutex
	refs []string
}

func (l *fetchLog) GetSet(ctx context.Context, ref types.SetRef) (object.NamedSet, error) {
	l.mu.Lock()
	l.refs = append(l.refs, ref.String())
	l.mu.Unlock()
	return l.Source.GetSet(ctx, ref)
}

// TestDraftFigure1Backends: RS-FIRST resolves to AS65000 and AS65001 in every
// backend, with OTHER outranking RIPE so that only src-members: keeps OTHER's
// RS-SECOND (and AS65002) out — it is never even asked for.
func TestDraftFigure1Backends(t *testing.T) {
	db := irrtest.New(figure1...)
	sources := []string{"EXAMPLE", "OTHER", "RIPE"}
	backends := map[string]resolve.Source{
		"memsource": resolve.NewMemSource(decodeAll(t, figure1), sources...),
		"whois":     &whois.Source{Addr: db.Whois(t), Sources: sources, Timeout: 5 * time.Second},
		"irrd":      &irrd.Source{Addr: db.IRRd(t), Sources: sources, SrcMembers: true, Timeout: 5 * time.Second},
	}
	for name, src := range backends {
		log := &fetchLog{Source: src}
		got, err := (&resolve.Expander{Src: log}).ExpandPrefixes(context.Background(), mustRef(t, "RS-FIRST"))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got.String() != "[10.0.0.0/24 10.0.1.0/24]" {
			t.Errorf("%s: RS-FIRST = %v, want [10.0.0.0/24 10.0.1.0/24]", name, got)
		}
		sort.Strings(log.refs)
		if want := []string{"RIPE::RS-SECOND", "RS-FIRST", "RS-LEGACY", "RS-THIRD"}; !slices.Equal(log.refs, want) {
			t.Errorf("%s: fetched %v, want %v (never OTHER's RS-SECOND)", name, log.refs, want)
		}
	}
}
