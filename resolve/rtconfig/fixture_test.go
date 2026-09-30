package rtconfig

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/types"
)

// The fixture IRR every rtconfig test evaluates policies over.
var fixtureTexts = []string{
	"route: 10.1.0.0/16\norigin: AS1\nsource: TEST\n",
	"route: 10.2.0.0/16\norigin: AS2\nsource: TEST\n",
	"route: 10.2.128.0/17\norigin: AS2\nsource: TEST\n",
	"route: 10.3.0.0/16\norigin: AS3\nsource: TEST\n",
	"route6: 2001:db8:2::/48\norigin: AS2\nsource: TEST\n",
	"as-set: AS-FOO\nmembers: AS10, AS11\nsource: TEST\n",
}

var (
	v4Session = peval.Session{Local: 1, Peer: 2, LocalRtr: netip.MustParseAddr("10.0.0.1"),
		PeerRtr: netip.MustParseAddr("10.0.0.2"), AF: types.AddrFamily{AFI: types.AFIv4, SAFI: types.SAFIUnicast}}
	v6Session = peval.Session{Local: 1, Peer: 2, LocalRtr: netip.MustParseAddr("2001:db8::1"),
		PeerRtr: netip.MustParseAddr("2001:db8::2"), AF: types.AddrFamily{AFI: types.AFIv6, SAFI: types.SAFIUnicast}}
)

func fixtureSource(t testing.TB, extra ...string) *resolve.MemSource {
	t.Helper()
	var objs []object.Object
	for _, s := range append(append([]string(nil), fixtureTexts...), extra...) {
		raw, _ := rpsl.ParseObject(s)
		o, ds := rpsl.Decode(raw)
		for _, d := range ds {
			if d.Severity >= ast.Error {
				t.Fatalf("fixture %q: %v", s, d)
			}
		}
		objs = append(objs, o)
	}
	return resolve.NewMemSource(objs)
}

// fixturePolicy evaluates AS1's import policy for the IPv4 session with AS2,
// AS1's aut-num holding the given import: values (an "mp-import: " prefix
// makes that line mp-import:).
func fixturePolicy(t testing.TB, imports ...string) (peval.Session, peval.Policy) {
	return fixturePolicyFor(t, v4Session, imports...)
}

func fixturePolicyFor(t testing.TB, s peval.Session, imports ...string) (peval.Session, peval.Policy) {
	t.Helper()
	var b strings.Builder
	b.WriteString("aut-num: AS1\nas-name: ONE\n")
	for _, imp := range imports {
		if strings.HasPrefix(imp, "mp-import: ") {
			b.WriteString(imp + "\n")
			continue
		}
		b.WriteString("import: " + imp + "\n")
	}
	b.WriteString("source: TEST\n")
	v := &peval.Evaluator{Src: fixtureSource(t, b.String())}
	p, err := v.Import(context.Background(), s)
	if err != nil {
		t.Fatalf("peval: %v", err)
	}
	return s, p
}
