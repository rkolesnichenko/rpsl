package peval

import (
	"testing"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
)

// fixture is a small IRR: AS1's policies toward AS2 … AS5 and a route server,
// with the sets, routers and routes they name.
var fixture = []string{
	`aut-num: AS1
as-name: ONE
import: from AS2 action pref = 10; accept AS2
import: from AS-PEERS accept AS-PEERS
import: from AS3 10.0.0.3 at 10.0.0.1 accept ANY
import: from PRNG-X accept {10.99.0.0/16}
import: protocol OSPF into BGP4 from AS2 accept ANY
mp-import: afi ipv6.unicast from AS2 accept AS2
import: from AS2 accept PeerAS^+
import: from AS4 rtr4.example.net at RTRS-LOCAL accept AS4
export: to AS2 announce AS1
default: to AS2 action pref = 5; networks ANY
source: TEST
`,
	`aut-num: AS9
as-name: NINE
import: from AS-GONE accept ANY
import: from AS2 rtr-gone.example.net accept ANY
source: TEST
`,
	`aut-num: AS10
as-name: TEN
import-via: AS6777 from AS2 accept PeerAS
import-via: AS6777 from AS-PEERS accept PeerAS
source: TEST
`,
	"route: 10.1.0.0/16\norigin: AS1\nsource: TEST\n",
	"route: 10.2.0.0/16\norigin: AS2\nsource: TEST\n",
	"route6: 2001:db8:2::/48\norigin: AS2\nsource: TEST\n",
	"route: 10.3.0.0/16\norigin: AS3\nsource: TEST\n",
	"route: 10.4.0.0/16\norigin: AS4\nsource: TEST\n",
	"as-set: AS-PEERS\nmembers: AS3, AS4\nsource: TEST\n",
	"peering-set: PRNG-X\npeering: AS5\nsource: TEST\n",
	"inet-rtr: rtr4.example.net\nlocal-as: AS4\nifaddr: 10.0.0.4 masklen 30\nsource: TEST\n",
	"rtr-set: RTRS-LOCAL\nmembers: 10.0.0.1\nsource: TEST\n",
}

func fixtureSource(t *testing.T) *resolve.MemSource {
	t.Helper()
	var objs []object.Object
	for _, s := range fixture {
		raw, _ := rpsl.ParseObject(s)
		o, ds := rpsl.Decode(raw)
		for _, d := range ds {
			if d.Severity >= ast.Error {
				t.Fatalf("fixture %q: %v", s[:20], d)
			}
		}
		objs = append(objs, o)
	}
	return resolve.NewMemSource(objs)
}
