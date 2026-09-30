package rtconfig_test

import (
	"context"
	"net/netip"
	"os"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/resolve/rtconfig"
	"github.com/rkolesnichenko/rpsl/types"
)

// Example evaluates AS1's import policy toward AS2 with resolve/peval, then
// writes it as Cisco IOS configuration with resolve/rtconfig.
func Example() {
	var objs []object.Object
	for _, s := range []string{
		"aut-num: AS1\nas-name: ONE\nimport: from AS2 accept AS2\nsource: TEST\n",
		"route: 192.0.2.0/24\norigin: AS2\nsource: TEST\n",
		"route: 198.51.100.0/24\norigin: AS2\nsource: TEST\n",
	} {
		raw, _ := rpsl.ParseObject(s)
		o, _ := rpsl.Decode(raw)
		objs = append(objs, o)
	}
	s := peval.Session{
		Local: 1, Peer: 2,
		LocalRtr: netip.MustParseAddr("10.0.0.1"), PeerRtr: netip.MustParseAddr("10.0.0.2"),
		AF: types.AddrFamily{AFI: types.AFIv4, SAFI: types.SAFIUnicast},
	}
	v := &peval.Evaluator{Src: resolve.NewMemSource(objs)}
	p, err := v.Import(context.Background(), s)
	if err != nil {
		panic(err)
	}

	g := &rtconfig.Generator{Vendor: rtconfig.IOS}
	if err := g.WriteImport(os.Stdout, s, p); err != nil {
		panic(err)
	}
	// Output:
	// !
	// no route-map MyMap_2_1
	// !
	// no ip prefix-list pl100
	// ip prefix-list pl100 seq 5 permit 192.0.2.0/24
	// ip prefix-list pl100 seq 10 permit 198.51.100.0/24
	// !
	// route-map MyMap_2_1 permit 1
	//  match ip address prefix-list pl100
	// !
	// route-map MyMap_2_1 deny 2
	// !
	// router bgp 1
	//  neighbor 10.0.0.2 remote-as 2
	//  neighbor 10.0.0.2 route-map MyMap_2_1 in
	// !
}
