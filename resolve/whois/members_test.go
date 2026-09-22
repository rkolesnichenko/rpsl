package whois

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

// RIPE serves comma-separated lists (RFC 2622 §2). Before the fix this
// expanded to [AS0].
func TestEngineExpandsCommaMembersOverWhois(t *testing.T) {
	fw := newFakeWhois(t, map[string]string{
		"-r -T as-set,route-set AS-FOO": "as-set: AS-FOO\nmembers: AS1, AS2\nmembers: AS-BAR\nsource: TEST\n",
		"-r -T as-set,route-set AS-BAR": "as-set: AS-BAR\nmembers: AS3,\n  AS4\nsource: TEST\n",
	})
	e := &resolve.Expander{Src: &Source{Addr: fw.addr(), Timeout: 2 * time.Second}}
	got, err := e.ExpandAS(context.Background(), mustSet(t, "AS-FOO"))
	if err != nil || !reflect.DeepEqual(got.List(), []types.ASN{1, 2, 3, 4}) {
		t.Errorf("ExpandAS(AS-FOO) = %v, %v; want [AS1 AS2 AS3 AS4]", got.List(), err)
	}
}

// List-valued mbrs-by-ref, member-of and mnt-by all take part in the mntner
// check: the first route is maintained by one of the listed mntners.
func TestWhoisMembersByRefListValues(t *testing.T) {
	resp := "route: 198.51.100.0/24\norigin: AS10\nmember-of: RS-OTHER, RS-REF\nmnt-by: MAINT-X, MAINT-GOOD\nsource: TEST\n\n" +
		"route: 203.0.113.0/24\norigin: AS20\nmember-of: RS-REF\nmnt-by: MAINT-EVIL, MAINT-WORSE\nsource: TEST\n"
	fw := newFakeWhois(t, map[string]string{
		"-r -T route,route6,aut-num,as-set -i member-of RS-REF": resp,
	})
	src := &Source{Addr: fw.addr(), Timeout: 2 * time.Second}
	got, err := src.MembersByRef(context.Background(), refSet(t, "RS-REF", "TEST", "MAINT-A", "MAINT-GOOD"))
	if err != nil {
		t.Fatalf("MembersByRef: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d objects, want 1 (the MAINT-GOOD route)", len(got))
	}
	if r, ok := got[0].(object.Route); !ok || r.Prefix.String() != "198.51.100.0/24" {
		t.Errorf("member = %+v, want 198.51.100.0/24", got[0])
	}
}

// A zero SetName is refused before any bytes reach the wire.
func TestWhoisRejectsZeroSetName(t *testing.T) {
	src := &Source{Dial: func(context.Context) (net.Conn, error) {
		t.Error("dialed for a zero SetName")
		return nil, errors.New("unreachable")
	}}
	if _, err := src.GetSet(context.Background(), types.SetName{}); err == nil {
		t.Error("GetSet(zero SetName) succeeded, want an error")
	}
	if _, err := src.MembersByRef(context.Background(), object.RouteSet{MbrsByRef: []string{"ANY"}}); err == nil {
		t.Error("MembersByRef(zero SetName) succeeded, want an error")
	}
	if _, err := src.MembersByRef(context.Background(), nil); err == nil {
		t.Error("MembersByRef(nil) succeeded, want an error")
	}
}
