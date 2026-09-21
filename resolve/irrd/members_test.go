package irrd

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

// !i payload tokens are parsed with the set's class rules: range operators and
// prefixes only in route-sets, and anything unparseable is MemberInvalid —
// never the zero-valued MemberAS the engine used to read as AS0.
func TestParseMembersByContainerClass(t *testing.T) {
	type want struct {
		kind object.MemberKind
		op   string
	}
	summarize := func(ms []object.SetMember) []want {
		var out []want
		for _, m := range ms {
			out = append(out, want{m.Kind, m.Op.String()})
		}
		return out
	}
	rs := parseMembers("AS1 AS2^+ garbage RS-X^24 10.0.0.0/8^+", types.RouteSet)
	if got := summarize(rs); !reflect.DeepEqual(got, []want{
		{object.MemberAS, ""}, {object.MemberAS, "^+"}, {object.MemberInvalid, ""},
		{object.MemberSet, "^24"}, {object.MemberPrefixRange, ""},
	}) {
		t.Errorf("route-set members = %+v", got)
	}
	as := parseMembers("AS1 AS2^+ 10.0.0.0/8", types.AsSet)
	if got := summarize(as); !reflect.DeepEqual(got, []want{
		{object.MemberAS, ""}, {object.MemberInvalid, ""}, {object.MemberInvalid, ""},
	}) {
		t.Errorf("as-set members = %+v", got)
	}
}

// The review's repro: an unparseable !i token used to expand to AS0.
func TestEngineSkipsUnparseableIRRdTokens(t *testing.T) {
	fs := newFakeServer(t, map[string]string{"!iAS-X": frame("AS1 garbage AS2^+")})
	e := &resolve.Expander{Src: &Source{Addr: fs.addr(), Timeout: 2 * time.Second}}
	got, err := e.ExpandAS(context.Background(), mustSet(t, "AS-X"))
	if err != nil || !reflect.DeepEqual(got.List(), []types.ASN{1}) {
		t.Errorf("ExpandAS(AS-X) = %v, %v; want [AS1]", got.List(), err)
	}
}

// A zero SetName is refused before any bytes reach the wire.
func TestGetSetRejectsZeroName(t *testing.T) {
	src := &Source{Dial: func(context.Context) (net.Conn, error) {
		t.Error("dialed for a zero SetName")
		return nil, errors.New("unreachable")
	}}
	if _, err := src.GetSet(context.Background(), types.SetName{}); err == nil {
		t.Error("GetSet(zero SetName) succeeded, want an error")
	}
}
