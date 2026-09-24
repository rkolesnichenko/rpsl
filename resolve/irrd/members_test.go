package irrd

import (
	"context"
	"errors"
	"net"
	"reflect"
	"runtime"
	"strings"
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
	rs := parseMembers("AS1 AS2^+ garbage RS-X^24 10.0.0.0/8^+", types.ClassRouteSet)
	if got := summarize(rs); !reflect.DeepEqual(got, []want{
		{object.MemberAS, ""}, {object.MemberAS, "^+"}, {object.MemberInvalid, ""},
		{object.MemberSet, "^24"}, {object.MemberPrefixRange, ""},
	}) {
		t.Errorf("route-set members = %+v", got)
	}
	as := parseMembers("AS1 AS2^+ 10.0.0.0/8", types.ClassAsSet)
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

// A hostile "!i" answer costs memory in proportion to its size, and little
// more: each member is one slot of a slice sized once, its text shared with the
// payload. (strings.Fields and a growing slice held about three times that.)
func TestParseMembersMemory(t *testing.T) {
	for _, tok := range []string{"x ", "AS1 ", "10.0.0.0/8 "} {
		payload := strings.Repeat(tok, 1<<18)
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		m := parseMembers(payload, types.ClassRouteSet)
		runtime.GC()
		runtime.ReadMemStats(&after)
		live := int64(after.HeapAlloc) - int64(before.HeapAlloc)
		if per := live / int64(len(m)); len(m) != 1<<18 || per > 128 {
			t.Errorf("%q: %d members, %d bytes live each; want %d and at most 128", tok, len(m), per, 1<<18)
		}
		runtime.KeepAlive(m)
	}
	got := parseMembers(" AS1\tAS-FOO\n\r10.0.0.0/8  ", types.ClassRouteSet)
	var raws []string
	for _, m := range got {
		raws = append(raws, m.Raw)
	}
	if strings.Join(raws, ",") != "AS1,AS-FOO,10.0.0.0/8" {
		t.Errorf("parseMembers split into %q", raws)
	}
}
