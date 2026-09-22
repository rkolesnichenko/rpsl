package irrd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

// frame builds an IRRd "A<len>\n<payload>C\n" data response for the given data.
func frame(data string) string {
	payload := data + "\n"
	return fmt.Sprintf("A%d\n%sC\n", len(payload), payload)
}

// fakeServer is an in-process IRRd query-protocol server replaying canned
// responses, so tests exercise the real dial + framing path without a network.
type fakeServer struct {
	ln        net.Listener
	responses map[string]string // exact command -> raw response frame ("" entries use "D\n")
	conns     atomic.Int64      // total accepted connections
}

func newFakeServer(t *testing.T, responses map[string]string) *fakeServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	fs := &fakeServer{ln: ln, responses: responses}
	go fs.serve()
	t.Cleanup(func() { ln.Close() })
	return fs
}

func (fs *fakeServer) addr() string { return fs.ln.Addr().String() }

func (fs *fakeServer) serve() {
	for {
		conn, err := fs.ln.Accept()
		if err != nil {
			return
		}
		fs.conns.Add(1)
		go fs.handle(conn)
	}
}

// handle models real IRRd: without "!!" (persistent mode) the server answers one
// command and closes the connection, as whois.radb.net does.
func (fs *fakeServer) handle(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	persistent := false
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.TrimRight(line, "\r\n")
		switch {
		case cmd == "":
			continue
		case cmd == "!!":
			persistent = true // no response
			continue
		case strings.HasPrefix(cmd, "!s"):
			fmt.Fprint(conn, "C\n") // source set acknowledged
		case strings.HasPrefix(cmd, "!q"):
			return
		default:
			if resp, ok := fs.responses[cmd]; ok {
				fmt.Fprint(conn, resp)
			} else {
				fmt.Fprint(conn, "D\n") // not found
			}
		}
		if !persistent {
			return
		}
	}
}

func mustSet(t *testing.T, s string) types.SetName {
	t.Helper()
	n, err := types.ParseSetName(s)
	if err != nil {
		t.Fatalf("ParseSetName(%q): %v", s, err)
	}
	return n
}

func TestGetSetParsesMembers(t *testing.T) {
	fs := newFakeServer(t, map[string]string{
		"!iAS-TOP": frame("AS1 AS-SUB"),
	})
	src := &Source{Addr: fs.addr(), Timeout: 2 * time.Second}
	set, err := src.GetSet(context.Background(), mustSet(t, "AS-TOP"))
	if err != nil {
		t.Fatalf("GetSet: %v", err)
	}
	ms := set.(object.Set).SetMembers()
	if len(ms) != 2 {
		t.Fatalf("members = %+v, want 2", ms)
	}
	if ms[0].Kind != object.MemberAS || uint32(ms[0].AS) != 1 {
		t.Errorf("member0 = %+v, want AS1", ms[0])
	}
	if ms[1].Kind != object.MemberSet || ms[1].Set.String() != "AS-SUB" {
		t.Errorf("member1 = %+v, want set AS-SUB", ms[1])
	}
}

func TestGetSetNotFound(t *testing.T) {
	fs := newFakeServer(t, map[string]string{})
	src := &Source{Addr: fs.addr(), Timeout: 2 * time.Second}
	_, err := src.GetSet(context.Background(), mustSet(t, "AS-MISSING"))
	if !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("err = %v, want resolve.ErrNotFound", err)
	}
}

func TestOriginatedRoutesAFI(t *testing.T) {
	fs := newFakeServer(t, map[string]string{
		"!gAS1": frame("10.0.0.0/8 192.0.2.0/24"),
		"!6AS1": frame("2001:db8::/32"),
	})
	src := &Source{Addr: fs.addr(), Timeout: 2 * time.Second}

	v4, err := src.OriginatedRoutes(context.Background(), 1, types.AFIv4)
	if err != nil || len(v4) != 2 {
		t.Fatalf("v4 = %v (err %v), want 2 prefixes", v4, err)
	}
	v6, err := src.OriginatedRoutes(context.Background(), 1, types.AFIv6)
	if err != nil || len(v6) != 1 {
		t.Fatalf("v6 = %v (err %v), want 1 prefix", v6, err)
	}
	any, err := src.OriginatedRoutes(context.Background(), 1, types.AFIAny)
	if err != nil || len(any) != 3 {
		t.Fatalf("any = %v (err %v), want 3 prefixes", any, err)
	}
}

// No v6 routes (D response) is an empty result, not an error.
func TestOriginatedRoutesEmptyFamily(t *testing.T) {
	fs := newFakeServer(t, map[string]string{
		"!gAS1": frame("10.0.0.0/8"),
		// no !6AS1 entry -> server returns D
	})
	src := &Source{Addr: fs.addr(), Timeout: 2 * time.Second}
	got, err := src.OriginatedRoutes(context.Background(), 1, types.AFIAny)
	if err != nil {
		t.Fatalf("OriginatedRoutes: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("got %v, want just the v4 prefix", got)
	}
}

// End-to-end: the pure engine drives the live backend to expand a nested as-set.
func TestEngineOverIRRdSource(t *testing.T) {
	fs := newFakeServer(t, map[string]string{
		"!iAS-TOP": frame("AS1 AS-SUB"),
		"!iAS-SUB": frame("AS2 AS3"),
	})
	src := &Source{Addr: fs.addr(), Timeout: 2 * time.Second}
	e := &resolve.Expander{Src: src}
	got, err := e.ExpandAS(context.Background(), mustSet(t, "AS-TOP"))
	if err != nil {
		t.Fatalf("ExpandAS: %v", err)
	}
	if got.Len() != 3 || !got.Has(1) || !got.Has(2) || !got.Has(3) {
		t.Errorf("ExpandAS = %v, want {1,2,3}", got.List())
	}
}

func TestEngineExpandPrefixesOverIRRd(t *testing.T) {
	fs := newFakeServer(t, map[string]string{
		"!iRS-X": frame("192.0.2.0/24 AS1"),
		"!gAS1":  frame("10.0.0.0/8"),
		// !6AS1 -> D (no v6)
	})
	src := &Source{Addr: fs.addr(), Timeout: 2 * time.Second}
	e := &resolve.Expander{Src: src}
	got, err := e.ExpandPrefixes(context.Background(), mustSet(t, "RS-X"))
	if err != nil {
		t.Fatalf("ExpandPrefixes: %v", err)
	}
	if got.Len() != 2 {
		t.Errorf("prefixes = %v, want the /24 plus AS1's 10.0.0.0/8", got.List())
	}
}

// TestKeepAliveReusesConnection: with KeepAlive, multiple queries ride one
// persistent connection instead of redialing per query.
func TestKeepAliveReusesConnection(t *testing.T) {
	fs := newFakeServer(t, map[string]string{
		"!gAS1": frame("10.0.0.0/8"),
		"!gAS2": frame("192.0.2.0/24"),
		"!gAS3": frame("198.51.100.0/24"),
	})
	src := &Source{Addr: fs.addr(), Timeout: 2 * time.Second, KeepAlive: true}
	defer src.Close()
	for _, as := range []types.ASN{1, 2, 3} {
		if _, err := src.OriginatedRoutes(context.Background(), as, types.AFIv4); err != nil {
			t.Fatalf("OriginatedRoutes(AS%d): %v", as, err)
		}
	}
	if got := fs.conns.Load(); got != 1 {
		t.Errorf("accepted %d connections, want 1 (pooled reuse)", got)
	}
}

// TestKeepAliveNotFoundKeepsConnection: a 'D' (not found) is a normal result,
// so the connection stays pooled and is reused.
func TestKeepAliveNotFoundKeepsConnection(t *testing.T) {
	fs := newFakeServer(t, map[string]string{"!gAS1": frame("10.0.0.0/8")})
	src := &Source{Addr: fs.addr(), Timeout: 2 * time.Second, KeepAlive: true}
	defer src.Close()
	// AS2 has no v4 routes -> server returns D -> empty, not an error.
	if _, err := src.OriginatedRoutes(context.Background(), 2, types.AFIv4); err != nil {
		t.Fatalf("OriginatedRoutes(AS2): %v", err)
	}
	if _, err := src.OriginatedRoutes(context.Background(), 1, types.AFIv4); err != nil {
		t.Fatalf("OriginatedRoutes(AS1): %v", err)
	}
	if got := fs.conns.Load(); got != 1 {
		t.Errorf("accepted %d connections, want 1 (D must not discard the conn)", got)
	}
}

// TestKeepAliveEndToEnd drives the engine through a pooled source.
func TestKeepAliveEndToEnd(t *testing.T) {
	fs := newFakeServer(t, map[string]string{
		"!iAS-TOP": frame("AS1 AS-SUB"),
		"!iAS-SUB": frame("AS2 AS3"),
	})
	src := &Source{Addr: fs.addr(), Timeout: 2 * time.Second, KeepAlive: true}
	defer src.Close()
	e := &resolve.Expander{Src: src}
	got, err := e.ExpandAS(context.Background(), mustSet(t, "AS-TOP"))
	if err != nil {
		t.Fatalf("ExpandAS: %v", err)
	}
	if got.Len() != 3 {
		t.Errorf("ExpandAS = %v, want {1,2,3}", got.List())
	}
	if c := fs.conns.Load(); c != 1 {
		t.Errorf("accepted %d connections, want 1", c)
	}
}

// IRRd answers "!i" for an existing set with no members with D, as for a
// missing one; "!m" tells them apart, so an empty set is empty, not missing.
func TestGetSetEmptyIsNotMissing(t *testing.T) {
	fs := newFakeServer(t, map[string]string{
		"!mas-set,AS-EMPTY":    frame("as-set: AS-EMPTY\nsource: RADB"),
		"!mroute-set,RS-EMPTY": frame("route-set: RS-EMPTY\nsource: RADB"),
	})
	src := &Source{Addr: fs.addr(), Timeout: 2 * time.Second}
	for _, name := range []string{"AS-EMPTY", "RS-EMPTY"} {
		set, err := src.GetSet(context.Background(), mustSet(t, name))
		if err != nil || set == nil || len(set.(object.Set).SetMembers()) != 0 || set.SetName() != mustSet(t, name) {
			t.Errorf("GetSet(%s) = %+v, %v; want the empty set", name, set, err)
		}
	}
	if _, err := src.GetSet(context.Background(), mustSet(t, "AS-GONE")); !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("GetSet(AS-GONE) err = %v, want ErrNotFound", err)
	}
	asns, err := (&resolve.Expander{Src: src}).ExpandAS(context.Background(), mustSet(t, "AS-EMPTY"))
	if err != nil || asns.Len() != 0 {
		t.Errorf("ExpandAS(AS-EMPTY) = %v, %v; want empty, no error", asns, err)
	}
}

// A route answer holding something other than prefixes is an error, not a
// shorter list.
func TestRoutesRejectJunk(t *testing.T) {
	fs := newFakeServer(t, map[string]string{
		"!gAS1": frame("10.0.0.0/8 junk"),
		"!6AS2": frame("2001:db8::/32 10.0.0.0/8/8"),
	})
	src := &Source{Addr: fs.addr(), Timeout: 2 * time.Second}
	if got, err := src.OriginatedRoutes(context.Background(), 1, types.AFIv4); err == nil {
		t.Errorf("!g with junk = %v, want an error", got)
	}
	if got, err := src.OriginatedRoutes(context.Background(), 2, types.AFIv6); err == nil {
		t.Errorf("!6 with junk = %v, want an error", got)
	}
}
