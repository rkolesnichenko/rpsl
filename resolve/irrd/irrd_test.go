package irrd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
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
		go fs.handle(conn)
	}
}

func (fs *fakeServer) handle(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.TrimRight(line, "\r\n")
		switch {
		case cmd == "":
			// ignore
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
	ms := set.SetMembers()
	if len(ms) != 2 {
		t.Fatalf("members = %+v, want 2", ms)
	}
	if ms[0].Kind != object.MemberAS || uint32(ms[0].AS) != 1 {
		t.Errorf("member0 = %+v, want AS1", ms[0])
	}
	if ms[1].Kind != object.MemberSet || ms[1].Set.Canonical() != "AS-SUB" {
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
