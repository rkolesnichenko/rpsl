package whois

import (
	"bufio"
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

func netipMust(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// fakeWhois is an in-process plain-WHOIS server: it reads one query line per
// connection, writes a canned response, and closes (matching RIPE-DB behavior).
type fakeWhois struct {
	ln        net.Listener
	responses map[string]string // exact query line -> response text
}

func newFakeWhois(t *testing.T, responses map[string]string) *fakeWhois {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	fw := &fakeWhois{ln: ln, responses: responses}
	go fw.serve()
	t.Cleanup(func() { ln.Close() })
	return fw
}

func (fw *fakeWhois) addr() string { return fw.ln.Addr().String() }

func (fw *fakeWhois) serve() {
	for {
		conn, err := fw.ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			line, err := bufio.NewReader(c).ReadString('\n')
			if err != nil {
				return
			}
			if resp, ok := fw.responses[strings.TrimRight(line, "\r\n")]; ok {
				c.Write([]byte(resp))
			} else {
				c.Write([]byte("% No entries found\n"))
			}
		}(conn)
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

// refSet is a route-set in source whose mbrs-by-ref lists refs.
func refSet(t *testing.T, name, source string, refs ...string) object.RouteSet {
	t.Helper()
	return object.RouteSet{Name: mustSet(t, name), MbrsByRef: refs, Common: object.Common{Source: source}}
}

func TestWhoisGetSet(t *testing.T) {
	fw := newFakeWhois(t, map[string]string{
		"-r -T as-set AS-FOO": "as-set: AS-FOO\nmembers: AS1\nmembers: AS-BAR\nsource: TEST\n",
	})
	src := &Source{Addr: fw.addr(), Timeout: 2 * time.Second}
	set, err := src.GetSet(context.Background(), mustSet(t, "AS-FOO"))
	if err != nil {
		t.Fatalf("GetSet: %v", err)
	}
	if set.SetName().String() != "AS-FOO" || len(set.(object.Set).SetMembers()) != 2 {
		t.Errorf("set = %+v, want AS-FOO with 2 members", set)
	}
}

func TestWhoisGetSetNotFound(t *testing.T) {
	fw := newFakeWhois(t, map[string]string{})
	src := &Source{Addr: fw.addr(), Timeout: 2 * time.Second}
	if _, err := src.GetSet(context.Background(), mustSet(t, "AS-MISSING")); err != resolve.ErrNotFound {
		t.Errorf("err = %v, want resolve.ErrNotFound", err)
	}
}

func TestWhoisOriginatedRoutes(t *testing.T) {
	fw := newFakeWhois(t, map[string]string{
		"-r -T route,route6 -i origin AS10": "route: 198.51.100.0/24\norigin: AS10\nsource: TEST\n\n" +
			"route6: 2001:db8::/32\norigin: AS10\nsource: TEST\n",
	})
	src := &Source{Addr: fw.addr(), Timeout: 2 * time.Second}
	v4, err := src.OriginatedRoutes(context.Background(), 10, types.AFIv4)
	if err != nil || len(v4) != 1 || v4[0].String() != "198.51.100.0/24" {
		t.Fatalf("v4 = %v (err %v), want [198.51.100.0/24]", v4, err)
	}
	all, _ := src.OriginatedRoutes(context.Background(), 10, types.AFIAny)
	if len(all) != 2 {
		t.Errorf("any = %v, want both families", all)
	}
}

// MembersByRef enforces the mntner check through the whois inverse query: only
// the route under an allowed maintainer is returned.
func TestWhoisMembersByRefMntnerCheck(t *testing.T) {
	resp := "route: 198.51.100.0/24\norigin: AS10\nmember-of: RS-REF\nmnt-by: MAINT-GOOD\nsource: TEST\n\n" +
		"route: 203.0.113.0/24\norigin: AS20\nmember-of: RS-REF\nmnt-by: MAINT-EVIL\nsource: TEST\n"
	fw := newFakeWhois(t, map[string]string{
		"-r -T route,route6 -i member-of RS-REF": resp,
	})
	src := &Source{Addr: fw.addr(), Timeout: 2 * time.Second}
	got, err := src.MembersByRef(context.Background(), refSet(t, "RS-REF", "TEST", "MAINT-GOOD"))
	if err != nil {
		t.Fatalf("MembersByRef: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d objects, want 1 (only MAINT-GOOD)", len(got))
	}
	if r, ok := got[0].(object.Route); !ok || r.Prefix.String() != "198.51.100.0/24" {
		t.Errorf("member = %+v, want the MAINT-GOOD route", got[0])
	}
}

// End-to-end: the engine resolves indirect membership through the whois Source.
func TestEngineExpandPrefixesOverWhois(t *testing.T) {
	fw := newFakeWhois(t, map[string]string{
		"-r -T route-set RS-REF": "route-set: RS-REF\nmbrs-by-ref: MAINT-GOOD\nsource: TEST\n",
		"-r -T route,route6 -i member-of RS-REF": "route: 198.51.100.0/24\norigin: AS10\nmember-of: RS-REF\nmnt-by: MAINT-GOOD\nsource: TEST\n\n" +
			"route: 203.0.113.0/24\norigin: AS20\nmember-of: RS-REF\nmnt-by: MAINT-EVIL\nsource: TEST\n",
	})
	src := &Source{Addr: fw.addr(), Timeout: 2 * time.Second}
	e := &resolve.Expander{Src: src}
	got, err := e.ExpandPrefixes(context.Background(), mustSet(t, "RS-REF"))
	if err != nil {
		t.Fatalf("ExpandPrefixes: %v", err)
	}
	if got.Len() != 1 || !got.Has(netipMust("198.51.100.0/24")) {
		t.Errorf("prefixes = %v, want only the MAINT-GOOD route", got.List())
	}
}

// A set defined in several sources is taken from the first in Sources, as irrd
// and MemSource do, whatever order the server lists them in.
func TestWhoisGetSetFollowsSourcePriority(t *testing.T) {
	resp := "as-set: AS-FOO\nmembers: AS1\nsource: RADB\n\nas-set: AS-FOO\nmembers: AS2\nsource: RIPE\n"
	fw := newFakeWhois(t, map[string]string{
		"-s RIPE,RADB -r -T as-set AS-FOO": resp,
		"-s RADB,RIPE -r -T as-set AS-FOO": resp,
		"-r -T as-set AS-FOO":              resp,
	})
	for _, c := range []struct {
		sources []string
		want    string
	}{{[]string{"ripe", "RADB"}, "RIPE"}, {[]string{"RADB", "RIPE"}, "RADB"}, {nil, "RADB"}} {
		src := &Source{Addr: fw.addr(), Sources: c.sources, Timeout: 2 * time.Second}
		set, err := src.GetSet(context.Background(), mustSet(t, "AS-FOO"))
		if err != nil || set.SetSource() != c.want {
			t.Errorf("Sources %v: GetSet = %+v, %v; want the %s set", c.sources, set, err, c.want)
		}
	}
}
