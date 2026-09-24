package whois

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

// newIRRdModeWhois serves objects the way IRRd's RIPE-style whois parser does
// (whois.radb.net and other IRRd servers): flags are read left to right, and
// "-i attr" takes the next two tokens as the attribute and the value and ends
// the query, so any -T after it is part of nothing. A query without -i looks up
// its last token as a primary key. Matching is case-insensitive.
func newIRRdModeWhois(t *testing.T, objects ...string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				line, err := bufio.NewReader(c).ReadString('\n')
				if err != nil {
					return
				}
				c.Write([]byte(irrdModeAnswer(strings.Fields(line), objects)))
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func irrdModeAnswer(tokens []string, objects []string) string {
	var classes []string
	var attr, value string
query:
	for i := 0; i < len(tokens); i++ {
		switch tokens[i] {
		case "-r", "-B", "-G":
		case "-T", "-s":
			if tokens[i] == "-T" && i+1 < len(tokens) {
				classes = strings.Split(tokens[i+1], ",")
			}
			i++
		case "-i":
			if i+2 >= len(tokens) {
				return "%% ERROR: Missing argument for inverse query.\n"
			}
			attr, value = tokens[i+1], tokens[i+2]
			break query
		default:
			value = tokens[i]
		}
	}
	var out []string
	for _, text := range objects {
		o, _ := rpsl.ParseObject(text)
		if len(classes) > 0 && !containsFold(classes, o.Class()) {
			continue
		}
		if attr == "" && strings.EqualFold(o.Key(), value) {
			out = append(out, text)
			continue
		}
		for _, a := range o.GetAll(attr) {
			for _, it := range a.List() {
				if strings.EqualFold(it.Value, value) {
					out = append(out, text)
				}
			}
		}
	}
	if len(out) == 0 {
		return "%  No entries found for the selected source(s).\n"
	}
	return strings.Join(out, "\n")
}

func containsFold(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

// Against an IRRd server the inverse queries used to put -i before -T, which
// IRRd reads as "origin = -T": every route and every indirect member was lost,
// with no error.
func TestWhoisOverIRRdQueryParser(t *testing.T) {
	addr := newIRRdModeWhois(t,
		"route: 193.0.0.0/21\norigin: AS3333\nsource: TEST\n",
		"route6: 2001:67c:2e8::/48\norigin: AS3333\nsource: TEST\n",
		"as-set: AS-FOO\nmembers: AS1\nmbrs-by-ref: ANY\nsource: TEST\n",
		"aut-num: AS65001\nas-name: X\nmember-of: AS-FOO\nmnt-by: MNT-X\nsource: TEST\n",
	)
	ctx := context.Background()
	src := &Source{Addr: addr, Timeout: 2 * time.Second}
	routes, err := src.OriginatedRoutes(ctx, 3333, types.AFIAny)
	want := []netip.Prefix{netip.MustParsePrefix("193.0.0.0/21"), netip.MustParsePrefix("2001:67c:2e8::/48")}
	if err != nil || !reflect.DeepEqual(routes, want) {
		t.Errorf("OriginatedRoutes(AS3333) = %v, %v; want %v", routes, err, want)
	}
	asns, err := (&resolve.Expander{Src: src}).ExpandAS(ctx, mustSet(t, "AS-FOO"))
	if err != nil || !reflect.DeepEqual(asns.List(), []types.ASN{1, 65001}) {
		t.Errorf("ExpandAS(AS-FOO) = %v, %v; want [AS1 AS65001]", asns.List(), err)
	}
}

// IRRd reports errors as "%% ERROR: …" lines, e.g. for an unknown source in
// Sources. They were discarded as comments, which turned every query into "not
// found" and silently emptied every expansion.
func TestWhoisIRRdErrorIsReported(t *testing.T) {
	const failed = "%% ERROR: One or more selected sources are unavailable.\n"
	fw := newFakeWhois(t, map[string]string{
		"-s BOGUS -r -T as-set AS-FOO":                    failed,
		"-s BOGUS -r -T route,route6 -i origin AS10":      failed,
		"-s BOGUS -r -T route,route6 -i member-of RS-REF": failed,
	})
	src := &Source{Addr: fw.addr(), Sources: []string{"BOGUS"}, Timeout: 2 * time.Second}
	ctx := context.Background()
	_, err1 := src.GetSet(ctx, mustSet(t, "AS-FOO"))
	_, err2 := src.OriginatedRoutes(ctx, 10, types.AFIAny)
	_, err3 := src.MembersByRef(ctx, refSet(t, "RS-REF", "TEST", "ANY"))
	for i, err := range []error{err1, err2, err3} {
		var se *ServerError
		if !errors.As(err, &se) || se.Message != "One or more selected sources are unavailable." ||
			errors.Is(err, resolve.ErrNotFound) {
			t.Errorf("call %d: err = %v, want ServerError with the IRRd message", i, err)
		}
	}
}

// A whois server may return claimants from several IRRs; only the set's own
// source may add members to it.
func TestWhoisMembersByRefSameSource(t *testing.T) {
	addr := newIRRdModeWhois(t,
		"route: 198.51.100.0/24\norigin: AS10\nmember-of: RS-REF\nmnt-by: MNT-A\nsource: RIPE\n",
		"route: 203.0.113.0/24\norigin: AS666\nmember-of: RS-REF\nmnt-by: MNT-A\nsource: RADB\n",
	)
	src := &Source{Addr: addr, Timeout: 2 * time.Second}
	got, err := src.MembersByRef(context.Background(), refSet(t, "RS-REF", "RIPE", "MNT-A"))
	if err != nil || len(got) != 1 {
		t.Fatalf("MembersByRef = %d objects, %v; want the RIPE route only", len(got), err)
	}
	if r, ok := got[0].(object.Route); !ok || r.Prefix.String() != "198.51.100.0/24" {
		t.Errorf("member = %+v, want 198.51.100.0/24", got[0])
	}
}
