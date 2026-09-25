package irrd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/internal/irrtest"
	"github.com/rkolesnichenko/rpsl/types"
)

func mustSetName(t *testing.T, s string) types.SetName {
	t.Helper()
	n, err := types.ParseSetName(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// ASSetPrefixes is the server's expansion of an as-set ("!a"): its members'
// routes, of the family asked for.
func TestASSetPrefixes(t *testing.T) {
	db := irrtest.New(
		"as-set: AS-X\nmembers: AS1, AS-Y\nsource: TEST\n",
		"as-set: AS-Y\nmembers: AS2\nsource: TEST\n",
		"as-set: AS-EMPTY\nmembers: AS9\nsource: TEST\n",
		"route: 192.0.2.0/24\norigin: AS1\nsource: TEST\n",
		"route: 198.51.100.0/24\norigin: AS2\nsource: TEST\n",
		"route6: 2001:db8::/32\norigin: AS2\nsource: TEST\n",
		"route-set: RS-X\nmembers: 10.0.0.0/8\nsource: TEST\n",
	).WithSources("TEST")
	addr := db.IRRd(t)
	for _, pipeline := range []int{0, 8} {
		src := &Source{Addr: addr, Sources: []string{"TEST"}, Pipeline: pipeline, Timeout: 5 * time.Second}
		ctx := context.Background()
		for _, c := range []struct {
			afi  types.AFI
			want string
		}{
			{types.AFIv4, "[192.0.2.0/24 198.51.100.0/24]"},
			{types.AFIv6, "[2001:db8::/32]"},
			{types.AFIAny, "[192.0.2.0/24 198.51.100.0/24 2001:db8::/32]"},
		} {
			got, err := src.ASSetPrefixes(ctx, mustSetName(t, "AS-X"), c.afi)
			if err != nil || fmt.Sprint(got) != c.want {
				t.Errorf("pipeline %d, %v: %v, %v; want %s", pipeline, c.afi, got, err, c.want)
			}
		}
		if got, err := src.ASSetPrefixes(ctx, mustSetName(t, "AS-EMPTY"), types.AFIv4); err != nil || len(got) != 0 {
			t.Errorf("an as-set whose members originate nothing: %v, %v", got, err)
		}
		if _, err := src.ASSetPrefixes(ctx, mustSetName(t, "AS-NOPE"), types.AFIv4); !errors.Is(err, resolve.ErrNotFound) {
			t.Errorf("a missing as-set: %v, want ErrNotFound", err)
		}
		if _, err := src.ASSetPrefixes(ctx, mustSetName(t, "RS-X"), types.AFIv4); !errors.Is(err, resolve.ErrSetClass) {
			t.Errorf("a route-set: %v, want ErrSetClass", err)
		}
		src.Close()
	}
	// The commands IRRd defines: !a4, !a6, and !a for both families.
	var sent []string
	for _, cmd := range db.Commands() {
		if len(cmd) > 1 && cmd[:2] == "!a" {
			sent = append(sent, cmd)
		}
	}
	if fmt.Sprint(sent[:3]) != "[!a4AS-X !a6AS-X !aAS-X]" {
		t.Errorf("commands sent: %v", sent)
	}
}

// A server that refuses "!a" (IRRd 3 has no such query) says so, and an
// answer that is not a prefix list is an error, never a shorter list.
func TestASSetPrefixesRefusedOrMalformed(t *testing.T) {
	srv := newRawServer(t, func(_ int64, c net.Conn, br *bufio.Reader) {
		commands(c, br, func(cmd string) bool {
			switch cmd {
			case "!a4AS-OLD":
				fmt.Fprint(c, "F Unrecognized command\n")
			case "!a4AS-JUNK":
				payload := "192.0.2.0/24 not-a-prefix\n"
				fmt.Fprintf(c, "A%d\n%sC\n", len(payload), payload)
			}
			return true
		})
	})
	src := &Source{Addr: srv.addr(), Timeout: 5 * time.Second}
	ctx := context.Background()
	if _, err := src.ASSetPrefixes(ctx, mustSetName(t, "AS-OLD"), types.AFIv4); !errors.Is(err, ErrQueryRefused) {
		t.Errorf("a refused !a: %v, want ErrQueryRefused", err)
	}
	if _, err := src.ASSetPrefixes(ctx, mustSetName(t, "AS-JUNK"), types.AFIv4); err == nil {
		t.Error("a malformed answer: no error")
	}
}
