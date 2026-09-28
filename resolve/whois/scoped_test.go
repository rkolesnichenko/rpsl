package whois_test

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/internal/irrtest"
	"github.com/rkolesnichenko/rpsl/resolve/whois"
	"github.com/rkolesnichenko/rpsl/types"
)

func ref(t *testing.T, s string) types.SetRef {
	t.Helper()
	r, err := types.ParseSetRef(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestScopedGetSet(t *testing.T) {
	db := irrtest.New(
		"as-set: AS-X\nmembers: AS1\nsource: RIPE\n",
		"as-set: AS-X\nmembers: AS2\nmbrs-by-ref: ANY\nsource: RADB\n",
		"aut-num: AS3\nas-name: X\nmember-of: AS-X\nmnt-by: M\nsource: RADB\n",
	)
	src := &whois.Source{Addr: db.Whois(t), Sources: []string{"RIPE"}, Timeout: 5 * time.Second}
	ctx := context.Background()
	set, err := src.GetSet(ctx, ref(t, "RADB::AS-X"))
	if err != nil || set.SetSource() != "RADB" {
		t.Fatalf("RADB::AS-X = %v, %v; want RADB's copy although Sources is RIPE", set, err)
	}
	claims, err := src.MembersByRef(ctx, set)
	if err != nil || len(claims) != 1 {
		t.Errorf("claimants of RADB's AS-X = %v, %v; want AS3 (queried in RADB, outside Sources)", claims, err)
	}
	if _, err := src.GetSet(ctx, ref(t, "NOSUCH::AS-X")); !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("unknown registry: err = %v, want ErrNotFound", err)
	}
	bad := &whois.Source{Addr: db.Whois(t), Sources: []string{"NOSUCH"}, Timeout: 5 * time.Second}
	var se *whois.ServerError
	if _, err := bad.GetSet(ctx, ref(t, "AS-X")); !errors.As(err, &se) {
		t.Errorf("an unknown source in Sources: err = %v, want a *ServerError", err)
	}
}

// RIPE answers an unknown source with %ERROR:102 (verified 2026-09-28).
func TestScopedGetSetRIPEUnknownSource(t *testing.T) {
	dial := func(context.Context) (net.Conn, error) {
		c, s := net.Pipe()
		go func() {
			defer s.Close()
			_, _ = bufio.NewReader(s).ReadString('\n')
			_, _ = io.WriteString(s, "%ERROR:102: unknown source\n%\n% \"NOSUCH\" is not a known source.\n")
		}()
		return c, nil
	}
	src := &whois.Source{Addr: "whois.example:43", Dial: dial, Timeout: 5 * time.Second}
	if _, err := src.GetSet(context.Background(), ref(t, "NOSUCH::AS-X")); !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}
