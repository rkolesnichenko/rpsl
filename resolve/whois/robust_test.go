package whois

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

// A server error other than 101 ("no entries") is an error, never "no data":
// rate limiting must not silently shrink a filter.
func TestWhoisServerErrorsAreReported(t *testing.T) {
	denied := "% This is the RIPE Database query service.\n\n%ERROR:201: access denied for 192.0.2.1\n%\n% Sorry.\n"
	fw := newFakeWhois(t, map[string]string{
		"-r -T as-set,route-set AS-FOO":                         denied,
		"-r -i origin -T route,route6 AS10":                     denied,
		"-r -i member-of -T route,route6,aut-num,as-set RS-REF": denied,
	})
	src := &Source{Addr: fw.addr()}
	ctx := context.Background()
	_, err1 := src.GetSet(ctx, mustSet(t, "AS-FOO"))
	_, err2 := src.OriginatedRoutes(ctx, 10, types.AFIAny)
	_, err3 := src.MembersByRef(ctx, mustSet(t, "RS-REF"), []string{"ANY"})
	for i, err := range []error{err1, err2, err3} {
		var se ErrServer
		if !errors.As(err, &se) || se.Code != 201 || errors.Is(err, resolve.ErrNotFound) {
			t.Errorf("call %d: err = %v, want ErrServer{201} (not ErrNotFound)", i, err)
		}
	}
}

func TestWhoisNoEntriesIsNotFound(t *testing.T) {
	none := "%ERROR:101: no entries found\n%\n% No entries found in source RIPE.\n"
	fw := newFakeWhois(t, map[string]string{
		"-r -T as-set,route-set AS-FOO":     none,
		"-r -i origin -T route,route6 AS10": none,
		"-r -T as-set,route-set AS-BAR":     "%WARNING:902: useless IP flag passed\nas-set: AS-BAR\nmembers: AS1\nsource: TEST\n",
	})
	src := &Source{Addr: fw.addr()}
	ctx := context.Background()
	if _, err := src.GetSet(ctx, mustSet(t, "AS-FOO")); !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("GetSet err = %v, want ErrNotFound", err)
	}
	if routes, err := src.OriginatedRoutes(ctx, 10, types.AFIAny); err != nil || len(routes) != 0 {
		t.Errorf("OriginatedRoutes = %v, %v; want empty, nil", routes, err)
	}
	if set, err := src.GetSet(ctx, mustSet(t, "AS-BAR")); err != nil || len(set.SetMembers()) != 1 {
		t.Errorf("a %%WARNING line broke GetSet: %v, %v", set, err)
	}
}

// A server that accepts and never replies is abandoned when ctx is cancelled.
func TestWhoisContextCancelsStalledQuery(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close() // hold the connection open, never answer
		}
	}()
	src := &Source{Addr: ln.Addr().String()}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	start := time.Now()
	if _, err := src.GetSet(ctx, mustSet(t, "AS-FOO")); time.Since(start) > time.Second || !errors.Is(err, context.Canceled) {
		t.Errorf("GetSet = %v after %v; want context.Canceled promptly", err, time.Since(start))
	}
}

func TestWhoisDefaultTimeout(t *testing.T) {
	for in, want := range map[time.Duration]time.Duration{0: DefaultTimeout, -1: 0, 5 * time.Second: 5 * time.Second} {
		if got := (&Source{Timeout: in}).timeout(); got != want {
			t.Errorf("Timeout %v resolves to %v, want %v", in, got, want)
		}
	}
}
