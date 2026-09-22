package whois

import (
	"context"
	"errors"
	"math"
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
		"-r -T route,route6 -i origin AS10":                     denied,
		"-r -T route,route6,aut-num,as-set -i member-of RS-REF": denied,
	})
	src := &Source{Addr: fw.addr()}
	ctx := context.Background()
	_, err1 := src.GetSet(ctx, mustSet(t, "AS-FOO"))
	_, err2 := src.OriginatedRoutes(ctx, 10, types.AFIAny)
	_, err3 := src.MembersByRef(ctx, refSet(t, "RS-REF", "TEST", "ANY"))
	for i, err := range []error{err1, err2, err3} {
		var se *ServerError
		if !errors.As(err, &se) || se.Code != 201 || errors.Is(err, resolve.ErrNotFound) {
			t.Errorf("call %d: err = %v, want ServerError{201} (not ErrNotFound)", i, err)
		}
	}
}

func TestWhoisNoEntriesIsNotFound(t *testing.T) {
	none := "%ERROR:101: no entries found\n%\n% No entries found in source RIPE.\n"
	fw := newFakeWhois(t, map[string]string{
		"-r -T as-set,route-set AS-FOO":     none,
		"-r -T route,route6 -i origin AS10": none,
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

// Timeout bounds the whole query, dial included, rather than restarting at it.
func TestWhoisTimeoutCoversTheWholeQuery(t *testing.T) {
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
	slowDial := func(ctx context.Context) (net.Conn, error) {
		select {
		case <-time.After(600 * time.Millisecond):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		var d net.Dialer
		return d.DialContext(ctx, "tcp", ln.Addr().String())
	}
	src := &Source{Dial: slowDial, Timeout: time.Second}
	start := time.Now()
	if _, err := src.GetSet(context.Background(), mustSet(t, "AS-FOO")); !errors.Is(err, context.DeadlineExceeded) ||
		time.Since(start) > 1400*time.Millisecond {
		t.Errorf("GetSet = %v after %v; want context.DeadlineExceeded after ~1s", err, time.Since(start))
	}
}

// Sources is a list of plain source names: a name carrying a space or a flag
// ("RIPE -k") is refused before anything is sent, instead of injecting flags
// into the query.
func TestWhoisSourcesAreValidated(t *testing.T) {
	for _, bad := range [][]string{{"RIPE -k -i mnt-by EVIL-MNT"}, {"RIPE\n-i x"}, {""}, {"RIPE,RADB"}} {
		src := &Source{Sources: bad, Dial: func(context.Context) (net.Conn, error) {
			t.Errorf("dialed with Sources %q", bad)
			return nil, errors.New("unreachable")
		}}
		if _, err := src.GetSet(context.Background(), mustSet(t, "AS-FOO")); err == nil {
			t.Errorf("Sources %q accepted", bad)
		}
	}
	fw := newFakeWhois(t, map[string]string{
		"-s RIPE,RADB -r -T as-set,route-set AS-FOO": "as-set: AS-FOO\nmembers: AS1\nsource: RIPE\n",
	})
	src := &Source{Addr: fw.addr(), Sources: []string{"ripe", "RADB"}, Timeout: 2 * time.Second}
	if _, err := src.GetSet(context.Background(), mustSet(t, "AS-FOO")); err != nil {
		t.Errorf("GetSet with Sources {ripe RADB}: %v", err)
	}
	if (&Source{MaxResponse: -1}).maxResponse() != math.MaxInt64 || (&Source{}).maxResponse() != maxResponse {
		t.Error("MaxResponse: zero is the default and negative is unlimited")
	}
}
