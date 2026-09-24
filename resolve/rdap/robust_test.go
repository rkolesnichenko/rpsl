package rdap

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl/types"
)

func TestForbiddenAddresses(t *testing.T) {
	for _, a := range []string{
		"127.0.0.1", "::1", "10.1.2.3", "192.168.0.1", "169.254.1.1", "fe80::1", "fc00::1",
		"0.1.2.3", "100.64.0.1", "::ffff:100.64.0.1", "::ffff:127.0.0.1", // 4in6 is unwrapped first
		"192.0.0.8", "198.18.0.1", "240.0.0.1", "255.255.255.255", "64:ff9b::a00:1", "::",
		"fec0::1",             // deprecated site-local
		"::a00:1",             // IPv4-compatible, carrying 10.0.0.1
		"2002:a00:1::1",       // 6to4, carrying 10.0.0.1
		"2001:0:4136:e378::1", // Teredo
		"::ffff:0:7f00:1",     // IPv4-translated (SIIT), carrying 127.0.0.1
		"::ffff:0:a00:1",      // IPv4-translated, carrying 10.0.0.1
		"100::1",              // discard-only
	} {
		if !isForbiddenAddr(netip.MustParseAddr(a)) {
			t.Errorf("%s is not forbidden", a)
		}
	}
	for _, a := range []string{"93.184.216.34", "2606:4700::1", "193.0.6.139", "2001:4860:4860::8888", "2003::1"} {
		if isForbiddenAddr(netip.MustParseAddr(a)) {
			t.Errorf("public address %s is forbidden", a)
		}
	}
}

// The guard runs on the address actually dialed, so names and numeric forms
// that resolve to a forbidden address (localhost, 127.1, 2130706433, DNS
// rebinding) are caught too.
func TestDialGuard(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:443", "[::1]:443", "[::ffff:100.64.0.1]:443", "[64:ff9b::a00:1]:443"} {
		if err := guardDial("tcp", addr, nil); !errors.Is(err, ErrForbiddenHost) {
			t.Errorf("guardDial(%s) = %v, want ErrForbiddenHost", addr, err)
		}
	}
	if err := guardDial("tcp", "93.184.216.34:443", nil); err != nil {
		t.Errorf("guardDial(public) = %v, want nil", err)
	}
}

// The built-in client refuses a hostname that resolves to loopback before any
// connection is made (port 1 has no listener: an unguarded client would get
// "connection refused" instead).
func TestDefaultClientRefusesResolvedLoopback(t *testing.T) {
	c := &Client{BaseURL: "https://localhost:1"}
	if _, err := c.LookupAutnum(context.Background(), 65001); !errors.Is(err, ErrForbiddenHost) {
		t.Errorf("LookupAutnum(https://localhost:1) = %v, want ErrForbiddenHost", err)
	}
}

// recorder is an httptest server that records requests and counts connections.
type recorder struct {
	srv   *httptest.Server
	conns atomic.Int64
	path  atomic.Value // last request path
	ua    atomic.Value // last User-Agent
}

func newRecorder(t *testing.T, h func(w http.ResponseWriter, r *http.Request)) *recorder {
	t.Helper()
	rec := &recorder{}
	rec.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.path.Store(r.URL.Path)
		rec.ua.Store(r.UserAgent())
		h(w, r)
	}))
	rec.srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			rec.conns.Add(1)
		}
	}
	rec.srv.Start()
	t.Cleanup(rec.srv.Close)
	return rec
}

func okJSON(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(`{"handle":"X"}`)) }

func TestRequestShape(t *testing.T) {
	rec := newRecorder(t, okJSON)
	// A trailing slash on BaseURL must not produce "//autnum/1".
	c := &Client{BaseURL: rec.srv.URL + "/", AllowInsecure: true}
	if _, err := c.LookupAutnum(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if p := rec.path.Load(); p != "/autnum/1" {
		t.Errorf("path = %v, want /autnum/1", p)
	}
	if ua := rec.ua.Load(); ua != "rpsl-go" {
		t.Errorf("User-Agent = %v, want rpsl-go", ua)
	}
	// LookupIP sends the masked prefix.
	if _, err := c.LookupIP(context.Background(), netip.MustParsePrefix("10.1.2.3/8")); err != nil {
		t.Fatal(err)
	}
	if p := rec.path.Load(); p != "/ip/10.0.0.0/8" {
		t.Errorf("path = %v, want /ip/10.0.0.0/8", p)
	}
	c.UserAgent = "my-tool/1.0"
	c.LookupAutnum(context.Background(), 1)
	if ua := rec.ua.Load(); ua != "my-tool/1.0" {
		t.Errorf("custom User-Agent = %v", ua)
	}
}

func TestRateLimited(t *testing.T) {
	rec := newRecorder(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(http.StatusTooManyRequests)
	})
	c := &Client{BaseURL: rec.srv.URL, AllowInsecure: true}
	_, err := c.LookupAutnum(context.Background(), 1)
	var rl *RateLimitedError
	if !errors.As(err, &rl) || rl.RetryAfter != 120*time.Second {
		t.Errorf("err = %v (%+v), want RateLimitedError{RetryAfter: 2m}", err, rl)
	}
}

// Error bodies are drained so the keep-alive connection is reused.
func TestErrorBodiesAreDrained(t *testing.T) {
	rec := newRecorder(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(strings.Repeat("x", 10<<10)))
	})
	c := &Client{BaseURL: rec.srv.URL, AllowInsecure: true}
	for i := 0; i < 2; i++ {
		if _, err := c.LookupAutnum(context.Background(), 1); !errors.Is(err, ErrNotFound) {
			t.Fatalf("err = %v, want ErrNotFound", err)
		}
	}
	if n := rec.conns.Load(); n != 1 {
		t.Errorf("two requests used %d connections, want 1 (the 404 body was not drained)", n)
	}
}

// A server that accepts a request and never answers must not block forever:
// Timeout (default DefaultTimeout) bounds every request.
func TestRequestTimeout(t *testing.T) {
	hang := make(chan struct{})
	rec := newRecorder(t, func(http.ResponseWriter, *http.Request) { <-hang })
	t.Cleanup(func() { close(hang) }) // runs before the server's Close, which waits for handlers
	c := &Client{BaseURL: rec.srv.URL, AllowInsecure: true, Timeout: 200 * time.Millisecond}
	start := time.Now()
	_, err := c.LookupAutnum(context.Background(), 1)
	if took := time.Since(start); !errors.Is(err, context.DeadlineExceeded) || took > 2*time.Second {
		t.Errorf("LookupAutnum = %v after %v; want context.DeadlineExceeded after ~200ms", err, took)
	}
	for in, want := range map[time.Duration]time.Duration{0: DefaultTimeout, -1: 0, 5 * time.Second: 5 * time.Second} {
		if got := (&Client{Timeout: in}).timeout(); got != want {
			t.Errorf("Timeout %v resolves to %v, want %v", in, got, want)
		}
	}
}

// Retry-After values too large for a time.Duration are capped, not wrapped
// around to a negative wait.
func TestRetryAfterIsCapped(t *testing.T) {
	for _, v := range []string{"9999999999", "99999999999999999999"} {
		if d := retryAfter(v); d != maxRetryAfter {
			t.Errorf("retryAfter(%q) = %v, want %v", v, d, maxRetryAfter)
		}
	}
	if d := retryAfter("120"); d != 2*time.Minute {
		t.Errorf("retryAfter(120) = %v", d)
	}
}

// Registration numbers and addresses decode to the library's types.
func TestTypedFields(t *testing.T) {
	rec := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/autnum/") {
			w.Write([]byte(`{"handle":"AS3333","startAutnum":3333,"endAutnum":3333,"name":"RIPE-NCC-AS"}`))
			return
		}
		w.Write([]byte(`{"handle":"193.0.0.0 - 193.0.7.255","startAddress":"193.0.0.0","endAddress":"193.0.7.255"}`))
	})
	c := &Client{BaseURL: rec.srv.URL, AllowInsecure: true}
	a, err := c.LookupAutnum(context.Background(), 3333)
	if err != nil || a.StartAutnum != types.ASN(3333) || a.EndAutnum != types.ASN(3333) {
		t.Errorf("autnum = %+v, %v", a, err)
	}
	n, err := c.LookupIP(context.Background(), netip.MustParsePrefix("193.0.0.0/21"))
	if err != nil || n.StartAddress != netip.MustParseAddr("193.0.0.0") || n.EndAddress != netip.MustParseAddr("193.0.7.255") {
		t.Errorf("ip network = %+v, %v", n, err)
	}
}
