package irrd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

// rawServer runs handle for each accepted connection and tracks how many are
// open at once, so tests can inject server misbehaviour.
type rawServer struct {
	ln                     net.Listener
	accepted, active, peak atomic.Int64
}

func newRawServer(t *testing.T, handle func(n int64, c net.Conn, br *bufio.Reader)) *rawServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &rawServer{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n := s.accepted.Add(1)
			if a := s.active.Add(1); a > s.peak.Load() {
				s.peak.Store(a)
			}
			go func() {
				defer s.active.Add(-1)
				defer c.Close()
				handle(n, c, bufio.NewReader(c))
			}()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *rawServer) addr() string { return s.ln.Addr().String() }

// commands yields each query line, answering "!!" and "!s" itself. Like real
// IRRd, it closes after one command unless "!!" switched on persistent mode.
func commands(c net.Conn, br *bufio.Reader, f func(cmd string) (keepGoing bool)) {
	persistent := false
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		switch cmd := strings.TrimRight(line, "\r\n"); {
		case cmd == "!!":
			persistent = true
			continue
		case strings.HasPrefix(cmd, "!s"):
			fmt.Fprint(c, "C\n")
		case strings.HasPrefix(cmd, "!q"):
			return
		default:
			if !f(cmd) {
				return
			}
		}
		if !persistent {
			return
		}
	}
}

// Real IRRd answers one command and closes unless "!!" came first; a per-query
// Source with a source list sends two commands, so it must open with "!!".
// (Found against whois.radb.net: "!sRIPE" was answered and the query got EOF.)
func TestPerQueryWithSourcesUsesPersistentMode(t *testing.T) {
	fs := newFakeServer(t, map[string]string{"!gAS3333": frame("193.0.0.0/21")})
	src := &Source{Addr: fs.addr(), Sources: "RIPE"}
	got, err := src.OriginatedRoutes(context.Background(), 3333, types.AFIv4)
	if err != nil || len(got) != 1 {
		t.Errorf("OriginatedRoutes = %v, %v; want [193.0.0.0/21]", got, err)
	}
}

// silent accepts and reads, but never answers and never closes.
func silent(_ int64, _ net.Conn, br *bufio.Reader) {
	for {
		if _, err := br.ReadString('\n'); err != nil {
			return
		}
	}
}

func modes() map[string]bool { return map[string]bool{"per-query": false, "keepalive": true} }

// A query to a server that never answers returns as soon as ctx is cancelled —
// with no Timeout set — and its pooled connection is not kept.
func TestContextCancelsStalledQuery(t *testing.T) {
	for name, keep := range modes() {
		srv := newRawServer(t, silent)
		src := &Source{Addr: srv.addr(), KeepAlive: keep}
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(50*time.Millisecond, cancel)
		start := time.Now()
		_, err := src.GetSet(ctx, mustSet(t, "AS-X"))
		if took := time.Since(start); took > time.Second || !errors.Is(err, context.Canceled) {
			t.Errorf("%s: GetSet returned %v after %v; want context.Canceled promptly", name, err, took)
		}
		if len(src.idle) != 0 {
			t.Errorf("%s: a cancelled connection was returned to the pool", name)
		}
		src.Close()
	}
}

func TestContextDeadlineBoundsQuery(t *testing.T) {
	srv := newRawServer(t, silent)
	src := &Source{Addr: srv.addr()}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := src.GetSet(ctx, mustSet(t, "AS-X")); time.Since(start) > time.Second || !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("GetSet = %v after %v; want context.DeadlineExceeded after ~200ms", err, time.Since(start))
	}
}

func TestDefaultTimeout(t *testing.T) {
	for in, want := range map[time.Duration]time.Duration{0: DefaultTimeout, -1: 0, 5 * time.Second: 5 * time.Second} {
		if got := (&Source{Timeout: in}).timeout(); got != want {
			t.Errorf("Timeout %v resolves to %v, want %v", in, got, want)
		}
	}
}

// IRRd closes idle connections: a reused pooled connection that turns out to be
// dead is retried once on a fresh connection instead of failing the query.
func TestStalePooledConnectionIsRetried(t *testing.T) {
	srv := newRawServer(t, func(_ int64, c net.Conn, br *bufio.Reader) {
		commands(c, br, func(string) bool {
			fmt.Fprint(c, frame("10.0.0.0/8"))
			return false // answer one query, then close as if idle-timed-out
		})
	})
	src := &Source{Addr: srv.addr(), KeepAlive: true}
	defer src.Close()
	for i := 1; i <= 2; i++ {
		if got, err := src.OriginatedRoutes(context.Background(), 1, types.AFIv4); err != nil || len(got) != 1 {
			t.Fatalf("query %d = %v, %v; want the route", i, got, err)
		}
	}
}

func TestStaleRetryHappensOnce(t *testing.T) {
	srv := newRawServer(t, func(n int64, c net.Conn, br *bufio.Reader) {
		if n > 1 {
			return // every later connection dies at once
		}
		commands(c, br, func(string) bool {
			fmt.Fprint(c, frame("10.0.0.0/8"))
			return false
		})
	})
	src := &Source{Addr: srv.addr(), KeepAlive: true}
	defer src.Close()
	if _, err := src.OriginatedRoutes(context.Background(), 1, types.AFIv4); err != nil {
		t.Fatal(err)
	}
	if _, err := src.OriginatedRoutes(context.Background(), 1, types.AFIv4); err == nil {
		t.Fatal("query on a dead server succeeded")
	}
	if got := srv.accepted.Load(); got != 2 {
		t.Errorf("accepted %d connections, want 2 (one retry, not a loop)", got)
	}
}

// A length header cannot force a large allocation: memory follows the bytes
// that actually arrive.
func TestFrameHeaderDoesNotPreallocate(t *testing.T) {
	srv := newRawServer(t, func(_ int64, c net.Conn, br *bufio.Reader) {
		commands(c, br, func(string) bool { fmt.Fprint(c, "A268435456\nshort"); return false })
	})
	src := &Source{Addr: srv.addr()}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := src.GetSet(context.Background(), mustSet(t, "AS-X"))
	runtime.ReadMemStats(&after)
	if err == nil {
		t.Fatal("a truncated 256 MiB frame was accepted")
	}
	if a := after.TotalAlloc - before.TotalAlloc; a > 16<<20 {
		t.Errorf("a lying 256 MiB header allocated %d bytes; want < 16 MiB", a)
	}
}

func TestMaxResponseRejectsLargeFrames(t *testing.T) {
	big := strings.Repeat("AS1 ", 500) // ~2000-byte payload
	srv := newRawServer(t, func(_ int64, c net.Conn, br *bufio.Reader) {
		commands(c, br, func(string) bool { fmt.Fprint(c, frame(big)); return true })
	})
	if _, err := (&Source{Addr: srv.addr(), MaxResponse: 1000}).GetSet(context.Background(), mustSet(t, "AS-X")); err == nil ||
		!strings.Contains(err.Error(), "MaxResponse") {
		t.Errorf("err = %v, want a MaxResponse error", err)
	}
	if _, err := (&Source{Addr: srv.addr(), MaxResponse: 5000}).GetSet(context.Background(), mustSet(t, "AS-X")); err != nil {
		t.Errorf("frame within MaxResponse failed: %v", err)
	}
}

// A server that refuses the configured source list must not make every set look
// missing: the error is reported as such.
func TestRejectedSourceListIsAnError(t *testing.T) {
	for name, keep := range modes() {
		srv := newRawServer(t, func(_ int64, c net.Conn, br *bufio.Reader) {
			for {
				line, err := br.ReadString('\n')
				if err != nil {
					return
				}
				if strings.HasPrefix(line, "!s") {
					fmt.Fprint(c, "D\n")
				} else if !strings.HasPrefix(line, "!!") {
					fmt.Fprint(c, frame("AS1"))
				}
			}
		})
		src := &Source{Addr: srv.addr(), Sources: "BOGUS", KeepAlive: keep}
		_, err := src.GetSet(context.Background(), mustSet(t, "AS-X"))
		if err == nil || errors.Is(err, resolve.ErrNotFound) || !strings.Contains(err.Error(), "BOGUS") {
			t.Errorf("%s: err = %v, want an error naming the rejected source list", name, err)
		}
		src.Close()
	}
}

func TestCloseStopsPooling(t *testing.T) {
	fs := newFakeServer(t, map[string]string{"!gAS1": frame("10.0.0.0/8")})
	src := &Source{Addr: fs.addr(), KeepAlive: true}
	if _, err := src.OriginatedRoutes(context.Background(), 1, types.AFIv4); err != nil {
		t.Fatal(err)
	}
	src.Close()
	if _, err := src.OriginatedRoutes(context.Background(), 1, types.AFIv4); err != nil {
		t.Fatalf("query after Close: %v", err)
	}
	if n := len(src.idle); n != 0 {
		t.Errorf("%d connections pooled after Close, want 0 (they would leak)", n)
	}
}

// countConn tracks how many client-side connections are open at once.
type countConn struct {
	net.Conn
	once       sync.Once
	open, peak *atomic.Int64
}

func (c *countConn) Close() error {
	c.once.Do(func() { c.open.Add(-1) })
	return c.Conn.Close()
}

// MaxConns bounds the connections the client holds open, in both modes
// (measured at the client: a server notices a close only after a delay).
func TestMaxConnsBoundsConcurrency(t *testing.T) {
	if got := (&Source{}).maxConns(); got != 4 {
		t.Errorf("default MaxConns = %d, want 4", got)
	}
	for name, keep := range modes() {
		srv := newRawServer(t, func(_ int64, c net.Conn, br *bufio.Reader) {
			commands(c, br, func(string) bool {
				time.Sleep(20 * time.Millisecond)
				fmt.Fprint(c, frame("10.0.0.0/8"))
				return true
			})
		})
		var open, peak atomic.Int64
		dial := func(ctx context.Context) (net.Conn, error) {
			c, err := (&net.Dialer{}).DialContext(ctx, "tcp", srv.addr())
			if err != nil {
				return nil, err
			}
			if n := open.Add(1); n > peak.Load() {
				peak.Store(n)
			}
			return &countConn{Conn: c, open: &open, peak: &peak}, nil
		}
		src := &Source{Addr: srv.addr(), KeepAlive: keep, MaxConns: 3, Dial: dial}
		var wg sync.WaitGroup
		var failed atomic.Int64
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := src.OriginatedRoutes(context.Background(), 1, types.AFIv4); err != nil {
					failed.Add(1)
				}
			}()
		}
		wg.Wait()
		src.Close()
		if failed.Load() != 0 || peak.Load() > 3 {
			t.Errorf("%s: %d queries failed, peak %d open connections; want 0 and <= 3", name, failed.Load(), peak.Load())
		}
	}
}
