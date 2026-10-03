package irrdserver_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl/resolve/internal/rpsldtest"
	"github.com/rkolesnichenko/rpsl/resolve/irrdq"
	"github.com/rkolesnichenko/rpsl/resolve/irrdserver"
)

var texts = []string{
	"as-set: AS-X\nmembers: AS1, AS2\nmnt-by: M\nsource: RIPE\n",
	"route: 192.0.2.0/24\norigin: AS1\nmnt-by: M\nsource: RIPE\n",
}

// asX is the answer to "!iAS-X": 13 bytes.
const asX = "A8\nAS1 AS2\nC\n"

// start serves snap with limits l on a localhost port; the server is shut
// down when the test ends. done receives what Serve returned.
func start(t *testing.T, snap func() *irrdq.Snapshot, l irrdserver.Limits) (*irrdserver.Server, string, chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &irrdserver.Server{Snapshot: snap, Limits: l}
	done := make(chan error, 1)
	go func() { done <- s.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.Shutdown(ctx); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
	})
	return s, ln.Addr().String(), done
}

func fixed(t *testing.T) func() *irrdq.Snapshot {
	snap := rpsldtest.Snapshot(t, texts, irrdq.SnapshotOptions{}, "RIPE")
	return func() *irrdq.Snapshot { return snap }
}

// talk sends send on a new connection and returns everything read until the
// server closes it; an error if it does not within 5 s. Safe to call from any
// goroutine: it reports instead of failing the test.
func talk(addr, send string) (string, error) {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return "", err
	}
	defer c.Close()
	if _, err := io.WriteString(c, send); err != nil {
		return "", err
	}
	return readAll(c, 5*time.Second)
}

// readAll reads c until the server closes it (EOF, or a reset when it closed
// with input unread); an error if within d it does not.
func readAll(c net.Conn, d time.Duration) (string, error) {
	c.SetReadDeadline(time.Now().Add(d))
	var out []byte
	buf := make([]byte, 64<<10)
	for {
		n, err := c.Read(buf)
		out = append(out, buf[:n]...)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return string(out), fmt.Errorf("the server did not close the connection; read %d bytes", len(out))
		}
		if err != nil {
			return string(out), nil
		}
	}
}

// mustTalk is talk on the test goroutine.
func mustTalk(t *testing.T, addr, send string) string {
	t.Helper()
	got, err := talk(addr, send)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// noLeak fails the test unless, within 2 s, no more goroutines run than
// before (slack allows for the runtime's own).
func noLeak(t *testing.T, before int) {
	t.Helper()
	n := runtime.NumGoroutine()
	for i := 0; i < 100 && n > before+2; i++ {
		time.Sleep(20 * time.Millisecond)
		n = runtime.NumGoroutine()
	}
	if n > before+2 {
		buf := make([]byte, 1<<20)
		t.Errorf("%d goroutines, %d before:\n%s", n, before, buf[:runtime.Stack(buf, true)])
	}
}

func TestServeAnswers(t *testing.T) {
	_, addr, _ := start(t, fixed(t), irrdserver.Limits{})
	if got, want := mustTalk(t, addr, "!!\n!iAS-X\n!gAS1\n!q\n"), asX+"A13\n192.0.2.0/24\nC\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if got := mustTalk(t, addr, "!iAS-X\n!gAS1\n"); got != asX {
		t.Errorf("without !!: %q", got)
	}
}

func TestPipelining(t *testing.T) {
	_, addr, _ := start(t, fixed(t), irrdserver.Limits{})
	send := "!!\n" + strings.Repeat("!iAS-X\n!gAS1\n", 1000) + "!q\n"
	if got, want := mustTalk(t, addr, send), strings.Repeat(asX+"A13\n192.0.2.0/24\nC\n", 1000); got != want {
		t.Errorf("pipelined: %d bytes, want %d", len(got), len(want))
	}
}

// A client that sends a command and half a line, then waits for the answer
// before sending the rest, is answered: the server flushes unless a whole
// further command is already buffered.
func TestPartialLineFlushes(t *testing.T) {
	_, addr, _ := start(t, fixed(t), irrdserver.Limits{})
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "!!\n!iAS-X\n!iAS")
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(c)
	got := ""
	for i := 0; i < 3; i++ {
		l, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("waiting for the first answer: %v (read %q)", err, got+l)
		}
		got += l
	}
	if got != asX {
		t.Fatalf("first answer %q", got)
	}
	io.WriteString(c, "-X\n!q\n")
	rest, err := io.ReadAll(br) // the deadline set above bounds it
	if err != nil || string(rest) != asX {
		t.Errorf("second answer %q (%v)", rest, err)
	}
}

// MaxLine holds at exactly its value: a line of MaxLine bytes is answered,
// one of MaxLine+1 is refused and the connection closed.
func TestMaxLine(t *testing.T) {
	_, addr, _ := start(t, fixed(t), irrdserver.Limits{MaxLine: 16})
	if got := mustTalk(t, addr, "!!\n!n"+strings.Repeat("x", 14)+"\n!q\n"); got != "C\n" {
		t.Errorf("a line of exactly MaxLine bytes: %q", got)
	}
	if got := mustTalk(t, addr, "!!\n!n"+strings.Repeat("x", 15)+"\n!iAS-X\n!q\n"); got != "F Line too long: over 16 bytes\n" {
		t.Errorf("a line of MaxLine+1 bytes: %q", got)
	}
	// A "\r" is part of the line: IRRd strips it after reading.
	if got := mustTalk(t, addr, "!!\n!n"+strings.Repeat("x", 13)+"\r\n!q\n"); got != "C\n" {
		t.Errorf("a line of MaxLine bytes with its \\r: %q", got)
	}
	if got := mustTalk(t, addr, "!!\n!n"+strings.Repeat("x", 14)+"\r\n!q\n"); got != "F Line too long: over 16 bytes\n" {
		t.Errorf("a line of MaxLine+1 bytes with its \\r: %q", got)
	}
	// Far over the limit, with input still unread when the server closes:
	// the refusal still reaches the client.
	if got := mustTalk(t, addr, "!!\n!n"+strings.Repeat("x", 1<<20)+"\n!q\n"); got != "F Line too long: over 16 bytes\n" {
		t.Errorf("a line of 1 MiB: %q", got)
	}
	// The same at the end of the input, without its newline.
	if got := mustTalk(t, addr, "!!\n!n"+strings.Repeat("x", 15)); got != "F Line too long: over 16 bytes\n" {
		t.Errorf("an unterminated line of MaxLine+1 bytes: %q", got)
	}
}

// MaxReply holds at exactly its value: a reply of MaxReply bytes is sent,
// one byte more is refused, and the connection stays open.
func TestMaxReply(t *testing.T) {
	_, addr, _ := start(t, fixed(t), irrdserver.Limits{MaxReply: int64(len(asX))})
	if got := mustTalk(t, addr, "!!\n!iAS-X\n!q\n"); got != asX {
		t.Errorf("a reply of exactly MaxReply bytes: %q", got)
	}
	_, addr, _ = start(t, fixed(t), irrdserver.Limits{MaxReply: int64(len(asX)) - 1})
	if got, want := mustTalk(t, addr, "!!\n!iAS-X\n!n x\n!q\n"), "F Answer larger than 12 bytes\nC\n"; got != want {
		t.Errorf("a reply of MaxReply+1 bytes: %q, want %q", got, want)
	}
	// Without "!!" the refusal closes the connection, as the reply would.
	if got := mustTalk(t, addr, "!iAS-X\n!n x\n"); got != "F Answer larger than 12 bytes\n" {
		t.Errorf("a one-shot reply of MaxReply+1 bytes: %q", got)
	}
}

// gate is a Snapshot func that blocks its n-th call until released.
type gate struct {
	snap    *irrdq.Snapshot
	n       int32
	calls   atomic.Int32
	entered chan struct{}
	release chan struct{}
}

func newGate(snap *irrdq.Snapshot, n int32) *gate {
	return &gate{snap: snap, n: n, entered: make(chan struct{}), release: make(chan struct{})}
}

func (g *gate) get() *irrdq.Snapshot {
	if g.calls.Add(1) == g.n {
		close(g.entered)
		<-g.release
	}
	return g.snap
}

// QueryTime: a command still evaluating when QueryTime has passed is
// refused, and the connection stays open (unless the command would have
// closed it). Deterministic: the command blocks in its snapshot read until
// QueryTime has passed on the clock, which the server checks.
func TestQueryTime(t *testing.T) {
	const qt = 50 * time.Millisecond
	snap := rpsldtest.Snapshot(t, texts, irrdq.SnapshotOptions{}, "RIPE")
	for _, c := range []struct {
		name, send string
		block      int32
		want       string
	}{
		{"persistent", "!!\n!iAS-X\n!iAS-X\n!q\n", 2, "F Query took longer than 50ms\n" + asX},
		{"one-shot", "!iAS-X\n!iAS-X\n", 1, "F Query took longer than 50ms\n"},
	} {
		g := newGate(snap, c.block)
		_, addr, _ := start(t, g.get, irrdserver.Limits{QueryTime: qt})
		type result struct {
			out string
			err error
		}
		res := make(chan result, 1)
		go func() {
			out, err := talk(addr, c.send)
			res <- result{out, err}
		}()
		select {
		case <-g.entered:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: the command never read its snapshot", c.name)
		}
		time.Sleep(2 * qt)
		close(g.release)
		r := <-res
		if r.err != nil {
			t.Fatalf("%s: %v", c.name, r.err)
		}
		if r.out != c.want {
			t.Errorf("%s: %q, want %q", c.name, r.out, c.want)
		}
	}
}

func TestMaxConns(t *testing.T) {
	_, addr, _ := start(t, fixed(t), irrdserver.Limits{MaxConns: 2})
	var held []net.Conn
	for i := 0; i < 2; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		io.WriteString(c, "!!\n!n x\n")
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if l, err := bufio.NewReader(c).ReadString('\n'); l != "C\n" { // it is being served
			t.Fatalf("held connection %d: %q, %v", i, l, err)
		}
		held = append(held, c)
	}
	if got := mustTalk(t, addr, "!v\n"); got != "" {
		t.Errorf("a connection over MaxConns was answered: %q", got)
	}
	held[0].Close()
	// The slot is free once the server has seen the close: retry, bounded.
	got := ""
	for i := 0; i < 100 && got != "C\n"; i++ {
		got = mustTalk(t, addr, "!n x\n")
		if got != "C\n" {
			time.Sleep(20 * time.Millisecond)
		}
	}
	if got != "C\n" {
		t.Errorf("after one closed: %q", got)
	}
}

func TestIdleTimeout(t *testing.T) {
	_, addr, _ := start(t, fixed(t), irrdserver.Limits{IdleTimeout: 300 * time.Millisecond})
	for _, c := range []struct {
		name, send string
		min, max   time.Duration
	}{
		{"IdleTimeout", "!!\n", 200 * time.Millisecond, 3 * time.Second},
		// "!t" overrides it for the connection.
		{"!t1", "!!\n!t1\n", 900 * time.Millisecond, 4 * time.Second},
	} {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(conn, c.send)
		begin := time.Now()
		got, err := readAll(conn, 10*time.Second)
		d := time.Since(begin)
		conn.Close()
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
		if want := strings.Repeat("C\n", strings.Count(c.send, "!t")); got != want {
			t.Errorf("%s: read %q", c.name, got)
		}
		if d < c.min || d > c.max {
			t.Errorf("%s: closed after %v, want between %v and %v", c.name, d, c.min, c.max)
		}
	}
}

// A client that pipelines without reading cannot hold the server: the
// write deadline closes it, and Shutdown leaves no goroutine behind.
func TestStuckClient(t *testing.T) {
	before := runtime.NumGoroutine()
	s, addr, done := start(t, fixed(t), irrdserver.Limits{IdleTimeout: 300 * time.Millisecond})
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	wrote := make(chan struct{})
	go func() {
		defer close(wrote)
		io.WriteString(c, "!!\n")
		for i := 0; i < 100000; i++ {
			if _, err := io.WriteString(c, "!iAS-X\n"); err != nil {
				return
			}
		}
	}()
	time.Sleep(time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown: %v", err)
	}
	if err := <-done; !errors.Is(err, irrdserver.ErrServerClosed) {
		t.Errorf("Serve returned %v", err)
	}
	c.Close()
	<-wrote
	noLeak(t, before)
}

// A client that sends its commands and closes its write side gets every
// answer, then the server closes; nothing is left running.
func TestHalfClosed(t *testing.T) {
	before := runtime.NumGoroutine()
	s, addr, _ := start(t, fixed(t), irrdserver.Limits{})
	for _, c := range []struct{ send, want string }{
		{"!!\n!iAS-X\n!n x\n!gAS1\n", asX + "C\n" + "A13\n192.0.2.0/24\nC\n"},
		{"!iAS-X\n!gAS1\n", asX},
		{"!!\n" + strings.Repeat("!iAS-X\n", 500), strings.Repeat(asX, 500)},
	} {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(conn, c.send)
		if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
			t.Fatal(err)
		}
		got, err := readAll(conn, 5*time.Second)
		conn.Close()
		if err != nil {
			t.Errorf("%q: %v", c.send, err)
		}
		if got != c.want {
			t.Errorf("%q: %q, want %q", c.send, got, c.want)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown: %v", err)
	}
	noLeak(t, before)
}

// Shutdown with connections busy sending commands ends at once, never
// waiting for an idle timeout: a connection that was about to wait for its
// next command when Shutdown began does not wait (repeated, for the race
// between the two).
func TestShutdownDuringCommands(t *testing.T) {
	before := runtime.NumGoroutine()
	for round := 0; round < 20; round++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		s := &irrdserver.Server{Snapshot: fixed(t), Limits: irrdserver.Limits{IdleTimeout: time.Minute}}
		done := make(chan error, 1)
		go func() { done <- s.Serve(ln) }()
		var wg sync.WaitGroup
		var conns []net.Conn
		for i := 0; i < 8; i++ {
			c, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			conns = append(conns, c)
			wg.Add(1)
			go func() { // a client sending commands one by one, reading each answer
				defer wg.Done()
				br := bufio.NewReader(c)
				if _, err := io.WriteString(c, "!!\n"); err != nil {
					return
				}
				for {
					if _, err := io.WriteString(c, "!n x\n"); err != nil {
						return
					}
					if _, err := br.ReadString('\n'); err != nil {
						return
					}
				}
			}()
		}
		time.Sleep(time.Duration(round%5) * 5 * time.Millisecond)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		begin := time.Now()
		err = s.Shutdown(ctx)
		cancel()
		if err != nil {
			t.Fatalf("round %d: Shutdown: %v after %v", round, err, time.Since(begin))
		}
		if d := time.Since(begin); d > 5*time.Second {
			t.Fatalf("round %d: Shutdown took %v", round, d)
		}
		for _, c := range conns {
			c.Close()
		}
		wg.Wait()
		if err := <-done; err != nil && !errors.Is(err, irrdserver.ErrServerClosed) {
			t.Fatalf("round %d: Serve: %v", round, err)
		}
	}
	noLeak(t, before)
}

func TestServeAfterShutdown(t *testing.T) {
	s := &irrdserver.Server{Snapshot: fixed(t)}
	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if err := s.Serve(ln); !errors.Is(err, irrdserver.ErrServerClosed) {
		t.Errorf("Serve after Shutdown: %v", err)
	}
	if err := (&irrdserver.Server{}).Serve(ln); err == nil || errors.Is(err, irrdserver.ErrServerClosed) {
		t.Errorf("Serve without a Snapshot: %v", err)
	}
}

// TestLimitDefaults: a zero Limits field is its default (Refinement 13).
func TestLimitDefaults(t *testing.T) {
	got := irrdserver.LimitsWithDefaults(irrdserver.Limits{})
	want := irrdserver.Limits{MaxConns: 256, IdleTimeout: 30 * time.Second, MaxLine: 1 << 20, MaxReply: 256 << 20, QueryTime: 60 * time.Second}
	if got != want {
		t.Errorf("defaults %+v, want %+v", got, want)
	}
	set := irrdserver.Limits{MaxConns: 1, IdleTimeout: 2, MaxLine: 3, MaxReply: 4, QueryTime: 5}
	if got := irrdserver.LimitsWithDefaults(set); got != set {
		t.Errorf("set limits changed: %+v", got)
	}
}

// One answer, one snapshot: while snapshots swap, every answer is the old
// snapshot's or the new one's, never a mixture.
func TestAnswersComeFromOneSnapshot(t *testing.T) {
	a := rpsldtest.Snapshot(t, []string{"as-set: AS-X\nmembers: AS1, AS2\nsource: RIPE\n"}, irrdq.SnapshotOptions{}, "RIPE")
	b := rpsldtest.Snapshot(t, []string{"as-set: AS-X\nmembers: AS3, AS4, AS5\nsource: RIPE\n"}, irrdq.SnapshotOptions{}, "RIPE")
	var cur atomic.Pointer[irrdq.Snapshot]
	cur.Store(a)
	_, addr, _ := start(t, func() *irrdq.Snapshot { return cur.Load() }, irrdserver.Limits{})
	stop := make(chan struct{})
	swapped := make(chan struct{})
	go func() {
		defer close(swapped)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if i%2 == 0 {
				cur.Store(b)
			} else {
				cur.Store(a)
			}
		}
	}()
	errs := make(chan error, 4)
	var seen [2]atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := talk(addr, "!!\n"+strings.Repeat("!iAS-X\n", 200)+"!q\n")
			if err != nil {
				errs <- err
				return
			}
			n := 0
			for _, r := range strings.SplitAfter(got, "C\n") {
				switch r {
				case "":
					continue
				case asX:
					seen[0].Add(1)
				case "A12\nAS3 AS4 AS5\nC\n":
					seen[1].Add(1)
				default:
					errs <- fmt.Errorf("a mixed or broken answer: %q", r)
					return
				}
				n++
			}
			if n != 200 {
				errs <- fmt.Errorf("%d answers, want 200", n)
			}
		}()
	}
	wg.Wait()
	close(stop)
	<-swapped
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	t.Logf("answers from a: %d, from b: %d", seen[0].Load(), seen[1].Load())
}
