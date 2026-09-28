package irrd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve/internal/irrtest"
	"github.com/rkolesnichenko/rpsl/types"
)

// gatedConn holds back what it reads, once armed, until gate is closed, and
// counts the command lines written after arming.
type gatedConn struct {
	net.Conn
	gate  chan struct{}
	armed atomic.Bool
	lines atomic.Int32
}

func (g *gatedConn) Read(b []byte) (int, error) {
	n, err := g.Conn.Read(b)
	if g.armed.Load() {
		<-g.gate
	}
	return n, err
}

func (g *gatedConn) Write(b []byte) (int, error) {
	if g.armed.Load() {
		for _, c := range b {
			if c == '\n' {
				g.lines.Add(1)
			}
		}
	}
	return g.Conn.Write(b)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); !cond(); time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

// TestRetiringPipeDeliversQueuedAnswers: a pipe retired for a scoped lookup
// takes no new calls but still hands every answer already queued on it to its
// own caller; only then does it close and give its slot to the scoped lookup.
func TestRetiringPipeDeliversQueuedAnswers(t *testing.T) {
	const n = 8
	texts := []string{"as-set: AS-X\nmembers: AS1\nsource: RIPE\n"}
	for i := 1; i <= n; i++ {
		texts = append(texts, fmt.Sprintf("as-set: AS-Q%d\nmembers: AS%d\nsource: RADB\n", i, 100+i))
	}
	addr := irrtest.New(texts...).IRRd(t)
	gate := make(chan struct{})
	var first atomic.Pointer[gatedConn]
	src := &Source{Sources: []string{"RADB"}, Pipeline: n, MaxConns: 1, Timeout: 5 * time.Second,
		Dial: func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			c, err := d.DialContext(ctx, "tcp", addr)
			if err != nil {
				return nil, err
			}
			if g := (&gatedConn{Conn: c, gate: gate}); first.CompareAndSwap(nil, g) {
				return g, nil
			}
			return c, nil
		}}
	defer src.Close()
	ctx := context.Background()
	getSet := func(s string) (object.NamedSet, error) {
		r, err := types.ParseSetRef(s)
		if err != nil {
			return nil, err
		}
		return src.GetSet(ctx, r)
	}
	if _, err := getSet("AS-Q1"); err != nil { // opens the parent's one pipe
		t.Fatal(err)
	}
	src.mu.Lock()
	p := src.pipes[0]
	src.mu.Unlock()
	g := first.Load()
	g.armed.Store(true)

	errc := make(chan error, n)
	for i := 1; i <= n; i++ {
		go func(i int) {
			set, err := getSet(fmt.Sprintf("AS-Q%d", i))
			if err == nil {
				if m := set.(object.AsSet).Members; len(m) != 1 || m[0].AS != types.ASN(100+i) {
					err = fmt.Errorf("AS-Q%d answered with %v", i, m)
				}
			}
			errc <- err
		}(i)
	}
	waitFor(t, "the queued commands", func() bool { return g.lines.Load() == n && p.load.Load() == n })

	scoped := make(chan error, 1)
	go func() {
		set, err := getSet("RIPE::AS-X")
		if err == nil && set.SetSource() != "RIPE" {
			err = fmt.Errorf("RIPE::AS-X from %q", set.SetSource())
		}
		scoped <- err
	}()
	waitFor(t, "the pipe to retire", func() bool { return p.handoff.Load() != nil })
	if p.isBroken() {
		t.Fatal("the retiring pipe closed with answers still queued")
	}
	src.mu.Lock()
	for _, q := range src.pipes {
		if q == p {
			t.Error("the retiring pipe still takes calls")
		}
	}
	src.mu.Unlock()

	close(gate)
	for i := 0; i < n; i++ {
		if err := <-errc; err != nil {
			t.Error(err)
		}
	}
	if err := <-scoped; err != nil {
		t.Errorf("scoped lookup: %v", err)
	}
	if !p.isBroken() || !errors.Is(p.err, net.ErrClosed) {
		t.Errorf("retired pipe: broken %v, err %v; want closed once drained", p.isBroken(), p.err)
	}
}
