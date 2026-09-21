package netconn

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

// readErr performs one blocking read on c and reports its duration and error.
func readErr(c net.Conn) (time.Duration, error) {
	start := time.Now()
	_, err := c.Read(make([]byte, 1))
	return time.Since(start), err
}

// Cancelling the context unblocks a pending read at once, even with no timeout.
func TestBindCancelUnblocksRead(t *testing.T) {
	c, peer := net.Pipe()
	defer c.Close()
	defer peer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	release := Bind(ctx, c, 0)
	time.AfterFunc(50*time.Millisecond, cancel)
	took, err := readErr(c)
	if took > time.Second || !errors.Is(Err(ctx, err), context.Canceled) {
		t.Errorf("read returned %v after %v; want context.Canceled promptly", Err(ctx, err), took)
	}
	if release() {
		t.Error("release() = true for a connection whose deadline was expired by cancellation")
	}
}

func TestBindTimeout(t *testing.T) {
	c, peer := net.Pipe()
	defer c.Close()
	defer peer.Close()
	ctx := context.Background()
	release := Bind(ctx, c, 100*time.Millisecond)
	took, err := readErr(c)
	if took > time.Second || !errors.Is(Err(ctx, err), os.ErrDeadlineExceeded) {
		t.Errorf("read returned %v after %v; want a deadline error after ~100ms", err, took)
	}
	if release() {
		t.Error("release() = true after the timeout expired")
	}
}

// The earlier of the timeout and the context deadline wins.
func TestBindContextDeadlineEarlier(t *testing.T) {
	c, peer := net.Pipe()
	defer c.Close()
	defer peer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	Bind(ctx, c, 10*time.Second)
	took, err := readErr(c)
	if took > time.Second || !errors.Is(Err(ctx, err), context.DeadlineExceeded) {
		t.Errorf("read returned %v after %v; want context.DeadlineExceeded after ~50ms", Err(ctx, err), took)
	}
}

// A query that finishes in time leaves the connection reusable with its
// deadline cleared, so a later, slower read on it still succeeds.
func TestReleaseCleanClearsDeadline(t *testing.T) {
	c, peer := net.Pipe()
	defer c.Close()
	defer peer.Close()
	release := Bind(context.Background(), c, 50*time.Millisecond)
	if !release() {
		t.Fatal("release() = false for a query that finished before its deadline")
	}
	go func() {
		time.Sleep(150 * time.Millisecond) // past the released 50ms deadline
		peer.Write([]byte("x"))
	}()
	if _, err := readErr(c); err != nil {
		t.Errorf("read after release failed: %v (deadline not cleared)", err)
	}
}

func TestErrPassesThroughWhenContextLive(t *testing.T) {
	boom := errors.New("boom")
	if got := Err(context.Background(), boom); got != boom {
		t.Errorf("Err = %v, want the original error", got)
	}
}

// pastDeadline is a context whose deadline has passed but which has not yet
// been marked done — the window in which a socket deadline can fire first.
type pastDeadline struct{ context.Context }

func (pastDeadline) Deadline() (time.Time, bool) { return time.Now().Add(-time.Millisecond), true }

// A socket timeout caused by the context's own deadline reports
// context.DeadlineExceeded even before the context has noticed it is done.
func TestErrAttributesDeadlineRace(t *testing.T) {
	ctx := pastDeadline{context.Background()}
	if got := Err(ctx, os.ErrDeadlineExceeded); !errors.Is(got, context.DeadlineExceeded) {
		t.Errorf("Err = %v, want context.DeadlineExceeded", got)
	}
}
