// Package netconn applies context cancellation and per-query timeouts to a
// net.Conn for the socket-using resolve backends (irrd, whois). It is internal:
// the core resolve engine never imports it and stays socket-free.
package netconn

import (
	"context"
	"errors"
	"net"
	"os"
	"time"
)

// WithTimeout returns ctx bounded by timeout (unchanged if timeout <= 0). The
// backends apply it once per query, so one deadline covers every stage — slot
// wait, dial, I/O, a retry — instead of restarting at each.
func WithTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, timeout)
}

// aLongTimeAgo is a non-zero time in the past; setting it as a deadline makes
// every pending and future read or write on the connection fail immediately.
var aLongTimeAgo = time.Unix(1, 0)

// Bind applies ctx and timeout (none if <= 0) to conn for one query. The
// deadline is the earlier of now+timeout and ctx's deadline, and cancelling ctx
// expires it at once, unblocking any pending read or write. The returned release
// stops the watcher and reports whether conn is still safe to reuse — false if
// ctx fired or the deadline passed — clearing the deadline when it is.
func Bind(ctx context.Context, conn net.Conn, timeout time.Duration) (release func() (reusable bool)) {
	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	if d, ok := ctx.Deadline(); ok && (deadline.IsZero() || d.Before(deadline)) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(aLongTimeAgo) })
	return func() bool {
		if !stop() {
			return false // ctx fired: the deadline may already be expired
		}
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return false
		}
		return conn.SetDeadline(time.Time{}) == nil
	}
}

// Err returns ctx.Err() when ctx is done and err is non-nil — a deadline expired
// by cancellation surfaces as an i/o timeout, which would hide the real cause —
// and err otherwise. A socket timeout at or after ctx's own deadline reports
// context.DeadlineExceeded even if ctx has not yet marked itself done (its
// timer can fire a moment after the socket's).
func Err(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if cerr := ctx.Err(); cerr != nil {
		return cerr
	}
	if d, ok := ctx.Deadline(); ok && !time.Now().Before(d) && errors.Is(err, os.ErrDeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return err
}
