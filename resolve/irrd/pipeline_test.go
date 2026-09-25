package irrd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl/types"
)

// routeAnswer is the answer the fake servers give "!gAS<n>": one prefix that
// names n, so a caller handed another call's answer is caught.
func routeAnswer(cmd string) string {
	n, _ := strconv.Atoi(strings.TrimPrefix(cmd, "!gAS"))
	payload := fmt.Sprintf("10.%d.%d.0/24\n", n/256, n%256)
	return fmt.Sprintf("A%d\n%sC\n", len(payload), payload)
}

func wantRoute(as int) string { return fmt.Sprintf("[10.%d.%d.0/24]", as/256, as%256) }

// runQueries sends OriginatedRoutes for AS1..ASn at once and checks each gets
// its own answer.
func runQueries(t *testing.T, src *Source, n int) {
	t.Helper()
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 1; i <= n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			got, err := src.OriginatedRoutes(context.Background(), types.ASN(i), types.AFIv4)
			switch {
			case err != nil:
				errs[i-1] = err
			case fmt.Sprint(got) != wantRoute(i):
				errs[i-1] = fmt.Errorf("AS%d was answered %v", i, got)
			}
		}(i)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

// With Pipeline set, concurrent queries are written before the first answer
// is read. This server answers nothing until it holds ten commands, so a
// client that waited for each answer would time out.
func TestPipelineSendsBeforeAnswers(t *testing.T) {
	srv := newRawServer(t, func(_ int64, c net.Conn, br *bufio.Reader) {
		var held []string
		commands(c, br, func(cmd string) bool {
			if held = append(held, cmd); len(held) == 10 {
				for _, h := range held {
					fmt.Fprint(c, routeAnswer(h))
				}
				held = nil
			}
			return true
		})
	})
	src := &Source{Addr: srv.addr(), Pipeline: 10, MaxConns: 1, Timeout: 5 * time.Second}
	defer src.Close()
	runQueries(t, src, 10)
	if got := srv.accepted.Load(); got != 1 {
		t.Errorf("%d connections, want the one pipelined", got)
	}
}

// A pipelined Source answers exactly as an unpipelined one does, under load.
func TestPipelineMatchesSerial(t *testing.T) {
	srv := newRawServer(t, func(_ int64, c net.Conn, br *bufio.Reader) {
		commands(c, br, func(cmd string) bool { fmt.Fprint(c, routeAnswer(cmd)); return true })
	})
	for _, src := range []*Source{
		{Addr: srv.addr(), Timeout: 5 * time.Second},
		{Addr: srv.addr(), Pipeline: 16, MaxConns: 2, Timeout: 5 * time.Second},
		{Addr: srv.addr(), Pipeline: 1, MaxConns: 3, Timeout: 5 * time.Second},
	} {
		runQueries(t, src, 300)
		src.Close()
	}
}

// A connection the server drops mid-pipeline fails the queries still waiting
// on it, which are reads and are retried once on a fresh connection; none is
// handed another's answer, and none hangs.
func TestPipelineServerDropsMidway(t *testing.T) {
	srv := newRawServer(t, func(n int64, c net.Conn, br *bufio.Reader) {
		answered := 0
		commands(c, br, func(cmd string) bool {
			if n == 1 && answered == 3 {
				return false // the first connection breaks after three answers
			}
			answered++
			fmt.Fprint(c, routeAnswer(cmd))
			return true
		})
	})
	src := &Source{Addr: srv.addr(), Pipeline: 20, MaxConns: 1, Timeout: 5 * time.Second}
	defer src.Close()
	runQueries(t, src, 20)
	if srv.accepted.Load() < 2 {
		t.Error("the dropped connection was not replaced")
	}
}

// A caller that gives up does not desynchronise the connection: the answer to
// its command is still read, and the next caller gets its own.
func TestPipelineCancelKeepsOrder(t *testing.T) {
	release := make(chan struct{})
	srv := newRawServer(t, func(_ int64, c net.Conn, br *bufio.Reader) {
		first := true
		commands(c, br, func(cmd string) bool {
			if first {
				first = false
				<-release // hold the first answer until its caller has gone
			}
			fmt.Fprint(c, routeAnswer(cmd))
			return true
		})
	})
	src := &Source{Addr: srv.addr(), Pipeline: 8, MaxConns: 1, Timeout: 5 * time.Second}
	defer src.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := src.OriginatedRoutes(ctx, 7, types.AFIv4)
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("the cancelled caller got %v", err)
	}
	close(release)
	got, err := src.OriginatedRoutes(context.Background(), 9, types.AFIv4)
	if err != nil || fmt.Sprint(got) != wantRoute(9) {
		t.Fatalf("the next caller got %v, %v; want its own answer %s", got, err, wantRoute(9))
	}
}

// Close fails queries waiting on a pipeline, and later ones return ErrClosed.
func TestPipelineClose(t *testing.T) {
	block := make(chan struct{})
	srv := newRawServer(t, func(_ int64, c net.Conn, br *bufio.Reader) {
		commands(c, br, func(string) bool { <-block; return false })
	})
	defer close(block)
	src := &Source{Addr: srv.addr(), Pipeline: 4, MaxConns: 1, Timeout: 5 * time.Second}
	done := make(chan error, 1)
	go func() {
		_, err := src.OriginatedRoutes(context.Background(), 1, types.AFIv4)
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	src.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a query pending at Close succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a query pending at Close hung")
	}
	if _, err := src.OriginatedRoutes(context.Background(), 1, types.AFIv4); !errors.Is(err, ErrClosed) {
		t.Errorf("a query after Close: %v, want ErrClosed", err)
	}
}

var _ = reflect.DeepEqual
