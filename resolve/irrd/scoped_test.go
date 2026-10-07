package irrd_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/internal/irrtest"
	"github.com/rkolesnichenko/rpsl/resolve/irrd"
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

func scopedDB() *irrtest.DB {
	return irrtest.New(
		"as-set: AS-X\nmembers: AS1, AS-Y\nsrc-members: RIPE::AS-Y\nsource: RIPE\n",
		"as-set: AS-X\nmembers: AS2\nsource: RADB\n",
	)
}

func TestScopedGetSet(t *testing.T) {
	for _, pipeline := range []int{0, 4} {
		db := scopedDB()
		src := &irrd.Source{Addr: db.IRRd(t), Sources: []string{"RADB"}, Pipeline: pipeline, KeepAlive: true, Timeout: 5 * time.Second}
		ctx := context.Background()
		set, err := src.GetSet(ctx, ref(t, "RIPE::AS-X"))
		if err != nil || set.SetSource() != "RIPE" {
			t.Fatalf("pipeline %d: RIPE::AS-X = %v, %v; want RIPE's copy", pipeline, set, err)
		}
		if got, _ := src.GetSet(ctx, ref(t, "AS-X")); got.(*object.AsSet).Members[0].AS != 2 {
			t.Errorf("pipeline %d: unscoped AS-X = %v; want RADB's", pipeline, got)
		}
		if _, err := src.GetSet(ctx, ref(t, "NOSUCH::AS-X")); !errors.Is(err, resolve.ErrNotFound) {
			t.Errorf("pipeline %d: unknown registry: err = %v", pipeline, err)
		}
		if _, err := src.GetSet(ctx, ref(t, "AS-X")); err != nil {
			t.Errorf("pipeline %d: the unscoped connection broke after the scoped refusal: %v", pipeline, err)
		}
		src.Close()
	}
}

// TestScopedSelfReference: IRRd's "!i" drops a set's own name from its
// answer (members_for_set, irrd/server/query_resolver.py: "if parameter in
// members: members.remove(parameter)"). Looked up by precedence that
// reference is the set itself, a cycle, so an unscoped lookup leaves it out;
// a scoped one (RADB::AS-TOP listing AS-TOP, which precedence may resolve to
// another registry's copy) restores it from the object, spelled however the
// object spells it.
func TestScopedSelfReference(t *testing.T) {
	db := irrtest.New(
		"as-set: AS-TOP\nmembers: AS1, AS-TOP\nsource: RIPE\n",
		"as-set: AS-TOP\nmembers: AS2, as-top\nsource: RADB\n",
		"as-set: AS-SELF\nmembers: AS-SELF\nsource: RADB\n",
	)
	for _, pipeline := range []int{0, 4} {
		src := &irrd.Source{Addr: db.IRRd(t), Sources: []string{"RIPE", "RADB"}, Pipeline: pipeline, Timeout: 5 * time.Second}
		ctx := context.Background()
		for _, c := range []struct{ ref, want string }{
			{"RADB::AS-TOP", "[AS2 AS-TOP]"},
			{"RADB::AS-SELF", "[AS-SELF]"}, // "!i" answers D: the object holds it
			{"AS-TOP", "[AS1]"},            // RIPE's, by precedence: its self-reference is a no-op
			{"RIPE::AS-TOP", "[AS1 AS-TOP]"},
		} {
			set, err := src.GetSet(ctx, ref(t, c.ref))
			if err != nil {
				t.Fatalf("pipeline %d: %s: %v", pipeline, c.ref, err)
			}
			var got []string
			for _, m := range set.(*object.AsSet).Members {
				got = append(got, m.Ref().Name().String())
				if m.Kind == object.MemberAS {
					got[len(got)-1] = m.AS.String()
				}
			}
			if g := fmt.Sprint(got); g != c.want {
				t.Errorf("pipeline %d: %s members %s, want %s", pipeline, c.ref, g, c.want)
			}
		}
		src.Close()
	}
}

func TestSrcMembersOption(t *testing.T) {
	db := scopedDB()
	ctx := context.Background()
	off := &irrd.Source{Addr: db.IRRd(t), Sources: []string{"RIPE"}, Timeout: 5 * time.Second}
	set, err := off.GetSet(ctx, ref(t, "AS-X"))
	if err != nil || len(set.(*object.AsSet).SrcMembers) != 0 {
		t.Fatalf("SrcMembers off: %v, %v; want no src-members read", set, err)
	}
	on := &irrd.Source{Addr: db.IRRd(t), Sources: []string{"RIPE"}, SrcMembers: true, Timeout: 5 * time.Second}
	set, err = on.GetSet(ctx, ref(t, "AS-X"))
	if err != nil {
		t.Fatal(err)
	}
	as := set.(*object.AsSet)
	if len(as.SrcMembers) != 1 || as.SrcMembers[0].Ref().String() != "RIPE::AS-Y" || as.SetSource() != "RIPE" {
		t.Errorf("SrcMembers on: %+v (source %q); want [RIPE::AS-Y] from RIPE", as.SrcMembers, as.SetSource())
	}
}

// TestScopedSharesPipelinedSlots: a pipe holds its MaxConns slot while it
// lives, so a scoped lookup whose sub-source has no pipe must reclaim an idle
// one of the parent's (and the parent one of the sub-source's) rather than
// wait for a slot that is never given back.
func TestScopedSharesPipelinedSlots(t *testing.T) {
	db := scopedDB()
	src := &irrd.Source{Addr: db.IRRd(t), Sources: []string{"RADB"}, Pipeline: 1, MaxConns: 1, Timeout: 2 * time.Second}
	defer src.Close()
	ctx := context.Background()
	for i, r := range []string{"AS-X", "RIPE::AS-X", "AS-X", "RIPE::AS-X"} {
		if _, err := src.GetSet(ctx, ref(t, r)); err != nil {
			t.Fatalf("lookup %d (%s): %v", i, r, err)
		}
	}
}

// TestScopedClose: Close closes the scoped lookups' connections too, and a
// scoped lookup after it, even of a registry not yet used, is ErrClosed.
func TestScopedClose(t *testing.T) {
	for _, pipeline := range []int{0, 2} {
		db := scopedDB()
		src := &irrd.Source{Addr: db.IRRd(t), Sources: []string{"RADB"}, Pipeline: pipeline, KeepAlive: true, Timeout: 5 * time.Second}
		ctx := context.Background()
		if _, err := src.GetSet(ctx, ref(t, "RIPE::AS-X")); err != nil {
			t.Fatal(err)
		}
		src.Close()
		src.Close()
		for _, r := range []string{"RIPE::AS-X", "RADB::AS-X", "AS-X"} {
			if _, err := src.GetSet(ctx, ref(t, r)); !errors.Is(err, irrd.ErrClosed) {
				t.Errorf("pipeline %d: %s after Close: err = %v; want ErrClosed", pipeline, r, err)
			}
		}
	}
}

// TestScopedConcurrent mixes scoped and unscoped lookups on a Source whose
// pipes and pooled connections they share (run under -race).
func TestScopedConcurrent(t *testing.T) {
	for _, pipeline := range []int{0, 2} {
		db := scopedDB()
		src := &irrd.Source{Addr: db.IRRd(t), Sources: []string{"RADB"}, Pipeline: pipeline, KeepAlive: true, MaxConns: 2, Timeout: 5 * time.Second}
		refs := []string{"AS-X", "RIPE::AS-X", "RADB::AS-X", "NOSUCH::AS-X"}
		errc := make(chan error, 64)
		for i := 0; i < 64; i++ {
			go func(r string) {
				set, err := src.GetSet(context.Background(), ref(t, r))
				switch {
				case r == "NOSUCH::AS-X":
					if !errors.Is(err, resolve.ErrNotFound) {
						err = errors.New(r + ": want ErrNotFound, got " + errString(err))
					} else {
						err = nil
					}
				case err == nil && r == "RIPE::AS-X" && set.SetSource() != "RIPE":
					err = errors.New(r + ": not RIPE's copy")
				}
				errc <- err
			}(refs[i%len(refs)])
		}
		for i := 0; i < 64; i++ {
			if err := <-errc; err != nil {
				t.Errorf("pipeline %d: %v", pipeline, err)
			}
		}
		src.Close()
	}
}

func errString(err error) string {
	if err == nil {
		return "nil"
	}
	return err.Error()
}

// TestScopedUnderSteadyLoad: the parent's pipes are never idle while workers
// keep them full, so a scoped lookup must retire one rather than wait for an
// idle one, and finish long before its deadline.
func TestScopedUnderSteadyLoad(t *testing.T) {
	for _, c := range []struct{ maxConns, pipeline, workers int }{{1, 8, 16}, {4, 8, 64}, {2, 1, 8}} {
		db := scopedDB()
		src := &irrd.Source{Addr: db.IRRd(t), Sources: []string{"RADB"}, Pipeline: c.pipeline, MaxConns: c.maxConns, Timeout: 5 * time.Second}
		ctx, stop := context.WithCancel(context.Background())
		var wg sync.WaitGroup
		for i := 0; i < c.workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for ctx.Err() == nil {
					if _, err := src.GetSet(ctx, ref(t, "AS-X")); err != nil && ctx.Err() == nil {
						t.Errorf("%+v: unscoped worker: %v", c, err)
						return
					}
				}
			}()
		}
		time.Sleep(50 * time.Millisecond) // let the workers fill every pipe
		for i := 0; i < 3; i++ {
			start := time.Now()
			set, err := src.GetSet(context.Background(), ref(t, "RIPE::AS-X"))
			if err != nil || set.SetSource() != "RIPE" {
				t.Errorf("%+v: scoped lookup %d under load: %v, %v after %v", c, i, set, err, time.Since(start))
			} else if d := time.Since(start); d > 3*time.Second { // under the 5 s Timeout a starved lookup would hit
				t.Errorf("%+v: scoped lookup %d took %v", c, i, d)
			}
		}
		stop()
		wg.Wait()
		src.Close()
	}
}

// TestUnknownRegistryIsRemembered: a registry the server does not have is
// not asked for again; later lookups of it are ErrNotFound without a dial.
// With "!j-*" the Source learns the server's registries once and asks for no
// unknown one at all; a server that refuses "!j" is asked for the registry
// ("!s") once.
func TestUnknownRegistryIsRemembered(t *testing.T) {
	for _, listed := range []bool{true, false} {
		for _, pipeline := range []int{0, 2} {
			db := scopedDB()
			if !listed {
				db.WithoutSerialRange()
			}
			addr := db.IRRd(t)
			var dials atomic.Int32
			src := &irrd.Source{Sources: []string{"RADB"}, Pipeline: pipeline, KeepAlive: true, Timeout: 5 * time.Second,
				Dial: func(ctx context.Context) (net.Conn, error) {
					dials.Add(1)
					var d net.Dialer
					return d.DialContext(ctx, "tcp", addr)
				}}
			ctx := context.Background()
			for i := 0; i < 5; i++ {
				if _, err := src.GetSet(ctx, ref(t, "NOSUCH::AS-X")); !errors.Is(err, resolve.ErrNotFound) {
					t.Fatalf("listed %v, pipeline %d: lookup %d: err = %v", listed, pipeline, i, err)
				}
			}
			if _, err := src.GetSet(ctx, ref(t, "NOSUCH::AS-OTHER")); !errors.Is(err, resolve.ErrNotFound) {
				t.Fatalf("listed %v, pipeline %d: another set of the unknown registry: err = %v", listed, pipeline, err)
			}
			probes, lists := 0, 0
			for _, cmd := range db.Commands() {
				switch cmd {
				case "!sNOSUCH":
					probes++
				case "!j-*":
					lists++
				}
			}
			wantProbes, wantDials := 0, int32(1) // the "!j-*" alone
			if !listed {
				wantProbes, wantDials = 1, 2 // the refused "!j-*", then "!sNOSUCH" once
			}
			if probes != wantProbes || lists != 1 || dials.Load() != wantDials {
				t.Errorf("listed %v, pipeline %d: %d dials, %d \"!j-*\", %d \"!sNOSUCH\"; want %d, 1, %d",
					listed, pipeline, dials.Load(), lists, probes, wantDials, wantProbes)
			}
			if set, err := src.GetSet(ctx, ref(t, "RIPE::AS-X")); err != nil || set.SetSource() != "RIPE" {
				t.Errorf("listed %v, pipeline %d: a real registry after the unknown one: %v, %v", listed, pipeline, set, err)
			}
			src.Close()
		}
	}
}

// TestSrcMembersSourceIsCanonical: an unscoped lookup with SrcMembers takes
// the set's source: in canonical form, as a scoped lookup does.
func TestSrcMembersSourceIsCanonical(t *testing.T) {
	db := irrtest.New("as-set: AS-X\nmembers: AS1\nsrc-members: RIPE::AS-Y\nsource: ripe\n")
	src := &irrd.Source{Addr: db.IRRd(t), Sources: []string{"RIPE"}, SrcMembers: true, Timeout: 5 * time.Second}
	set, err := src.GetSet(context.Background(), ref(t, "AS-X"))
	if err != nil || set.SetSource() != "RIPE" {
		t.Errorf("source = %v, %v; want RIPE", set, err)
	}
}
