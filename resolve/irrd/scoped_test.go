package irrd_test

import (
	"context"
	"errors"
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
		if got, _ := src.GetSet(ctx, ref(t, "AS-X")); got.(object.AsSet).Members[0].AS != 2 {
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

func TestSrcMembersOption(t *testing.T) {
	db := scopedDB()
	ctx := context.Background()
	off := &irrd.Source{Addr: db.IRRd(t), Sources: []string{"RIPE"}, Timeout: 5 * time.Second}
	set, err := off.GetSet(ctx, ref(t, "AS-X"))
	if err != nil || len(set.(object.AsSet).SrcMembers) != 0 {
		t.Fatalf("SrcMembers off: %v, %v; want no src-members read", set, err)
	}
	on := &irrd.Source{Addr: db.IRRd(t), Sources: []string{"RIPE"}, SrcMembers: true, Timeout: 5 * time.Second}
	set, err = on.GetSet(ctx, ref(t, "AS-X"))
	if err != nil {
		t.Fatal(err)
	}
	as := set.(object.AsSet)
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
