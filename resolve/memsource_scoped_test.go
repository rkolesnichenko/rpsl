package resolve_test

import (
	"context"
	"errors"
	"testing"

	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

func TestMemSourceScoped(t *testing.T) {
	objs := decodeAll(t, []string{
		"as-set: AS-X\nmembers: AS1\nsource: RIPE\n",
		"as-set: AS-X\nmembers: AS2\nsource: RADB\n",
		"route: 10.0.0.0/8\norigin: AS1\nsource: RIPE\n",
		"route: 172.16.0.0/12\norigin: AS1\nsource: RADB\n",
	})
	ctx := context.Background()
	src := resolve.NewMemSource(objs, "RIPE", "RADB")
	for ref, want := range map[string]string{"AS-X": "RIPE", "RIPE::AS-X": "RIPE", "radb::as-x": "RADB"} {
		set, err := src.GetSet(ctx, mustRef(t, ref))
		if err != nil || set.SetSource() != want {
			t.Errorf("GetSet(%s) = %v, %v; want the %s copy", ref, set, err, want)
		}
	}
	if _, err := src.GetSet(ctx, mustRef(t, "ARIN::AS-X")); !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("unknown registry: err = %v", err)
	}

	var c resolve.Corpus
	for _, o := range objs {
		c.Put(o)
	}
	only := c.SourceOf("RADB")
	if set, _ := only.GetSet(ctx, mustRef(t, "AS-X")); set == nil || set.SetSource() != "RADB" {
		t.Errorf("SourceOf(RADB) unscoped = %v; want RADB's", set)
	}
	if set, _ := only.GetSet(ctx, mustRef(t, "RIPE::AS-X")); set == nil || set.SetSource() != "RIPE" {
		t.Errorf("SourceOf(RADB) scoped RIPE = %v; want RIPE's (a scoped ref reaches every held source)", set)
	}
	if ps, _ := only.OriginatedRoutes(ctx, 1, types.AFIAny); len(ps) != 1 || ps[0].String() != "172.16.0.0/12" {
		t.Errorf("SourceOf(RADB) routes = %v; want RADB's only", ps)
	}
}
