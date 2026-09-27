package nrtm4

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/internal/nrtmtest"
	"github.com/rkolesnichenko/rpsl/types"
)

// randomChange draws a change to a small database: routes of four ASes,
// three as-sets, and persons the mirror leaves out — added, modified (a
// route's text changes, a set's members), or deleted, with class, prefix and
// AS spelled in random case, as registries do.
func randomChange(r *rand.Rand) nrtmtest.Change {
	spell := func(s string) string {
		if r.IntN(2) == 0 {
			return strings.ToLower(s)
		}
		return strings.ToUpper(s)
	}
	switch r.IntN(10) {
	case 0, 1, 2, 3, 4:
		p := []string{"192.0.2.0/24", "192.0.2.0/25", "198.51.100.0/24", "2001:db8::/32", "2001:DB8:1::/48"}[r.IntN(5)]
		as := fmt.Sprintf("AS%d", 65001+r.IntN(4))
		pk := spell(p + as)
		if r.IntN(4) == 0 {
			return nrtmtest.Change{Delete: true, Class: spell("route" + map[bool]string{true: "6"}[strings.Contains(p, ":")]), PK: pk}
		}
		class := "route"
		if strings.Contains(p, ":") {
			class = "route6"
		}
		return nrtmtest.Change{Class: class, PK: pk,
			Text: fmt.Sprintf("%s: %s\ndescr: v%d\norigin: %s\nsource: TEST\n", class, spell(p), r.IntN(100), spell(as))}
	case 5, 6, 7:
		name := fmt.Sprintf("AS-S%d", r.IntN(3))
		if r.IntN(4) == 0 {
			return nrtmtest.Change{Delete: true, Class: "as-set", PK: spell(name)}
		}
		var members []string
		for k := r.IntN(4); k > 0; k-- {
			if r.IntN(3) == 0 {
				members = append(members, spell(fmt.Sprintf("AS-S%d", r.IntN(3))))
			} else {
				members = append(members, spell(fmt.Sprintf("AS%d", 65001+r.IntN(4))))
			}
		}
		text := fmt.Sprintf("as-set: %s\nsource: TEST\n", spell(name))
		if len(members) > 0 {
			text = fmt.Sprintf("as-set: %s\nmembers: %s\nsource: TEST\n", spell(name), strings.Join(members, ", "))
		}
		return nrtmtest.Change{Class: "as-set", PK: name, Text: text}
	default:
		h := fmt.Sprintf("P%d-TEST", r.IntN(3))
		if r.IntN(3) == 0 {
			return nrtmtest.Change{Delete: true, Class: "person", PK: h}
		}
		return nrtmtest.Change{Class: "person", PK: h, Text: fmt.Sprintf("person: A B\nnic-hdl: %s\nsource: TEST\n", h)}
	}
}

// checkMirror compares a client's mirror with the server's database: a
// Corpus built from the server's objects must hold as many and answer as the
// mirror does — each set, each AS's routes — and every set must expand alike.
func checkMirror(t *testing.T, label string, c *Client, s *nrtmtest.Server) {
	t.Helper()
	ref := &resolve.Corpus{}
	var texts []string
	for _, text := range s.Objects() {
		texts = append(texts, text)
	}
	sort.Strings(texts)
	for _, text := range texts {
		o, _ := rpsl.ParseObject(text)
		obj, _ := object.Decode(o)
		ref.Put(obj)
	}
	if got := c.Status().Objects; got != ref.Len() {
		t.Fatalf("%s: holds %d objects, the server's database %d", label, got, ref.Len())
	}
	want, got := ref.Source(), c.Source()
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		n, _ := types.ParseSetName(fmt.Sprintf("AS-S%d", i))
		gs, _ := got.GetSet(ctx, n)
		ws, _ := want.GetSet(ctx, n)
		if (gs == nil) != (ws == nil) || gs != nil && gs.Raw().String() != ws.Raw().String() {
			t.Fatalf("%s: GetSet(%s) = %v, want %v", label, n, gs, ws)
		}
		gp, gerr := (&resolve.Expander{Src: got}).ExpandPrefixes(ctx, n)
		wp, werr := (&resolve.Expander{Src: want}).ExpandPrefixes(ctx, n)
		if (gerr == nil) != (werr == nil) || gerr == nil && !slices.Equal(gp.List(), wp.List()) {
			t.Fatalf("%s: %s = %v, %v; want %v, %v", label, n, gp.List(), gerr, wp.List(), werr)
		}
	}
	for as := types.ASN(65001); as <= 65004; as++ {
		gr, _ := got.OriginatedRoutes(ctx, as, types.AFIAny)
		wr, _ := want.OriginatedRoutes(ctx, as, types.AFIAny)
		if !slices.Equal(sorted(gr), sorted(wr)) {
			t.Fatalf("%s: AS%d originates %v, want %v", label, as, gr, wr)
		}
	}
}

func sorted(ps []netip.Prefix) []string {
	var out []string
	for _, p := range ps {
		out = append(out, p.String())
	}
	sort.Strings(out)
	return out
}

// TestModel follows random histories: deltas of random changes, snapshots now
// and then, deltas expiring, the server starting a new session, clients
// joining late. Whenever a client syncs, it must hold exactly the server's
// database at that version.
func TestModel(t *testing.T) {
	for seed := uint64(0); seed < 60; seed++ {
		r := rand.New(rand.NewPCG(seed, 23))
		s := nrtmtest.New(t, "TEST")
		clients := []*Client{newClient(s, "TEST")}
		for step := 0; step < 40; step++ {
			switch k := r.IntN(20); {
			case k < 12:
				var cs []nrtmtest.Change
				for n := 1 + r.IntN(4); n > 0; n-- {
					cs = append(cs, randomChange(r))
				}
				s.Publish(cs...)
			case k < 14:
				s.Snapshot()
			case k < 16:
				s.Expire(s.Version() - int64(r.IntN(4)))
			case k == 16:
				s.NewSession()
			case k == 17:
				clients = append(clients, newClient(s, "TEST"))
			}
			for i, c := range clients {
				if r.IntN(3) > 0 {
					continue
				}
				if _, err := c.Sync(context.Background()); err != nil {
					t.Fatalf("seed %d step %d client %d: %v", seed, step, i, err)
				}
				checkMirror(t, fmt.Sprintf("seed %d step %d client %d (version %d)", seed, step, i, c.Status().Version), c, s)
			}
		}
	}
}

// TestSyncDuringExpansions: expansions over Source() while Sync applies
// deltas each see one version whole (run with -race).
func TestSyncDuringExpansions(t *testing.T) {
	s := nrtmtest.New(t, "TEST")
	c := newClient(s, "TEST")
	mustSync(t, c)
	n, _ := types.ParseSetName("AS-S0")
	var wg sync.WaitGroup
	done := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				src := c.Source()
				a, _ := (&resolve.Expander{Src: src}).ExpandPrefixes(context.Background(), n)
				b, _ := (&resolve.Expander{Src: src}).ExpandPrefixes(context.Background(), n)
				if !slices.Equal(a.List(), b.List()) {
					t.Error("one view expanded two ways")
					return
				}
			}
		}()
	}
	r := rand.New(rand.NewPCG(1, 1))
	for v := 0; v < 30; v++ {
		s.Publish(randomChange(r), randomChange(r), nrtmtest.Change{Class: "as-set", PK: "AS-S0",
			Text: fmt.Sprintf("as-set: AS-S0\nmembers: AS%d, AS%d\nsource: TEST\n", 65001+v%4, 65001+(v+1)%4)})
		mustSync(t, c)
	}
	close(done)
	wg.Wait()
}
