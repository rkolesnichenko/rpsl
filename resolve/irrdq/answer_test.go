package irrdq

import (
	"context"
	"fmt"
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/resolve/rpki"
	"github.com/rkolesnichenko/rpsl/types"
)

// bigSnapshot is one registry of n routes under 10.0.0.0/8, each with text
// of about pad bytes, and n more of 198.51.100.0/24, each with its own
// origin, built directly (no parsing): what "!r0.0.0.0/0,M" or
// "!r198.51.100.0/24,o" over a whole registry with -keep-route-text reads.
// With vrps, RPKI-aware mode, the routes under 10.0.0.0/9 valid and the
// others not_found.
func bigSnapshot(t testing.TB, n, pad int, vrps bool) *Snapshot {
	t.Helper()
	r := &Registry{name: "RIPE", text: true, byPrefix: map[netip.Prefix][]int{}}
	remarks := "remarks:        " + strings.Repeat("x", pad) + "\n"
	for i := 0; i < n; i++ {
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}), 24)
		text := fmt.Sprintf("route:          %s\norigin:         AS64500\n%ssource:         RIPE\n", p, remarks)
		r.routes = append(r.routes, route{prefix: p, origin: 64500, text: text})
	}
	shared := netip.MustParsePrefix("198.51.100.0/24")
	for i := 0; i < n; i++ {
		as := types.ASN(65536 + i)
		text := fmt.Sprintf("route:          %s\norigin:         %s\nsource:         RIPE\n", shared, as)
		r.routes = append(r.routes, route{prefix: shared, origin: as, text: text})
	}
	slices.SortFunc(r.routes, routeCmp)
	for i, rt := range r.routes {
		r.byPrefix[rt.prefix] = append(r.byPrefix[rt.prefix], i)
	}
	var opts SnapshotOptions
	if vrps {
		v, err := rpki.NewVRPs([]rpki.VRP{{Prefix: netip.MustParsePrefix("10.0.0.0/9"), MaxLength: 24, ASN: 64500}})
		if err != nil {
			t.Fatal(err)
		}
		opts.VRPs = v
	}
	snap, err := NewSnapshot([]*Registry{r}, opts)
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

// allocated is the bytes allocated by one Do of line on a fresh session
// with budget max, averaged over a few runs, and that reply.
func allocated(snap *Snapshot, max int64, line string) (uint64, Reply) {
	var r Reply
	do := func() {
		s := NewSession(func() *Snapshot { return snap })
		s.SetMaxReply(max)
		r, _ = s.Do(context.Background(), line)
	}
	do() // warm up
	const runs = 4
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for i := 0; i < runs; i++ {
		do()
	}
	runtime.ReadMemStats(&after)
	return (after.TotalAlloc - before.TotalAlloc) / runs, r
}

// An answer far over the budget is refused without being built: what one
// command allocates stays near the budget, not near the answer's size, for
// every answer that grows with the data.
func TestBudgetStopsBuilding(t *testing.T) {
	const budget = 32 << 10
	for _, vrps := range []bool{false, true} {
		snap := bigSnapshot(t, 20000, 1000, vrps)
		for _, line := range []string{
			"!r0.0.0.0/0,M",
			"-M 0.0.0.0/0",
			"-T route -M 0.0.0.0/0",
			"-K -M 0.0.0.0/0",
			"!r198.51.100.0/24,o",
		} {
			full, _ := allocated(snap, 0, line)
			got, r := allocated(snap, budget, line)
			if want := fmt.Sprintf("F Answer larger than %d bytes\n", budget); r.text != want {
				t.Errorf("vrps %v, %q: %.60q, want the refusal", vrps, line, r.text)
			}
			// The words of ",o" are 8 bytes per route (a 160 kB answer); the
			// others about 1 kB per route (20 MB, or 7 MB with -K, whose
			// blocks are kept to drop repeats).
			if got > full/4 || got > 16*budget {
				t.Errorf("vrps %v, %q: %d bytes allocated under a budget of %d (%d without one)", vrps, line, got, budget, full)
			}
			t.Logf("vrps %v, %q: %d bytes allocated under the budget, %d without one", vrps, line, got, full)
		}
	}
}

// The budget holds at exactly its value, for every kind of answer built
// under it: a reply of N bytes passes a budget of N, and N+1 bytes are
// refused.
func TestBudgetExact(t *testing.T) {
	for _, vrps := range []bool{false, true} {
		snap := bigSnapshot(t, 300, 50, vrps)
		for _, line := range []string{
			"!r10.0.0.0/16,M",
			"!r198.51.100.0/24,o",
			"!r10.0.1.0/24",
			"!mroute,10.0.1.0/24AS64500",
			"-M 10.0.0.0/16",
			"-K -M 10.0.0.0/16",
			"-T route -x 10.0.1.0/24",
			"!s-lc",
			"!v",
		} {
			s := NewSession(func() *Snapshot { return snap })
			full, _ := s.Do(context.Background(), line)
			n := int64(full.Len())
			if n == 0 || strings.HasPrefix(full.text, "F ") || full.text == "D\n" {
				t.Fatalf("%q: %q, want an answer", line, full.text)
			}
			s.SetMaxReply(n)
			if r, _ := s.Do(context.Background(), line); r.text != full.text {
				t.Errorf("vrps %v, %q under a budget of exactly its %d bytes: %.60q", vrps, line, n, r.text)
			}
			s.SetMaxReply(n - 1)
			if r, _ := s.Do(context.Background(), line); r.text != fmt.Sprintf("F Answer larger than %d bytes\n", n-1) {
				t.Errorf("vrps %v, %q under a budget of %d: %.60q", vrps, line, n-1, r.text)
			}
		}
	}
}

// The lists of "!g", "!i" and "!a" are under the budget too.
func TestBudgetLists(t *testing.T) {
	snap := fixture(t, SnapshotOptions{})
	for _, line := range []string{"!gAS65001", "!iAS-FOO", "!iRS-FOO,1", "!aAS-FOO"} {
		s := NewSession(func() *Snapshot { return snap })
		full, _ := s.Do(context.Background(), line)
		if !strings.HasPrefix(full.text, "A") {
			t.Fatalf("%q: %q, want a list", line, full.text)
		}
		n := int64(full.Len())
		s.SetMaxReply(n)
		if r, _ := s.Do(context.Background(), line); r.text != full.text {
			t.Errorf("%q under a budget of exactly %d: %q", line, n, r.text)
		}
		s.SetMaxReply(n - 1)
		if r, _ := s.Do(context.Background(), line); r.text != fmt.Sprintf("F Answer larger than %d bytes\n", n-1) {
			t.Errorf("%q under a budget of %d: %q", line, n-1, r.text)
		}
	}
}
