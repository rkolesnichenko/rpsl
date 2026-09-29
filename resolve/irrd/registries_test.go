package irrd

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/internal/irrtest"
	"github.com/rkolesnichenko/rpsl/types"
)

// radbSerialRange is whois.radb.net's answer to "!j-*" on 2026-09-28 (one
// read-only query), the form IRRd 4's handle_irrd_database_serial_range
// writes: NAME:<journal Y|N>:<0-newest serial, or ->[:<last export serial>].
const radbSerialRange = `RADB:N:0-6248424
LACNIC:N:0-559895:135331
IDNIC:N:0-1543
AFRINIC:N:0-1781934
RIPE:N:0-66028019
RIPE-NONAUTH:N:0-66028019
BELL:N:0-251074:13362
NTTCOM:N:0-3215055:240513
ALTDB:N:0-159206:13936
PANIX:N:0-113
NESTEGG:N:0-49
LEVEL3:N:0-54931
ARIN:N:0-11462841
JPIRR:N:0-339931:424
BBOI:N:0-19719:272
CANARIE:N:0-5471:345
REACH:N:0-874054:47
TC:N:0-373814:36595
APNIC:N:0-16631742
RPKI:N:-
`

func TestParseRegistries(t *testing.T) {
	got := parseRegistries([]byte(radbSerialRange))
	want := []string{"AFRINIC", "ALTDB", "APNIC", "ARIN", "BBOI", "BELL", "CANARIE", "IDNIC", "JPIRR", "LACNIC",
		"LEVEL3", "NESTEGG", "NTTCOM", "PANIX", "RADB", "REACH", "RIPE", "RIPE-NONAUTH", "RPKI", "TC"}
	if keys := slices.Sorted(maps.Keys(got)); !slices.Equal(keys, want) {
		t.Errorf("RADB's answer: %v; want %v", keys, want)
	}
	for _, tc := range []struct {
		payload string
		want    []string // nil: unreadable, so the Source probes instead
	}{
		{"ripe:N:0-1\r\nFOO:X:Database unknown\n", []string{"RIPE"}},
		{"", nil},
		{"FOO:X:Database unknown", nil},
		{"RIPE:N:0-1\nnot a registry line\n", nil},
		{"RI PE:N:-\n", nil},
		{"RIPE\n", nil},
	} {
		got := parseRegistries([]byte(tc.payload))
		if tc.want == nil {
			if got != nil {
				t.Errorf("parseRegistries(%q) = %v; want nil", tc.payload, got)
			}
			continue
		}
		if keys := slices.Sorted(maps.Keys(got)); !slices.Equal(keys, tc.want) {
			t.Errorf("parseRegistries(%q) = %v; want %v", tc.payload, keys, tc.want)
		}
	}
}

// countingDial dials addr, counting the dials.
func countingDial(addr string, n *atomic.Int32) func(context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		n.Add(1)
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
}

func scopedCount(s *Source) (subs int, refused int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.scoped), len(s.refused)
}

// TestUnlistedRegistriesCostNothing: data can name any number of registries
// (an as-set of 2,000 "FAKEi::AS-Yi" src-members). The Source learns the
// server's registries once with "!j-*", so the fakes cost that one query and
// neither a connection nor a sub-source each; a real registry still resolves.
func TestUnlistedRegistriesCostNothing(t *testing.T) {
	for _, c := range []struct {
		pipeline  int
		keepAlive bool
	}{{0, false}, {0, true}, {4, false}} {
		db := irrtest.New(
			"as-set: AS-X\nmembers: AS1\nsource: RIPE\n",
			"as-set: AS-X\nmembers: AS2\nsource: RADB\n",
		)
		var dials atomic.Int32
		src := &Source{Sources: []string{"RADB"}, Pipeline: c.pipeline, KeepAlive: c.keepAlive, Timeout: 5 * time.Second,
			Dial: countingDial(db.IRRd(t), &dials)}
		ctx := context.Background()
		if _, err := src.GetSet(ctx, types.Ref(mustName(t, "AS-X"))); err != nil {
			t.Fatal(err)
		}
		base := dials.Load()
		for i := 0; i < 500; i++ {
			r := mustRef(t, fmt.Sprintf("FAKE%d::AS-Y%d", i, i))
			if _, err := src.GetSet(ctx, r); !errors.Is(err, resolve.ErrNotFound) {
				t.Fatalf("%+v: %s: err = %v; want ErrNotFound", c, r, err)
			}
			if _, err := src.AutNum(ctx, 1, fmt.Sprintf("FAKE%d", i)); !errors.Is(err, resolve.ErrNotFound) {
				t.Fatalf("%+v: AutNum in FAKE%d: err = %v; want ErrNotFound", c, i, err)
			}
		}
		if extra := dials.Load() - base; extra > 1 {
			t.Errorf("%+v: 500 unlisted registries cost %d dials; want at most 1 (the \"!j-*\")", c, extra)
		}
		if subs, refused := scopedCount(src); subs != 0 || refused != 0 {
			t.Errorf("%+v: %d sub-sources, %d refused names kept for unlisted registries; want none", c, subs, refused)
		}
		for _, cmd := range db.Commands() {
			if len(cmd) > 6 && cmd[:6] == "!sFAKE" {
				t.Errorf("%+v: asked the server for %q", c, cmd)
				break
			}
		}
		set, err := src.GetSet(ctx, mustRef(t, "RIPE::AS-X"))
		if err != nil || set.SetSource() != "RIPE" {
			t.Errorf("%+v: RIPE::AS-X = %v, %v; want RIPE's copy", c, set, err)
		}
		if subs, _ := scopedCount(src); subs != 1 {
			t.Errorf("%+v: %d sub-sources after one real registry; want 1", c, subs)
		}
		src.Close()
		if subs, refused := scopedCount(src); subs != 0 || refused != 0 || src.regs != nil {
			t.Errorf("%+v: Close kept %d sub-sources, %d refused names, registries %v", c, subs, refused, src.regs)
		}
	}
}

// TestRefusedRegistriesAreBounded: a server that refuses "!j" leaves the
// Source to ask for each registry; each refused registry leaves its
// sub-source (which family() would otherwise walk forever), and at most
// maxRefused of their names are remembered. A remembered one costs nothing
// again; past the cap one is asked for again, and still not found.
func TestRefusedRegistriesAreBounded(t *testing.T) {
	defer func(n int) { maxRefused = n }(maxRefused)
	maxRefused = 8
	for _, pipeline := range []int{0, 2} {
		db := irrtest.New("as-set: AS-X\nmembers: AS1\nsource: RIPE\n").WithoutSerialRange()
		var dials atomic.Int32
		src := &Source{Sources: []string{"RIPE"}, Pipeline: pipeline, KeepAlive: true, Timeout: 5 * time.Second,
			Dial: countingDial(db.IRRd(t), &dials)}
		ctx := context.Background()
		for i := 0; i < 20; i++ {
			if _, err := src.GetSet(ctx, mustRef(t, fmt.Sprintf("FAKE%d::AS-X", i))); !errors.Is(err, resolve.ErrNotFound) {
				t.Fatalf("pipeline %d: FAKE%d: err = %v; want ErrNotFound", pipeline, i, err)
			}
		}
		subs, refused := scopedCount(src)
		if subs != 0 || refused != maxRefused {
			t.Errorf("pipeline %d: %d sub-sources, %d refused names; want 0 and %d", pipeline, subs, refused, maxRefused)
		}
		before := dials.Load()
		if _, err := src.GetSet(ctx, mustRef(t, "FAKE0::AS-X")); !errors.Is(err, resolve.ErrNotFound) {
			t.Fatalf("pipeline %d: remembered FAKE0: err = %v", pipeline, err)
		}
		if dials.Load() != before {
			t.Errorf("pipeline %d: a remembered refusal dialed again", pipeline)
		}
		if _, err := src.GetSet(ctx, mustRef(t, "FAKE19::AS-X")); !errors.Is(err, resolve.ErrNotFound) {
			t.Fatalf("pipeline %d: FAKE19 past the cap: err = %v", pipeline, err)
		}
		if subs, refused := scopedCount(src); subs != 0 || refused != maxRefused {
			t.Errorf("pipeline %d: past the cap: %d sub-sources, %d refused names", pipeline, subs, refused)
		}
		if set, err := src.GetSet(ctx, mustRef(t, "RIPE::AS-X")); err != nil || set.SetSource() != "RIPE" {
			t.Errorf("pipeline %d: RIPE::AS-X = %v, %v", pipeline, set, err)
		}
		src.Close()
	}
}

// TestRegistriesListedWithoutDefaults: the "!j-*" query selects no source, so
// a default Sources list the server refuses does not keep scoped lookups from
// learning the registries (unscoped lookups stay loud about it).
func TestRegistriesListedWithoutDefaults(t *testing.T) {
	db := irrtest.New("as-set: AS-X\nmembers: AS1\nsource: RIPE\n")
	src := &Source{Addr: db.IRRd(t), Sources: []string{"NOSUCH"}, Timeout: 5 * time.Second}
	defer src.Close()
	ctx := context.Background()
	if set, err := src.GetSet(ctx, mustRef(t, "RIPE::AS-X")); err != nil || set.SetSource() != "RIPE" {
		t.Errorf("RIPE::AS-X = %v, %v", set, err)
	}
	if _, err := src.GetSet(ctx, types.Ref(mustName(t, "AS-X"))); err == nil || errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("unscoped AS-X with a refused default list: err = %v; want a loud error", err)
	}
}

func mustRef(t *testing.T, s string) types.SetRef {
	t.Helper()
	r, err := types.ParseSetRef(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func mustName(t *testing.T, s string) types.SetName {
	t.Helper()
	n, err := types.ParseSetName(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// serialRangeAsked counts the "!j" commands db received.
func serialRangeAsked(db *irrtest.DB) int {
	n := 0
	for _, cmd := range db.Commands() {
		if strings.HasPrefix(cmd, "!j") {
			n++
		}
	}
	return n
}

// TestSerialRangeHangupFallsBack: a server that hangs up on "!j" — IRRd answers
// or refuses it, but another server may not know it — must not fail scoped
// lookups. Each falls back to asking for its registry with "!s", and after
// maxRegistryFailures hangups in a row the Source stops sending "!j".
func TestSerialRangeHangupFallsBack(t *testing.T) {
	for _, pipeline := range []int{0, 2} {
		db := irrtest.New(
			"as-set: AS-X\nmembers: AS1\nsource: RIPE\n",
			"as-set: AS-X\nmembers: AS2\nsource: RADB\n",
		).WithSerialRangeHangups(-1)
		src := &Source{Addr: db.IRRd(t), Sources: []string{"RADB"}, Pipeline: pipeline, KeepAlive: true,
			Timeout: 5 * time.Second}
		ctx := context.Background()
		for i := 0; i < 5; i++ {
			set, err := src.GetSet(ctx, mustRef(t, "RIPE::AS-X"))
			if err != nil || set.SetSource() != "RIPE" {
				t.Fatalf("pipeline %d, lookup %d: RIPE::AS-X = %v, %v; want RIPE's copy", pipeline, i, set, err)
			}
		}
		if _, err := src.GetSet(ctx, mustRef(t, "FAKE::AS-X")); !errors.Is(err, resolve.ErrNotFound) {
			t.Errorf("pipeline %d: FAKE::AS-X: err = %v; want ErrNotFound (by asking for FAKE)", pipeline, err)
		}
		// Each failed attempt is one "!j"; a pipelined query broken in transport
		// is retried once on a fresh pipe, so there it is two.
		asked := serialRangeAsked(db)
		want := maxRegistryFailures
		if pipeline > 0 {
			want *= 2
		}
		if asked != want {
			t.Errorf("pipeline %d: \"!j\" sent %d times; want %d", pipeline, asked, want)
		}
		for i := 0; i < 5; i++ {
			if _, err := src.GetSet(ctx, mustRef(t, "RIPE::AS-X")); err != nil {
				t.Fatalf("pipeline %d: RIPE::AS-X after giving up on \"!j\": %v", pipeline, err)
			}
		}
		if n := serialRangeAsked(db); n != asked {
			t.Errorf("pipeline %d: \"!j\" sent again after giving up (%d, then %d)", pipeline, asked, n)
		}
		src.Close()
	}
}

// TestSerialRangeHangupOnceThenLearns: one hangup is a transient fault. That
// lookup falls back to "!s"; the next learns the registries, after which
// unlisted registries cost no connection.
func TestSerialRangeHangupOnceThenLearns(t *testing.T) {
	db := irrtest.New("as-set: AS-X\nmembers: AS1\nsource: RIPE\n").WithSerialRangeHangups(1)
	var dials atomic.Int32
	src := &Source{Sources: []string{"RIPE"}, KeepAlive: true, Timeout: 5 * time.Second,
		Dial: countingDial(db.IRRd(t), &dials)}
	defer src.Close()
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if _, err := src.GetSet(ctx, mustRef(t, "RIPE::AS-X")); err != nil {
			t.Fatalf("lookup %d: %v", i, err)
		}
	}
	base := dials.Load()
	for i := 0; i < 100; i++ {
		if _, err := src.GetSet(ctx, mustRef(t, fmt.Sprintf("FAKE%d::AS-X", i))); !errors.Is(err, resolve.ErrNotFound) {
			t.Fatalf("FAKE%d::AS-X: err = %v; want ErrNotFound", i, err)
		}
	}
	if extra := dials.Load() - base; extra != 0 {
		t.Errorf("100 unlisted registries cost %d dials after the registries were learned; want 0", extra)
	}
	if n := serialRangeAsked(db); n != 2 {
		t.Errorf("\"!j\" sent %d times; want 2 (the hangup, then the answer)", n)
	}
}

// TestSerialRangeCancelIsNotAFailure: a caller that gives up while "!j-*" is
// in flight is not the server failing: it is not counted, and the next caller
// learns the registries.
func TestSerialRangeCancelIsNotAFailure(t *testing.T) {
	db := irrtest.New("as-set: AS-X\nmembers: AS1\nsource: RIPE\n")
	src := &Source{Addr: db.IRRd(t), Sources: []string{"RIPE"}, Timeout: 5 * time.Second}
	defer src.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := src.GetSet(ctx, mustRef(t, "RIPE::AS-X")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled lookup: err = %v; want context.Canceled", err)
	}
	src.mu.Lock()
	failures := src.regFailures
	src.mu.Unlock()
	if failures != 0 {
		t.Errorf("a cancelled lookup counted %d registry-list failures; want 0", failures)
	}
	if _, err := src.GetSet(context.Background(), mustRef(t, "RIPE::AS-X")); err != nil {
		t.Fatal(err)
	}
	if known, err := src.registries(context.Background()); err != nil || !known["RIPE"] {
		t.Errorf("registries after the cancel = %v, %v; want learned, with RIPE", known, err)
	}
}
