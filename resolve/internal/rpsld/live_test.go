package rpsld

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve/internal/backend"
	"github.com/rkolesnichenko/rpsl/resolve/whois"
	"github.com/rkolesnichenko/rpsl/types"
)

// ripeNotification is the RIPE Database's NRTMv4 notification file, as
// resolve/nrtm4's live tests use it.
const ripeNotification = "https://nrtm.db.ripe.net/nrtmv4/RIPE/update-notification-file.jose"

// TestLiveMirror (opt-in: RPSL_LIVE_NRTM=1, which mirrors the RIPE Database
// over NRTMv4 — about 400 MB — and RPSL_REALDATA, for the local RIPE as-set
// dump that picks the sets) runs rpsld with RIPE as an NRTMv4 mirror, and
// asks it and whois.ripe.net for the direct members of the 20 largest RIPE
// as-sets of the dump. Both sides are live, so a difference is freshness and
// is logged, not failed; a set one side has and the other has not fails.
func TestLiveMirror(t *testing.T) {
	if os.Getenv("RPSL_LIVE_NRTM") == "" {
		t.Skip("set RPSL_LIVE_NRTM=1 to mirror the RIPE Database (about 400 MB)")
	}
	dir := os.Getenv("RPSL_REALDATA")
	if dir == "" {
		t.Skip("set RPSL_REALDATA to the directory scripts/fetch-irr-dumps.sh fills")
	}
	sets := largestASSets(t, filepath.Join(dir, "ripe", "ripe.db.as-set.gz"), 20)

	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	base := m.HeapAlloc
	ctx, cancel := context.WithCancel(context.Background())
	log, code := &lockedBuffer{}, make(chan int, 1)
	begin := time.Now()
	go func() {
		code <- Run(ctx, []string{"-source", "RIPE=nrtm4:" + ripeNotification + ",key=../../nrtm4/testdata/ripe-public-key.pem",
			"-listen", "127.0.0.1:0"}, io.Discard, log, make(chan struct{}))
	}()
	exited := false // reported already, by the wait for "listening"
	t.Cleanup(func() {
		cancel()
		if exited {
			return
		}
		select {
		case c := <-code:
			if c != 0 {
				t.Errorf("exit %d; log:\n%s", c, log.String())
			}
		case <-time.After(30 * time.Second):
			t.Error("rpsld did not stop")
		}
	})
	var addr string
	for i := 0; addr == "" && i < 20*60*10; i++ { // up to 20 minutes for the snapshot
		if mm := listening.FindStringSubmatch(log.String()); mm != nil {
			addr = mm[1]
			break
		}
		select {
		case c := <-code:
			exited = true
			t.Fatalf("exited %d before listening; log:\n%s", c, log.String())
		default:
		}
		time.Sleep(100 * time.Millisecond)
	}
	if addr == "" {
		t.Fatalf("not listening after 20 minutes; log:\n%s", log.String())
	}
	ready := time.Since(begin)
	runtime.GC()
	runtime.ReadMemStats(&m)
	t.Logf("live: rpsld listening after %v; heap with the RIPE mirror held %d MB", ready.Round(time.Second), (m.HeapAlloc-base)>>20)
	for _, line := range strings.Split(strings.TrimSpace(log.String()), "\n") {
		t.Log(line)
	}
	serial := liveQuery(t, addr, "!jRIPE")
	t.Logf("live: !jRIPE answered %q", strings.TrimSpace(serial))

	ws := &whois.Source{Addr: "whois.ripe.net:43", Sources: []string{"RIPE"}}
	differ := 0
	for _, name := range sets {
		got, found := irrdMembers(t, liveQuery(t, addr, "!i"+name))
		set, err := ws.GetSet(context.Background(), types.Ref(mustSetName(t, name)))
		if err != nil {
			t.Errorf("%s: rpsld found=%v; whois.ripe.net: %v", name, found, err)
			continue
		}
		want, err := whoisMembers(ws, set)
		if err != nil {
			t.Errorf("%s: whois.ripe.net member-of claimants: %v", name, err)
			continue
		}
		if !found && len(want) > 0 {
			t.Errorf("%s: rpsld has no such set (or no members); whois.ripe.net lists %d members", name, len(want))
			continue
		}
		added, removed := diff(got, want)
		if len(added)+len(removed) > 0 {
			differ++
			t.Logf("%s: rpsld %d members, whois.ripe.net %d; only in rpsld: %v; only in whois.ripe.net: %v",
				name, len(got), len(want), added, removed)
		} else {
			t.Logf("%s: %d members, the same", name, len(got))
		}
	}
	t.Logf("live: %d sets, %d differ (at %s)", len(sets), differ, time.Now().UTC().Format(time.RFC3339))
}

// largestASSets is the n as-sets of the dump with the most members:/
// mp-members: items, largest first.
func largestASSets(t *testing.T, dump string, n int) []string {
	t.Helper()
	type sized struct {
		name string
		n    int
	}
	var all []sized
	err := backend.ReadInput(dump, func(r io.Reader) error {
		for raw := range rpsl.Parse(r) {
			if raw == nil || raw.Class() != "as-set" {
				continue
			}
			o, _ := object.Decode(raw)
			if s, ok := o.(object.AsSet); ok {
				all = append(all, sized{s.Name.String(), len(s.SetMembers())})
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].n > all[j].n || all[i].n == all[j].n && all[i].name < all[j].name })
	var out []string
	for _, s := range all[:min(n, len(all))] {
		out = append(out, s.name)
	}
	return out
}

func mustSetName(t *testing.T, s string) types.SetName {
	t.Helper()
	n, err := types.ParseSetName(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// liveQuery sends one IRRd command and returns the answer, read to the
// connection's end (the server closes it after one command without "!!").
func liveQuery(t *testing.T, addr, cmd string) string {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Minute))
	fmt.Fprintf(c, "%s\n", cmd)
	b, err := io.ReadAll(bufio.NewReader(c))
	if err != nil {
		t.Fatalf("%s: %v", cmd, err)
	}
	return string(b)
}

// irrdMembers reads a "!i" answer: the normalized members, and whether the
// set was found ("D" is not found, or a set with no members).
func irrdMembers(t *testing.T, answer string) ([]string, bool) {
	t.Helper()
	if answer == "D\n" {
		return nil, false
	}
	head, rest, ok := strings.Cut(answer, "\n")
	n, err := strconv.Atoi(strings.TrimPrefix(head, "A"))
	if !ok || !strings.HasPrefix(head, "A") || err != nil || len(rest) != n+len("C\n") || !strings.HasSuffix(rest, "C\n") {
		t.Fatalf("not an IRRd answer: %q", answer)
	}
	return normMembers(strings.Fields(rest[:n])), true
}

// whoisMembers is what IRRd's "!i" lists for set: its members:/mp-members:
// items, and the AS numbers of the aut-nums whose member-of: claims its
// mbrs-by-ref: honours.
func whoisMembers(ws *whois.Source, set object.NamedSet) ([]string, error) {
	var items []string
	if raw := set.Raw(); raw != nil {
		for _, attr := range []string{"members", "mp-members"} {
			for _, a := range raw.GetAll(attr) {
				for _, it := range a.List() {
					if it.Value != "" {
						items = append(items, it.Value)
					}
				}
			}
		}
	}
	claims, err := ws.MembersByRef(context.Background(), set)
	if err != nil {
		return nil, err
	}
	for _, o := range claims {
		if a, ok := o.(object.AutNum); ok {
			items = append(items, a.AS.String())
		}
	}
	out := normMembers(items)
	// IRRd leaves the set itself out of its own members.
	return slices.DeleteFunc(out, func(s string) bool { return s == set.SetName().String() }), nil
}

// normMembers canonicalizes AS numbers and set names, upper-cases anything
// else, and sorts and deduplicates.
func normMembers(items []string) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		it = strings.TrimSpace(it)
		if as, err := types.ParseASN(it); err == nil {
			it = as.String()
		} else if n, err := types.ParseSetName(it); err == nil {
			it = n.String()
		} else {
			it = strings.ToUpper(it)
		}
		out = append(out, it)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// diff is what only a has and what only b has, both sorted.
func diff(a, b []string) (onlyA, onlyB []string) {
	for _, x := range a {
		if _, ok := slices.BinarySearch(b, x); !ok {
			onlyA = append(onlyA, x)
		}
	}
	for _, x := range b {
		if _, ok := slices.BinarySearch(a, x); !ok {
			onlyB = append(onlyB, x)
		}
	}
	return onlyA, onlyB
}
