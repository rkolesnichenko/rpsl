package resolve_test

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve/internal/irrdoracle"
	"github.com/rkolesnichenko/rpsl/resolve/internal/irrtest"
	"github.com/rkolesnichenko/rpsl/resolve/internal/rpsldtest"
	"github.com/rkolesnichenko/rpsl/resolve/irrdq"
	"github.com/rkolesnichenko/rpsl/types"
)

// sourceOf is an object's source:, upper-case ("" without one).
func sourceOf(o *ast.Object) string {
	if a, ok := o.GetFirst("source"); ok {
		return strings.ToUpper(strings.TrimSpace(a.Value))
	}
	return ""
}

// lastOfEach keeps, of texts, the last object of each (class, canonical
// primary key, source), in place. A registry holds one object per primary
// key, and a resolve.Corpus (so irrdq) keeps the last it is given, but
// irrtest keeps every copy; the random model can draw a route or aut-num
// twice in one source, so both are given the IRR a registry could hold.
func lastOfEach(texts []string) []string {
	key := func(text string) string {
		o, _ := rpsl.ParseObject(text)
		obj, _ := object.Decode(o)
		var pk string
		switch t := obj.(type) {
		case object.AsSet:
			pk = t.Name.String()
		case object.RouteSet:
			pk = t.Name.String()
		case object.AutNum:
			pk = t.AS.String()
		case object.Route:
			pk = t.Prefix.Masked().String() + t.Origin.String()
		case object.Route6:
			pk = t.Prefix.Masked().String() + t.Origin.String()
		default:
			pk = strings.ToUpper(strings.TrimSpace(o.Key()))
		}
		return o.Class() + "\x00" + pk + "\x00" + sourceOf(o)
	}
	last := map[string]int{}
	keys := make([]string, len(texts))
	for i, text := range texts {
		keys[i] = key(text)
		last[keys[i]] = i
	}
	var out []string
	for i, text := range texts {
		if last[keys[i]] == i {
			out = append(out, text)
		}
	}
	return out
}

// askIRRdq plays one connection's lines through a Session, as a server
// would: each reply in order, until one closes the connection.
func askIRRdq(t testing.TB, snap *irrdq.Snapshot, send string) string {
	t.Helper()
	s := irrdq.NewSession(func() *irrdq.Snapshot { return snap })
	var b strings.Builder
	lines := strings.Split(send, "\n")
	for _, l := range lines[:len(lines)-1] {
		r, err := s.Do(context.Background(), l)
		if err != nil {
			t.Fatalf("Do(%q): %v", l, err)
		}
		r.WriteTo(&b)
		if r.Close() {
			break
		}
	}
	return b.String()
}

// askTCP sends send on a fresh connection to addr and returns everything
// read until the server closes it.
func askTCP(t testing.TB, addr, send string) string {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := c.Write([]byte(send)); err != nil {
		t.Fatal(err)
	}
	var out []byte
	buf := make([]byte, 64<<10)
	for {
		n, err := c.Read(buf)
		out = append(out, buf[:n]...)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("%s did not close the connection: read %q", addr, out)
			}
			return string(out)
		}
	}
}

// firstDiffering names the command of the first reply on which got and
// want differ: reply 0 answers the "!s", reply i the command cmds[i-1].
func firstDiffering(got, want string, cmds []string) string {
	g, w := irrdoracle.Split(got), irrdoracle.Split(want)
	for i := 0; i < len(g) && i < len(w); i++ {
		if irrdoracle.Compare(irrdoracle.Words, g[i], w[i]) != nil {
			if i == 0 || i > len(cmds) {
				return "reply " + strconv.Itoa(i)
			}
			return cmds[i-1]
		}
	}
	return "the reply count"
}

// TestIRRdqMatchesIrrtest: on random IRRs, irrdq answers !i, !i…,1, !a,
// !a4, !a6, !g and !6 as irrtest (held to IRRd's recordings, Task 3) does,
// for every set and AS the IRR names, under both source orders; and
// irrdserver, serving the same snapshot on a socket, answers each pipelined
// burst byte for byte as the session does.
func TestIRRdqMatchesIrrtest(t *testing.T) {
	const seeds = 60
	total := 0
	for seed := uint64(0); seed < seeds; seed++ {
		r := rand.New(rand.NewPCG(seed, 24))
		m := randomModel(r, false)
		texts := lastOfEach(m.texts(r))
		addr := irrtest.New(texts...).WithSources("RIPE", "RADB").IRRd(t)
		snap := rpsldtest.Snapshot(t, texts, irrdq.SnapshotOptions{}, "RIPE", "RADB")
		served := rpsldtest.Serve(t, snap)
		var sets []string
		asns := map[types.ASN]bool{}
		for _, text := range texts {
			o, _ := rpsl.ParseObject(text)
			switch o.Class() {
			case "as-set", "route-set":
				sets = append(sets, strings.TrimSpace(o.Key()))
			case "route", "route6", "aut-num":
				for _, a := range []string{"origin", "aut-num"} {
					if v, ok := o.GetFirst(a); ok {
						if as, err := types.ParseASN(strings.TrimSpace(v.Value)); err == nil {
							asns[as] = true
						}
					}
				}
			}
		}
		sort.Strings(sets)
		var cmds []string
		// Each set as written (the model writes names lower-case) and
		// upper-case, as bgpq4 sends them: IRRd removes a set's own name
		// from "!i" only as sent.
		var names []string
		for _, s := range sets {
			names = append(names, s, strings.ToUpper(s))
		}
		for _, s := range append(names, "AS-NOSUCH", "RS-NOSUCH") {
			cmds = append(cmds, "!i"+s, "!i"+s+",1", "!a"+s, "!a4"+s, "!a6"+s)
		}
		for as := range asns {
			cmds = append(cmds, "!g"+as.String(), "!6"+as.String())
		}
		sort.Strings(cmds)
		for _, sel := range []string{"!sRIPE,RADB", "!sRADB,RIPE"} {
			send := "!!\n" + sel + "\n" + strings.Join(cmds, "\n") + "\n!q\n"
			got, want := askIRRdq(t, snap, send), askTCP(t, addr, send)
			if err := irrdoracle.Compare(irrdoracle.Words, got, want); err != nil {
				t.Fatalf("seed %d, %s: %s: %v", seed, sel, firstDiffering(got, want, cmds), err)
			}
			// Served on a socket by irrdserver, byte for byte the same.
			if tcp := askTCP(t, served, send); tcp != got {
				t.Fatalf("seed %d, %s: irrdserver answered otherwise than the session: %s", seed, sel, firstDiffering(tcp, got, cmds))
			}
			total += len(cmds)
		}
	}
	t.Logf("%d seeds, %d commands compared", seeds, total)
}
