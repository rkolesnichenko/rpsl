package resolve_test

import (
	"bytes"
	"context"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/internal/irrtest"
	"github.com/rkolesnichenko/rpsl/resolve/internal/rpslq"
	"github.com/rkolesnichenko/rpsl/resolve/irrd"
	"github.com/rkolesnichenko/rpsl/resolve/rpki"
	"github.com/rkolesnichenko/rpsl/resolve/whois"
	"github.com/rkolesnichenko/rpsl/types"
)

// The model with IRRd's RPKI-aware mode: random ROAs over the model's address
// space, and an oracle that suppresses RPKI-invalid routes (RFC 6811, as the
// model states it) and, with the pseudo source, adds each ROA's prefix to its
// AS's routes. rpki.Filter, rpki.WriteRPSL and irrtest's IRRd emulation must
// all agree with it.

type mROA struct {
	pfx    netip.Prefix
	as     types.ASN
	maxLen int
}

// randomROAs draws up to four ROAs inside the model's universes, for its ASes,
// AS0 or an AS that has no route, with every maxLength from the prefix's own
// to the family's.
func randomROAs(r *rand.Rand, m model) []mROA {
	var out []mROA
	for k := r.IntN(5); k > 0; k-- {
		u := v4Universe
		if r.IntN(3) == 0 {
			u = v6Universe
		}
		bits := u.Addr().BitLen()
		p := netip.PrefixFrom(u.Addr(), u.Bits()-1+r.IntN(bits-u.Bits()+2)).Masked()
		if r.IntN(4) == 0 { // a sibling of the universe: covers nothing
			p = netip.PrefixFrom(p.Addr().Next().Next().Next().Next().Next().Next().Next().Next(), p.Bits()).Masked()
		}
		as := types.ASN(firstAS + r.IntN(4))
		switch r.IntN(6) {
		case 0:
			as = 0
		case 1:
			as = 64999
		}
		out = append(out, mROA{pfx: p, as: as, maxLen: p.Bits() + r.IntN(bits-p.Bits()+1)})
	}
	return out
}

// withRPKI returns the oracle for an RPKI-aware IRR with roas, serving them as
// routes when pseudo.
func (o *oracle) withRPKI(roas []mROA, pseudo bool) *oracle {
	c := *o
	c.rpki, c.roas, c.pseudo = true, roas, pseudo
	return &c
}

// suppressed reports whether an RPKI-aware IRRd hides c: a route that ROAs
// cover — a ROA prefix of its family equal to or less specific than its own —
// none of which names its origin, not AS0, with a maxLength of at least its
// length.
func (o *oracle) suppressed(c mObject) bool {
	if !o.rpki || c.class == "aut-num" {
		return false
	}
	covered := false
	for _, roa := range o.roas {
		if roa.pfx.Addr().Is4() != c.pfx.Addr().Is4() || roa.pfx.Bits() > c.pfx.Bits() || !roa.pfx.Contains(c.pfx.Addr()) {
			continue
		}
		covered = true
		if roa.as != 0 && roa.as == c.as && c.pfx.Bits() <= roa.maxLen {
			return false
		}
	}
	return covered
}

func vrpsOf(t *testing.T, roas []mROA) *rpki.VRPs {
	t.Helper()
	var vs []rpki.VRP
	for _, roa := range roas {
		vs = append(vs, rpki.VRP{Prefix: roa.pfx, MaxLength: uint8(roa.maxLen), ASN: roa.as, TA: "model"})
	}
	v, err := rpki.NewVRPs(vs)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func pseudoTexts(t *testing.T, v *rpki.VRPs) []string {
	t.Helper()
	var b strings.Builder
	if err := v.WriteRPSL(&b); err != nil {
		t.Fatal(err)
	}
	if b.Len() == 0 {
		return nil
	}
	return strings.Split(b.String(), "\n\n")
}

// A MemSource under rpki.Filter, with and without WriteRPSL's pseudo objects,
// agrees with the RPKI-aware oracle on every expansion of every random IRR.
func TestModelRPKI(t *testing.T) {
	suppressed := 0
	for seed := uint64(0); seed < 2000; seed++ {
		r := rand.New(rand.NewPCG(seed, 5))
		m := randomModel(r, false)
		texts := m.texts(r)
		roas := randomROAs(r, m)
		v := vrpsOf(t, roas)
		o := newOracle(m)
		for _, c := range m.objs {
			if o.withRPKI(roas, false).suppressed(c) {
				suppressed++
			}
		}
		label := fmt.Sprintf("seed %d, ROAs %v", seed, roas)

		plain := resolve.NewMemSource(decodeAll(t, texts), "RIPE", "RADB")
		checkModel(t, label, o.withRPKI(roas, false), texts, &rpki.Filter{Src: plain, VRPs: v}, true)

		all := append(append([]string(nil), texts...), pseudoTexts(t, v)...)
		withPseudo := resolve.NewMemSource(decodeAll(t, all), "RIPE", "RADB", "RPKI")
		checkModel(t, label+" with the RPKI source", o.withRPKI(roas, true), all, &rpki.Filter{Src: withPseudo, VRPs: v}, true)
	}
	if suppressed < 500 {
		t.Errorf("only %d routes suppressed over all seeds: the ROAs miss the model", suppressed)
	}
}

// The network backends against irrtest in IRRd's RPKI-aware mode — the server
// suppresses, and serves the pseudo source when selected — and rpki.Filter over
// a server that does neither, agree with the oracle.
func TestModelRPKIBackends(t *testing.T) {
	for seed := uint64(0); seed < 150; seed++ {
		r := rand.New(rand.NewPCG(seed, 5))
		m := randomModel(r, false)
		texts := m.texts(r)
		roas := randomROAs(r, m)
		var iroas []irrtest.ROA
		for _, roa := range roas {
			iroas = append(iroas, irrtest.ROA{Prefix: roa.pfx, ASN: roa.as, MaxLength: roa.maxLen, TA: "model"})
		}
		aware := irrtest.New(texts...).WithSources("RIPE", "RADB").WithRPKI(iroas...)
		plain := irrtest.New(texts...).WithSources("RIPE", "RADB")
		o := newOracle(m)
		label := fmt.Sprintf("seed %d, ROAs %v", seed, roas)
		for _, srcs := range [][]string{{"RIPE", "RADB", "RPKI"}, {"RIPE", "RADB"}} {
			oo := o.withRPKI(roas, len(srcs) == 3)
			ir := &irrd.Source{Addr: aware.IRRd(t), Sources: srcs, Pipeline: 4, Timeout: 5 * time.Second}
			checkModel(t, fmt.Sprintf("irrd %s %v", label, srcs), oo, texts, ir, false)
			ir.Close()
			wh := &whois.Source{Addr: aware.Whois(t), Sources: srcs, Timeout: 5 * time.Second}
			checkModel(t, fmt.Sprintf("whois %s %v", label, srcs), oo, texts, wh, false)
		}
		v := vrpsOf(t, roas)
		// "!i" folds a route-set's indirect route members into its answer, as
		// prefixes Filter cannot tell from the members: the set lists.
		folded := o.withRPKI(roas, false)
		folded.folded = true
		ir := &irrd.Source{Addr: plain.IRRd(t), Sources: []string{"RIPE", "RADB"}, Pipeline: 4, Timeout: 5 * time.Second}
		checkModel(t, "filtered irrd "+label, folded, texts, &rpki.Filter{Src: ir, VRPs: v}, false)
		ir.Close()
		wh := &whois.Source{Addr: plain.Whois(t), Sources: []string{"RIPE", "RADB"}, Timeout: 5 * time.Second}
		checkModel(t, "filtered whois "+label, o.withRPKI(roas, false), texts, &rpki.Filter{Src: wh, VRPs: v}, false)
	}
}

// rpslq --dump --rpki writes what bgpq4 writes against an RPKI-aware IRRd
// holding the same objects and ROAs: bgpq4 recursing itself (-L) and letting
// the server expand ("!a", "!i…,1"), with the pseudo source selected or not.
func TestRpslqRPKIMatchesBgpq4(t *testing.T) {
	needBgpq4Output(t)
	dir := t.TempDir()
	for seed := uint64(0); seed < 30; seed++ {
		r := rand.New(rand.NewPCG(seed, 17))
		m := randomModel(r, true)
		texts := m.texts(r)
		roas := randomROAs(r, m)
		var iroas []irrtest.ROA
		var js []string
		for _, roa := range roas {
			iroas = append(iroas, irrtest.ROA{Prefix: roa.pfx, ASN: roa.as, MaxLength: roa.maxLen, TA: "model"})
			js = append(js, fmt.Sprintf(`{"asn": %d, "prefix": "%s", "maxLength": %d, "ta": "model"}`, uint32(roa.as), roa.pfx, roa.maxLen))
		}
		dump := filepath.Join(dir, fmt.Sprintf("irr-%d.db", seed))
		vrps := filepath.Join(dir, fmt.Sprintf("vrps-%d.json", seed))
		if err := os.WriteFile(dump, []byte(strings.Join(texts, "\n")), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(vrps, []byte(`{"roas": [`+strings.Join(js, ",")+`]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		addr := irrtest.New(texts...).WithSources("RIPE", "RADB").WithRPKI(iroas...).IRRd(t)
		var tops []string
		for name := range newOracle(m).sets {
			tops = append(tops, name)
		}
		sort.Strings(tops)
		for _, top := range tops {
			for _, srcs := range []string{modelSources + ",RPKI", modelSources} {
				for _, depth := range [][]string{{"-L", "64"}, nil} {
					for _, fam := range []string{"-4", "-6"} {
						args := append(append([]string{"-S", srcs, "-p", fam}, depth...), top)
						want := runBgpq4Text(t, append([]string{"-h", addr}, args...))
						var got, errs bytes.Buffer
						if code := rpslq.Run(context.Background(), append([]string{"--dump", dump, "--rpki", vrps}, args...), &got, &errs); code != 0 {
							t.Fatalf("seed %d: rpslq %v: exit %d: %s", seed, args, code, errs.String())
						}
						if got.String() != want {
							t.Fatalf("seed %d, ROAs %v: rpslq --dump --rpki %v differs from bgpq4:\nrpslq:\n%s\nbgpq4:\n%s\nobjects:\n%s",
								seed, roas, args, got.String(), want, strings.Join(texts, "\n"))
						}
					}
				}
			}
		}
	}
}
