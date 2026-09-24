package bulk

import (
	"compress/gzip"
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/auth"
	"github.com/rkolesnichenko/rpsl/object"
)

// acceptAll is a Verifier that accepts every credential: with it, Authorise
// shows whether each check finds the objects it needs, not whether a password
// is right. The RIPE dumps keep a placeholder in every auth: line.
type acceptAll struct{}

func (acceptAll) Verify(context.Context, object.Auth, auth.Credential) (bool, error) {
	return true, nil
}

// forEachObject decodes every object of a gzipped dump.
func forEachObject(t *testing.T, path string, f func(object.Object)) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	zr, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	for raw := range rpsl.Parse(zr) {
		if o, _ := rpsl.Decode(raw); o != nil {
			f(o)
		}
	}
}

type sampleRoute struct {
	lo, hi netip.Addr
	key    string
	route  object.Route
}

// TestRealDataAuthRouteParents authorises, under RIPE's rules, the creation of
// a sample of the RIPE Database's own routes, against the address space and
// routes around them. Every route RIPE holds was once authorised, so each must
// find a parent — a covering route, inetnum or inet6num — and a maintainer in
// it; the few that cannot (space since returned, a parent since deleted) are
// counted, and must stay rare.
func TestRealDataAuthRouteParents(t *testing.T) {
	base := os.Getenv("RPSL_REALDATA")
	if base == "" {
		t.Skip("set RPSL_REALDATA to the directory scripts/fetch-irr-dumps.sh fills")
	}
	dir := filepath.Join(base, "ripe")
	for _, f := range []string{"route", "inetnum", "mntner"} {
		if _, err := os.Stat(filepath.Join(dir, "ripe.db."+f+".gz")); err != nil {
			t.Skipf("no ripe.db.%s.gz under %s", f, dir)
		}
	}

	// Every 250th route is a sample.
	var samples []sampleRoute
	n := 0
	forEachObject(t, filepath.Join(dir, "ripe.db.route.gz"), func(o object.Object) {
		r, ok := o.(object.Route)
		if n++; !ok || n%250 != 0 || !r.Prefix.IsValid() {
			return
		}
		p := r.Prefix.Masked()
		samples = append(samples, sampleRoute{p.Addr(), last(p), p.String() + r.Origin.String(), r})
	})
	sort.Slice(samples, func(i, j int) bool { return samples[i].lo.Compare(samples[j].lo) < 0 })
	sampled := map[string]bool{}
	for _, s := range samples {
		sampled[s.key] = true
	}

	// Keep what covers a sample, and every maintainer.
	covers := func(lo, hi netip.Addr) bool {
		i := sort.Search(len(samples), func(i int) bool { return samples[i].lo.Compare(lo) >= 0 })
		for ; i < len(samples) && samples[i].lo.Compare(hi) <= 0; i++ {
			if samples[i].hi.Compare(hi) <= 0 {
				return true
			}
		}
		return false
	}
	var kept []object.Object
	forEachObject(t, filepath.Join(dir, "ripe.db.route.gz"), func(o object.Object) {
		if r, ok := o.(object.Route); ok && r.Prefix.IsValid() {
			p := r.Prefix.Masked()
			if !sampled[p.String()+r.Origin.String()] && covers(p.Addr(), last(p)) {
				kept = append(kept, o)
			}
		}
	})
	forEachObject(t, filepath.Join(dir, "ripe.db.inetnum.gz"), func(o object.Object) {
		if in, ok := o.(object.Inetnum); ok && in.Lo.IsValid() && covers(in.Lo, in.Hi) {
			kept = append(kept, o)
		}
	})
	forEachObject(t, filepath.Join(dir, "ripe.db.mntner.gz"), func(o object.Object) { kept = append(kept, o) })
	db := auth.NewMemDatabase(kept)

	outcomes := map[string]int{}
	var examples []string
	for _, s := range samples {
		d, err := auth.RIPE.Authorise(context.Background(), db,
			auth.Update{Action: auth.Create, Object: s.route}, auth.Credential{}, acceptAll{})
		if err != nil {
			t.Fatal(err)
		}
		outcome := "authorised"
		if !d.OK {
			last := d.Reasons[len(d.Reasons)-1]
			switch {
			case strings.Contains(last, "covers"):
				outcome = "no parent"
			case strings.Contains(last, "delegates no maintainer"):
				outcome = "parent delegates nothing for it"
			case strings.Contains(last, "has no auth: lines"):
				outcome = "a maintainer has no auth: lines in the dump"
			case strings.Contains(last, "no such maintainer"), strings.Contains(last, "names no maintainer"):
				outcome = "a maintainer is missing"
			default:
				outcome = "refused otherwise"
			}
			if len(examples) < 10 {
				examples = append(examples, s.key+": "+d.String())
			}
		}
		outcomes[outcome]++
	}
	t.Logf("%d sampled routes, %d objects kept: %v", len(samples), len(kept), outcomes)
	for _, e := range examples {
		t.Log(e)
	}
	if len(samples) < 100 {
		t.Fatalf("only %d sampled routes", len(samples))
	}
	// A maintainer with no auth: lines in the dump is the dump's doing (RIPE
	// removes some); every other refusal is this model's, and must stay rare.
	if bad := len(samples) - outcomes["authorised"] - outcomes["a maintainer has no auth: lines in the dump"]; bad*100 > len(samples) {
		t.Errorf("%d of %d routes could not be authorised as RIPE would (more than 1%%)", bad, len(samples))
	}
}

// last is the highest address of the masked prefix p.
func last(p netip.Prefix) netip.Addr {
	a := p.Addr().AsSlice()
	for i := p.Bits(); i < len(a)*8; i++ {
		a[i/8] |= 0x80 >> (i % 8)
	}
	hi, _ := netip.AddrFromSlice(a)
	return hi
}
