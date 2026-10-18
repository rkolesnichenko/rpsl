package rtconfig

import (
	"errors"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/internal/cfgsim"
	"github.com/rkolesnichenko/rpsl/resolve/internal/routemodel"
	"github.com/rkolesnichenko/rpsl/types"
)

// fuzzPaths are the synthetic paths FuzzTranslateRegexp compares on: every
// path of up to three ASes over {1, 2, 10, 11}, and a few longer ones.
var fuzzPaths = func() [][]types.ASN {
	alphabet := []types.ASN{1, 2, 10, 11}
	paths := [][]types.ASN{{}}
	for n, from := 0, 0; n < 3; n++ {
		to := len(paths)
		for _, p := range paths[from:to] {
			for _, a := range alphabet {
				paths = append(paths, append(append([]types.ASN(nil), p...), a))
			}
		}
		from = to
	}
	return append(paths, []types.ASN{1, 1, 1, 1}, []types.ASN{2, 10, 11, 10, 1}, []types.ASN{1, 2, 1, 2, 1, 2})
}()

// FuzzTranslateRegexp: no AS-path regexp panics the translator; one a vendor
// translates is refused only with ErrUnsupported, and the translation matches,
// under that dialect's own matcher (cfgsim), exactly the fuzzPaths the RFC
// matcher (routemodel) says the regexp matches, its sets bound to AS10 and
// AS11 and PeerAS to AS2. A regexp naming AS-ALL, bound to a set reaching
// AS-ANY (resolve.NewAnyASNSet), is never translated: every vendor refuses
// it, with CauseAnySet or with the cause the same regexp is refused with
// when AS-ALL is an ordinary set (one met before the set).
func FuzzTranslateRegexp(f *testing.F) {
	for _, s := range []string{
		"AS1", "^AS1$", "^AS1 .* AS2$", "^AS1 AS-FOO$", "^AS-EMPTY", "^AS1+$", "^(AS1 | AS2) .+$",
		"^[AS1 AS5 - AS7]$", "^AS1{2,3}$", "^AS1~*$", "^$", "^. .* AS-ANY$", "(AS1 | ^AS2)",
		"[^AS1]", "AS-FOO~*", "AS1 ^AS2", "AS1*", "^PeerAS+ AS10?$", "AS1{0,2} AS2",
		"^AS1 AS-ALL$", "[AS-ALL AS1]", "AS-ALL~*", "[AS-ANY AS-ALL]", "(AS1 | AS-ALL)", "AS1{40} AS-ALL",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 64 {
			return
		}
		re, err := policy.ParseASPathRegexp(s)
		if err != nil {
			return
		}
		if re.UsesPeer() {
			re = re.Bind(2)
		}
		m := resolve.PathMatch{RE: re, Sets: map[types.SetName]resolve.ASNSet{}}
		anySet := resolve.PathMatch{RE: re, Sets: map[types.SetName]resolve.ASNSet{}}
		namesAll := false
		for _, n := range re.SetNames() {
			m.Sets[n] = resolve.NewASNSet(10, 11)
			anySet.Sets[n] = m.Sets[n]
			if strings.EqualFold(n.String(), "AS-ALL") {
				anySet.Sets[n], namesAll = resolve.NewAnyASNSet(), true
			}
		}
		if namesAll {
			for _, v := range Vendors() {
				g := &Generator{Vendor: v}
				tr, err := g.translatePath(anySet, s)
				var ue, fe *UnsupportedError
				if !errors.As(err, &ue) {
					t.Fatalf("%v <%s>, AS-ALL reaching AS-ANY: translated as %q, %v", v, s, tr, err)
				}
				if _, ferr := g.translatePath(m, s); ue.Cause != CauseAnySet && (!errors.As(ferr, &fe) || fe.Cause != ue.Cause) {
					t.Fatalf("%v <%s>, AS-ALL reaching AS-ANY: refused with %q; as an ordinary set: %v", v, s, ue.Cause, ferr)
				}
			}
		}
		want := make([]bool, len(fuzzPaths))
		for i, p := range fuzzPaths {
			ok, err := routemodel.MatchPath(m, p)
			if errors.Is(err, routemodel.ErrTooComplex) || errors.Is(err, routemodel.ErrNotSingleAS) {
				return
			}
			if err != nil {
				t.Fatalf("routemodel.MatchPath(<%s>, %v): %v", s, p, err)
			}
			want[i] = ok
		}
		for _, v := range Vendors() {
			g := &Generator{Vendor: v}
			tr, err := g.translatePath(m, s)
			if errors.Is(err, ErrUnsupported) {
				continue
			}
			if err != nil {
				t.Fatalf("%v <%s>: an error that is not ErrUnsupported: %v", v, s, err)
			}
			match := cfgsim.MatchIOS
			switch v {
			case Junos:
				match = cfgsim.MatchJunos
			case BIRD2:
				match = cfgsim.MatchBIRD
			}
			for i, p := range fuzzPaths {
				got, err := match(tr, p)
				if err != nil {
					t.Fatalf("%v <%s> as %q: the dialect matcher: %v", v, s, tr, err)
				}
				if got != want[i] {
					t.Fatalf("%v <%s> as %q on path %v: %v, the RFC matcher %v", v, s, tr, p, got, want[i])
				}
			}
		}
	})
}
