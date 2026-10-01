package consist

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/ast"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/types"
)

func TestPeers(t *testing.T) {
	c := checker(t,
		autNum(1,
			"import: from AS2 accept ANY",
			"export: to AS-PEERS announce AS-ONE",
			"import: from AS-ANY accept ANY",
			"default: to AS6",
			"import: from AS1:AS-CUST:PeerAS accept ANY",
			"mp-import: from PRNG-X accept ANY",
			"import: from AS-NOPE accept ANY",
			"import-via: AS11 from AS12 accept ANY"),
		autNum(9, "export: to AS1 announce ANY"),
		"peering-set: PRNG-X\npeering: AS7\nmnt-by: MNT-A\nsource: RIPE\n")
	pl, err := c.Peers(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if want := []types.ASN{2, 3, 6, 7}; !slices.Equal(pl.Forward, want) {
		t.Errorf("Forward %v, want %v", pl.Forward, want)
	}
	if want := []string{"AS-ANY", "AS1:AS-CUST:PeerAS"}; !slices.Equal(pl.Skipped, want) {
		t.Errorf("Skipped %v, want %v", pl.Skipped, want)
	}
	if want := []types.ASN{9}; !slices.Equal(pl.Reverse, want) || pl.NoIndex {
		t.Errorf("Reverse %v NoIndex %v, want %v false", pl.Reverse, pl.NoIndex, want)
	}
	// A source that keeps no index.
	c.Eval.Src = plainSource{c.Eval.Src}
	if pl, err = c.Peers(context.Background(), 1); err != nil || !pl.NoIndex || len(pl.Reverse) != 0 {
		t.Errorf("plain source: %+v %v", pl, err)
	}
	if _, err := c.Peers(context.Background(), 99); !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("missing aut-num: %v, want ErrNotFound", err)
	}
}

// A regexp peering is skipped, as written.
func TestPeersRegexp(t *testing.T) {
	c := checker(t, autNum(1, "import: from <^AS8$> accept ANY"))
	pl, err := c.Peers(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(pl.Forward) != 0 || !slices.Equal(pl.Skipped, []string{"<^AS8$>"}) {
		t.Errorf("Forward %v Skipped %v", pl.Forward, pl.Skipped)
	}
}

// plainSource hides every method but PolicySource's.
type plainSource struct{ resolve.PolicySource }

// issueText renders an issue compactly: "rule attr#index line: message
// [peers] [afs]".
func issueText(is Issue) string {
	var afs []string
	for _, af := range is.AFs {
		afs = append(afs, af.String())
	}
	return fmt.Sprintf("%s %s#%d L%d: %s %v %v", is.Rule, is.Attr, is.Index, is.Span.StartLine, is.Message, is.Peers, afs)
}

func lint(t *testing.T, c *Checker, as types.ASN) []Issue {
	t.Helper()
	is, err := c.Lint(context.Background(), as)
	if err != nil {
		t.Fatal(err)
	}
	return is
}

func rulesOf(is []Issue) []string {
	var out []string
	for _, i := range is {
		out = append(out, i.Rule)
	}
	return out
}

func TestLintShadowed(t *testing.T) {
	is := lint(t, checker(t, autNum(1, "import: from AS2 accept ANY", "import: from AS2 accept AS-ONE"), autNum(2)), 1)
	if len(is) != 1 {
		t.Fatalf("issues %v", is)
	}
	i := is[0]
	if i.Rule != RuleShadowed || i.Severity != ast.Warning || i.Attr != "import" || i.Index != 1 || i.Span.StartLine != 4 ||
		!slices.Equal(i.Peers, []types.ASN{2}) || len(i.AFs) != 1 || i.AFs[0] != v4 {
		t.Errorf("issue %s", issueText(i))
	}
}

func TestLintNotPartiallyShadowed(t *testing.T) {
	is := lint(t, checker(t,
		autNum(1, "import: from AS2 accept {10.1.0.0/16}", "import: from AS2 accept {10.1.0.0/16, 10.9.0.0/16}"), autNum(2)), 1)
	if len(is) != 0 {
		t.Errorf("issues %v", is)
	}
}

func TestLintShadowedSymbolic(t *testing.T) {
	// A broader term with fewer tests first: the narrower one is shadowed.
	is := lint(t, checker(t,
		autNum(1, "import: from AS2 accept <^AS2$>", "import: from AS2 accept <^AS2$> AND {10.0.0.0/8^+}"), autNum(2)), 1)
	if got := rulesOf(is); !slices.Equal(got, []string{RuleShadowed}) {
		t.Errorf("rules %v", got)
	}
	// The other way round, nothing is.
	is = lint(t, checker(t,
		autNum(1, "import: from AS2 accept <^AS2$> AND {10.0.0.0/8^+}", "import: from AS2 accept <^AS2$>"), autNum(2)), 1)
	if len(is) != 0 {
		t.Errorf("issues %v", is)
	}
	// A test the earlier term lacks does not shadow: <^AS2$> does not cover
	// routes failing it.
	is = lint(t, checker(t,
		autNum(1, "import: from AS2 accept <^AS2$>", "import: from AS2 accept ANY"), autNum(2)), 1)
	if len(is) != 0 {
		t.Errorf("issues %v", is)
	}
}

func TestLintRules(t *testing.T) {
	for _, c := range []struct {
		name    string
		objects []string
		want    []string // issueText prefixes, in order
	}{
		{
			name:    "empty",
			objects: []string{autNum(1, "import: from AS2 accept NOT ANY"), autNum(2)},
			want:    []string{"lint/empty import#0 L3:"},
		},
		{
			name:    "missing set in a filter",
			objects: []string{autNum(1, "import: from AS2 accept AS-NOPE"), autNum(2)},
			want:    []string{"lint/empty import#0 L3:", "lint/missing-set import#0 L3:"},
		},
		{
			name:    "missing set in a peering",
			objects: []string{autNum(1, "import: from AS2 accept ANY", "import: from AS-NOPE accept ANY"), autNum(2)},
			want:    []string{"lint/missing-set import#1 L4:"},
		},
		{
			name:    "missing router",
			objects: []string{autNum(1, "import: from AS2 r9.example.net accept ANY"), autNum(2)},
			want:    []string{"lint/missing-router import#0 L3:", "lint/undecided import#0 L3:"},
		},
		{
			name:    "missing rtr-set",
			objects: []string{autNum(1, "import: from AS2 at RTRS-NOPE accept ANY"), autNum(2)},
			want:    []string{"lint/missing-set import#0 L3:", "lint/undecided import#0 L3:"},
		},
		{
			name:    "a peer without an aut-num",
			objects: []string{autNum(1, "import: from AS3 accept ANY")},
			want:    []string{"lint/no-aut-num #-1 L0:"},
		},
		{
			name:    "undecided",
			objects: []string{autNum(1, "import: from AS2 192.0.2.1 accept ANY"), autNum(2)},
			want:    []string{"lint/undecided import#0 L3:"},
		},
		{
			name:    "a default's empty networks",
			objects: []string{autNum(1, "default: to AS2 networks NOT ANY"), autNum(2)},
			want:    []string{"lint/empty default#0 L3:"},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			is := lint(t, checker(t, c.objects...), 1)
			var got []string
			for _, i := range is {
				got = append(got, issueText(i))
			}
			if len(got) != len(c.want) {
				t.Fatalf("issues\n%s\nwant prefixes %v", strings.Join(got, "\n"), c.want)
			}
			for k := range got {
				if !strings.HasPrefix(got[k], c.want[k]) {
					t.Errorf("issue %d: %s, want prefix %s", k, got[k], c.want[k])
				}
			}
		})
	}
}

// A policy naming no concrete peer is still linted: missing sets statically,
// AS-ANY through a session with the reserved AS4294967295 (no peer listed).
func TestLintWithoutConcretePeers(t *testing.T) {
	for _, c := range []struct {
		name    string
		objects []string
		want    []string // full issueText, in order
	}{
		{
			name:    "a missing set as the only peering",
			objects: []string{autNum(1, "import: from AS-NOPE accept ANY")},
			want:    []string{"lint/missing-set import#0 L3: the policy names AS-NOPE, which is not in the source [] []"},
		},
		{
			name:    "AS-ANY with a missing filter set",
			objects: []string{autNum(1, "import: from AS-ANY accept AS-NOPE"), autNum(2)},
			want: []string{
				"lint/empty import#0 L3: import term AS-ANY | AS-NOPE accepts no route [] [ipv4.unicast]",
				"lint/missing-set import#0 L3: the policy names AS-NOPE, which is not in the source [] []",
			},
		},
		{
			name:    "AS-ANY shadowed",
			objects: []string{autNum(1, "import: from AS-ANY accept ANY", "import: from AS-ANY accept AS-ONE")},
			want:    []string{"lint/shadowed import#1 L4: import term AS-ANY | AS-ONE never decides: earlier terms accept every route it accepts [] [ipv4.unicast]"},
		},
		{
			name:    "AS-ANY shadowed, a reverse peer",
			objects: []string{autNum(1, "import: from AS-ANY accept ANY", "import: from AS-ANY accept AS-ONE"), autNum(9, "export: to AS1 announce ANY")},
			want:    []string{"lint/shadowed import#1 L4: import term AS-ANY | AS-ONE never decides: earlier terms accept every route it accepts [AS9] [ipv4.unicast]"},
		},
		{
			name: "a set missing inside an existing one",
			objects: []string{autNum(1, "import: from AS2 accept AS-OUTER"), autNum(2),
				"as-set: AS-OUTER\nmembers: AS-GONE\nmnt-by: MNT-A\nsource: RIPE\n"},
			want: []string{
				"lint/empty import#0 L3: import term AS2 | AS-OUTER accepts no route [AS2] [ipv4.unicast]",
				"lint/missing-set import#0 L3: the filter names AS-GONE, which is not in the source [AS2] [ipv4.unicast]",
			},
		},
		{
			// A set reported missing for one attribute is still reported for
			// another that reaches it inside an existing set.
			name: "one missing set, two attributes",
			objects: []string{autNum(1, "import: from AS-NOPE accept ANY", "export: to AS2 announce AS-BIG"), autNum(2),
				"as-set: AS-BIG\nmembers: AS-NOPE\nmnt-by: MNT-A\nsource: RIPE\n"},
			want: []string{
				"lint/missing-set import#0 L3: the policy names AS-NOPE, which is not in the source [] []",
				"lint/empty export#0 L4: export term AS2 | AS-BIG accepts no route [AS2] [ipv4.unicast]",
				"lint/missing-set export#0 L4: the filter names AS-NOPE, which is not in the source [AS2] [ipv4.unicast]",
			},
		},
		{
			// PeerAS and set templates mean nothing toward the sentinel: no
			// lint/empty, no missing AS1:AS-CUST:AS4294967295.
			name:    "AS-ANY with PeerAS",
			objects: []string{autNum(1, "import: from AS-ANY accept PeerAS", "import: from AS-ANY accept AS1:AS-CUST:PeerAS")},
		},
		{
			// NOT PeerAS toward the sentinel would be every route: it must not
			// shadow a later term.
			name:    "AS-ANY with NOT PeerAS first",
			objects: []string{autNum(1, "import: from AS-ANY accept NOT PeerAS", "import: from AS-ANY accept AS-ONE")},
		},
		{
			// Ruling R15: PeerAS inside a filter-set is as peer-dependent as
			// one written in the term: no lint/shadowed toward the sentinel.
			name: "AS-ANY with PeerAS inside a filter-set",
			objects: []string{autNum(1, "import: from AS-ANY accept {10.1.0.0/16}", "import: from AS-ANY accept FLTR-PEER"),
				"filter-set: FLTR-PEER\nfilter: PeerAS OR {10.1.0.0/16}\nmnt-by: MNT-A\nsource: RIPE\n"},
		},
		{
			// …and inside a filter-set's AS-path regexp.
			name: "AS-ANY with a regexp naming PeerAS inside a filter-set",
			objects: []string{autNum(1, "import: from AS-ANY accept <^AS1>", "import: from AS-ANY accept FLTR-PEER-RE"),
				"filter-set: FLTR-PEER-RE\nfilter: <^PeerAS> OR <^AS1>\nmnt-by: MNT-A\nsource: RIPE\n"},
		},
		{
			// A filter-set without PeerAS is linted toward the sentinel.
			name: "AS-ANY with a filter-set of no peer",
			objects: []string{autNum(1, "import: from AS-ANY accept {10.1.0.0/16}", "import: from AS-ANY accept FLTR-PLAIN"),
				"filter-set: FLTR-PLAIN\nfilter: {10.1.0.0/16}\nmnt-by: MNT-A\nsource: RIPE\n"},
			want: []string{"lint/shadowed import#1 L4: import term AS-ANY | FLTR-PLAIN never decides: earlier terms accept every route it accepts [] [ipv4.unicast]"},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			var got []string
			for _, i := range lint(t, checker(t, c.objects...), 1) {
				got = append(got, issueText(i))
			}
			if !slices.Equal(got, c.want) {
				t.Errorf("issues\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(c.want, "\n"))
			}
		})
	}
}

func TestLintMergesSessions(t *testing.T) {
	is := lint(t, checker(t,
		autNum(1, "mp-import: afi any from AS2 OR AS3 accept ANY", "mp-import: afi any from AS2 OR AS3 accept AS-ONE"),
		autNum(2), autNum(3)), 1)
	if len(is) != 1 {
		t.Fatalf("issues %v", is)
	}
	i := is[0]
	if i.Rule != RuleShadowed || i.Attr != "mp-import" || !slices.Equal(i.Peers, []types.ASN{2, 3}) || !slices.Equal(i.AFs, []types.AddrFamily{v4, v6}) {
		t.Errorf("issue %s", issueText(i))
	}
}

func TestLintLimit(t *testing.T) {
	c := checker(t, autNum(1, "import: from AS2 accept AS-A"), autNum(2),
		"as-set: AS-A\nmembers: AS-B\nmnt-by: MNT-A\nsource: RIPE\n",
		"as-set: AS-B\nmembers: AS-C\nmnt-by: MNT-A\nsource: RIPE\n",
		"as-set: AS-C\nmembers: AS1\nmnt-by: MNT-A\nsource: RIPE\n")
	c.Eval.Expander = resolve.Expander{MaxDepth: 1}
	is := lint(t, c, 1)
	if got := rulesOf(is); !slices.Contains(got, RuleLimit) {
		t.Errorf("rules %v, want a lint/limit", got)
	}
}

func TestLintMissingAutNum(t *testing.T) {
	if _, err := checker(t).Lint(context.Background(), 99); !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("err %v, want ErrNotFound", err)
	}
}

func TestRules(t *testing.T) {
	want := []string{RuleShadowed, RuleEmpty, RuleMissingSet, RuleMissingRouter, RuleNoAutNum, RuleUndecided, RuleLimit}
	if !slices.Equal(Rules(), want) {
		t.Errorf("Rules %v", Rules())
	}
	for _, r := range want {
		if _, ok := ruleSeverity[r]; !ok {
			t.Errorf("%s has no severity", r)
		}
	}
	_ = peval.WhyPeerRouter // the undecided message carries peval's Why
}

// AS0 is reserved (RFC 7607) and never a session's peer: a peering naming
// it, directly or through an as-set, is skipped as "AS0", and Lint runs no
// session toward it.
func TestPeersAS0(t *testing.T) {
	for _, c := range []struct {
		name    string
		objects []string
		forward []types.ASN
	}{
		{"direct", []string{autNum(1, "import: from AS0 accept ANY", "export: to AS0 announce AS1")}, nil},
		{"through an as-set", []string{autNum(1, "import: from AS-IX accept ANY"), autNum(2),
			"as-set: AS-IX\nmembers: AS0, AS2\nmnt-by: MNT-A\nsource: RIPE\n"}, []types.ASN{2}},
		{"mp-import", []string{autNum(1, "mp-import: afi ipv6.unicast from AS0 accept ANY", "import: from AS-ANY accept ANY")}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			ch := checker(t, c.objects...)
			pl, err := ch.Peers(context.Background(), 1)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(pl.Forward, c.forward) || !slices.Contains(pl.Skipped, "AS0") || slices.Contains(pl.Reverse, 0) {
				t.Errorf("Forward %v Skipped %v Reverse %v, want Forward %v and AS0 skipped", pl.Forward, pl.Skipped, pl.Reverse, c.forward)
			}
			if !slices.IsSorted(pl.Skipped) || len(slices.Compact(slices.Clone(pl.Skipped))) != len(pl.Skipped) {
				t.Errorf("Skipped %v: not sorted or repeated", pl.Skipped)
			}
			if _, err := ch.Lint(context.Background(), 1); err != nil {
				t.Errorf("Lint: %v", err)
			}
		})
	}
}

// A session whose filter cannot be normalized — AS1887's shape: an AS-path
// regexp names a set that reaches AS-ANY — is a lint/undecided issue with
// no attribute, and the other sessions are still linted; Check still
// returns the error.
func TestLintFilterNotEvaluable(t *testing.T) {
	for _, c := range []struct {
		name    string
		objects []string
		wantErr func(error) bool
	}{
		{
			name: "AS-ANY inside a regexp's set",
			objects: []string{
				autNum(1, "export: to AS2 announce <AS1:AS-CUST:AS-RCVD> OR <AS1:AS-PEERS:AS-RCVD$>", "import: from AS3 accept AS-NOPE"),
				autNum(2, "import: from AS1 accept <AS1:AS-PEERS:AS-RCVD$>"), autNum(3),
				"as-set: AS1:AS-CUST:AS-RCVD\nmembers: AS1\nmnt-by: MNT-A\nsource: RIPE\n",
				"as-set: AS1:AS-PEERS:AS-RCVD\nmembers: AS1:AS-PEERS:AS2\nmnt-by: MNT-A\nsource: RIPE\n",
				"as-set: AS1:AS-PEERS:AS2\nmembers: AS-ANY\nmnt-by: MNT-A\nsource: RIPE\n",
			},
			wantErr: func(err error) bool { var e *resolve.AnySetError; return errors.As(err, &e) },
		},
		{
			name: "a cycle of filter-sets through a regexp",
			objects: []string{
				autNum(1, "export: to AS2 announce FLTR-X", "import: from AS3 accept AS-NOPE"),
				autNum(2, "import: from AS1 accept ANY"), autNum(3),
				"filter-set: FLTR-X\nfilter: <^AS1$> OR FLTR-Y\nmnt-by: MNT-A\nsource: RIPE\n",
				"filter-set: FLTR-Y\nfilter: FLTR-X\nmnt-by: MNT-A\nsource: RIPE\n",
			},
			wantErr: func(err error) bool { var e *resolve.NotEnumerableError; return errors.As(err, &e) },
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			ch := checker(t, c.objects...)
			_, cerr := ch.Check(context.Background(), Pair{A: 1, B: 2, AF: v4})
			if !c.wantErr(cerr) {
				t.Fatalf("Check: %v, want the error peval wraps", cerr)
			}
			is := lint(t, ch, 1)
			var undecided []Issue
			for _, i := range is {
				if i.Rule == RuleUndecided {
					undecided = append(undecided, i)
				}
			}
			if len(undecided) != 1 {
				t.Fatalf("issues\n%v\nwant one lint/undecided", is)
			}
			u := undecided[0]
			if u.Attr != "" || u.Index != -1 || u.Message != cerr.Error() || u.Severity != ast.Info ||
				!slices.Equal(u.Peers, []types.ASN{2}) || !slices.Equal(u.AFs, []types.AddrFamily{v4}) {
				t.Errorf("issue %s, want the error %q for AS2 in ipv4.unicast", issueText(u), cerr)
			}
			// The session toward AS3 is still linted: its missing filter set.
			if !slices.ContainsFunc(is, func(i Issue) bool { return i.Rule == RuleEmpty && slices.Equal(i.Peers, []types.ASN{3}) }) {
				t.Errorf("issues\n%v\nwant AS3's session linted", is)
			}
		})
	}
}

// Ruling R15 (completing R8): a member-of: claimant aut-num is kept whole by
// a Corpus, positions and all, yet its issues' spans are relative to the
// object, as every other aut-num's are.
func TestLintSpansAreObjectRelative(t *testing.T) {
	const dump = `route: 10.1.0.0/16
origin: AS65011
mnt-by: MNT-A
source: RIPE

as-set: AS-CLAIM
members: AS65012
mbrs-by-ref: MNT-A
mnt-by: MNT-A
source: RIPE

# a comment before the object
aut-num: AS65010
as-name: TEN
member-of: AS-CLAIM
import: from AS65011 accept ANY
import: from AS65011 accept {10.1.0.0/16}
mnt-by: MNT-A
source: RIPE
`
	l := &resolve.DumpLoader{Sources: []string{"RIPE"}, KeepPolicy: true}
	if err := l.Read(strings.NewReader(dump)); err != nil {
		t.Fatal(err)
	}
	c := &Checker{Eval: peval.Evaluator{Src: l.Source()}}
	is := lint(t, c, 65010)
	var got []string
	for _, i := range is {
		if i.Rule == RuleShadowed {
			got = append(got, fmt.Sprintf("L%d-%d C%d B%d", i.Span.StartLine, i.Span.EndLine, i.Span.StartCol, i.Span.StartByte))
		}
	}
	// The second import: is the object's fifth line, 82 bytes in:
	// "aut-num: AS65010\n" (17), "as-name: TEN\n" (13),
	// "member-of: AS-CLAIM\n" (20), "import: from AS65011 accept ANY\n" (32).
	if want := []string{"L5-5 C1 B82"}; !slices.Equal(got, want) {
		t.Errorf("shadowed spans %v, want %v; issues %v", got, want, is)
	}
}

// evilSource answers AS-EVIL with a route-set of that name.
type evilSource struct{ resolve.PolicySource }

func (s evilSource) GetSet(ctx context.Context, ref types.SetRef) (object.NamedSet, error) {
	if ref.Name().String() == "AS-EVIL" {
		return object.RouteSet{Name: ref.Name()}, nil
	}
	return s.PolicySource.GetSet(ctx, ref)
}

// The static walk treats a set whose class is not its name's as missing, as
// the engine does.
func TestLintSetOfAnotherClass(t *testing.T) {
	c := checker(t, autNum(1, "import: from AS2 accept AS-EVIL"), autNum(2))
	c.Eval.Src = evilSource{c.Eval.Src}
	var got []string
	for _, i := range lint(t, c, 1) {
		if i.Rule == RuleMissingSet && i.Peers == nil {
			got = append(got, issueText(i))
		}
	}
	if want := []string{"lint/missing-set import#0 L3: the policy names AS-EVIL, which is not in the source [] []"}; !slices.Equal(got, want) {
		t.Errorf("static missing-set issues %v, want %v", got, want)
	}
}

// A peer's aut-num is looked up in the Evaluator's registry, as Check looks
// it up: one only another registry holds is lint/no-aut-num.
func TestLintPeerAutNumSource(t *testing.T) {
	c := checker(t, autNum(1, "import: from AS2 accept ANY"),
		strings.Replace(autNum(2), "source: RIPE", "source: RADB", 1))
	c.Eval.Source = "RIPE"
	var got []string
	for _, i := range lint(t, c, 1) {
		got = append(got, i.Rule)
	}
	if !slices.Contains(got, RuleNoAutNum) {
		t.Errorf("rules %v, want %s", got, RuleNoAutNum)
	}
	r := check(t, c, Pair{A: 1, B: 2, AF: v4})
	if kinds(r.AtoB)[0] != "no-aut-num" {
		t.Errorf("Check: AtoB %v", kinds(r.AtoB))
	}
}
