# Known divergences from IRRToolSet (rtconfig/peval)

`TestPevalMatchesIRRToolSet` (`resolve/peval_irrtoolset_test.go`) checks
`Expander.NormalizeFilter` against IRRToolSet 5.1.3's `peval` on random IPv4
filters, served by the in-process IRRd in `internal/irrtest`. A throwaway
spike (design doc §3) found ten IRRToolSet bugs running `rtconfig` and
`peval` together against it (D1–D10); writing v0.22's plan found three more
(D11–D13), and the rtconfig differential (`resolve/rtconfig_irrtoolset_test.go`)
three after that (D14–D16), and running the peval differential against the
Linux build one more (D17). They are pinned here, and each by a test, so a fix
on either side is caught instead of passing unnoticed.

| # | Input | rtconfig/peval does | Correct |
| --- | --- | --- | --- |
| D1 | `AS-FOO AND NOT AS10`, `NOT AS10` | `NOT ANY` | AS-FOO's routes less AS10's |
| D2 | route-set member `AS-BAZ^24-26` | `permit 0.0.0.0/0` (hijack-relevant) | AS-BAZ's routes, ^24-26 |
| D3 | IPv6 `^+` ranges, v6 filter-sets | enumerates without end | ranges |
| D4 | IPv6-only mp-import | an IPv4 route-map entry with no match: permits all IPv4 | no IPv4 entry |
| D5 | `import-via:` | silently ignored | evaluated (design §6); printers refuse (design §7) |
| D6 | `default:` with `pref` on cisco; any default on Junos | pref dropped; "default not implemented" | rendered |
| D7 | `configureRouter` | drops router-specific clauses | deferred (design §8) |
| D8 | `importGroup` with a template | empty policy | deferred (design §8) |
| D9 | exit status | 0 after "Error: no object for AS99" | non-zero |
| D10 | peval prints an AS range as `AS10-AS12`; rtconfig names an unbound PeerAS `AS4294967295`, even in its queries (`!iAS1:AS-CUST:AS4294967295,1`) | not re-parseable; a query for a set that cannot exist | `NormalFilter.String` parses back |
| D11 | IOS-XR, `NOT community.contains(5:666)` | `community matches-any <*> and not …`: refuses a route with no community | accepted, as rtconfig's own IOS rendering does |
| D12 | Junos, a clause with a community test and a prefix list | two `from policy` subroutines, a Junos policy chain: the community test decides alone (unless `-junos_and_not_or`) | both must hold |
| D13 | a session the aut-num has no policy for | a warning, and no policy: the neighbour keeps the router's default | a policy that refuses everything |
| D14 | IOS-XR, a clause that is ANY (`announce ANY`) or NOT ANY | `drop` (then `done`), which ends the policy: ANY refuses every route, NOT ANY also the routes a later clause accepts | ANY: `done`; NOT ANY: nothing |
| D15 | IOS, a session whose policy denotes no route (`accept NOT ANY`, an AS with no routes) | `neighbor … route-map MyMap_2_1 in`, with no `route-map MyMap_2_1` written or cleared: what the router already holds under that name decides | a route-map that denies |
| D16 | IOS-XR, a clause whose only AS-path regexp is negated (`NOT <AS65004>`) | an `as-path-set` holding `permit .*`, which is not RPL (its elements are `ios-regex`, `length`, …): the configuration does not load | `not as-path in …` alone |
| D17 | peval, IPv4 routes under a range-operator window beyond /32 (`AS65001^127-128`, `^126`, `^40`) | the Linux build (`scripts/build-irrtoolset.sh`, -O0; seen on aarch64 and on x86-64, both in Docker, the latter emulated) enumerates prefixes: `({10.0.0.0/31, 10.0.0.2/31})` for a /30, or invalid ones (`10.0.0.4/33`, `138.0.0.4/33`), with no pattern (`^33` and `^65` come out right); the Homebrew bottle answers `NOT ANY` | `NOT ANY`: no IPv4 prefix is longer than /32 |

## Where each is pinned

Each test fails when its divergence goes away, on either side.

| # | Pinned by |
| --- | --- |
| D1 | `TestPevalDivergences/D1`; `pevalSafe` keeps it out of `TestPevalMatchesIRRToolSet` |
| D2 | `TestRtconfigGoldens` (import-v4, 10.0.0.3, all three vendors); `TestPevalDivergences/D2` |
| D3 | `TestPevalDivergences/D3` |
| D4 | `TestRtconfigDivergences/D4`; `TestImportIPv6SessionIgnoresLegacyImport` (resolve/peval) |
| D5 | `TestRtconfigDivergences/D5` |
| D6 | `TestRtconfigDivergences/D6`; `TestTemplateModeVendors` (resolve/internal/rpslconf) |
| D7 | `TestRtconfigDivergences/D7` |
| D8 | `TestRtconfigDivergences/D8+D10` |
| D9 | `TestRtconfigDivergences/D9`; `TestTemplateModeErrors` (resolve/internal/rpslconf) |
| D10 | `TestRtconfigDivergences/D8+D10`; `TestPevalDivergences/D10` |
| D11 | `TestRtconfigGoldens` (import-v4, ciscoxr, 10.0.0.5); `TestXRReadsRtconfig` (cfgsim) |
| D12 | `TestRtconfigDivergences/D12`; `TestJunosPolicyChains` (cfgsim) |
| D13 | `TestRtconfigDivergences/D13`; `TestEmptyPolicyRejects` (resolve/rtconfig) |
| D14 | `TestRtconfigGoldens` (export-v4, ciscoxr, 10.0.0.3: ANY); `TestRtconfigDivergences/D14` (NOT ANY before a clause that accepts) |
| D15 | `TestRtconfigDivergences/D15` |
| D16 | `TestRtconfigDivergences/D16` |
| D17 | `TestPevalDivergences/D17`, on the Linux build (told by its echo, not by its answer) on the architectures seen (`d17Arches`: arm64, amd64); skipped on the bottle, which answers correctly; `pevalSafe` keeps it out of `TestPevalMatchesIRRToolSet` |

## rtconfig (`TestRtconfigMatches`, `TestRtconfigGoldens`)

The random differential draws only what rtconfig renders correctly:
- IPv4 policies over prefix lists and bare AS numbers;
- NOT over prefix lists only;
- AS-path regexps over AS numbers;
- positive community tests;
- Junos with `-junos_and_not_or`.

Three shapes it draws are wrong on one vendor, and are set aside for that
vendor only, counted in the test's log. Seeds are drawn until every vendor
rtconfig writes has compared 30 in full (at most 200; fewer fails the test),
and a vendor that has is not run again:
- **D14** on IOS-XR: a policy with a clause that `peval` finds ANY, or NOT ANY
  before another clause (about half the seeds: `pevalFilter` draws ANY often,
  so IOS-XR takes about 70 seeds to reach 30);
- **D15** on IOS: rtconfig attached a route-map it never wrote, and rpslconf's
  policy must then accept none of the routes;
- **D16** on IOS-XR: a policy with a negated regexp.

D13 is handled like D15: when rtconfig attaches nothing, rpslconf must accept
nothing.

`TestRtconfigGoldens` compares rtconfig's checked-in output for two fixed templates with rpslconf's, so it runs without rtconfig. With rtconfig installed, it also holds rtconfig to its goldens; `RPSL_RTCONFIG_UPDATE=1` rewrites them.

rtconfig writes its warnings to stderr and its configuration to stdout, one
line at a time, and the goldens keep the two in that order. The Docker
wrappers `scripts/build-irrtoolset.sh` installs join stderr to stdout inside
the container, since docker relays the two apart and reorders them.

## peval (`TestPevalMatchesIRRToolSet`)

The differential is narrow by design (design §9 item 5): it compares
`NormalizeFilter` against peval only on the shapes peval gets right — prefix
lists, bare AS numbers, AND, OR, and NOT over prefix lists, all IPv4 (peval
reads a filter with no afi clause as ipv4.unicast) — and `pevalSafe` in
`peval_irrtoolset_test.go` is the allow-list. D1 is pinned there directly:
`pevalSafe` refuses NOT over anything but a prefix list, since peval's NOT
over an AS-derived term is simply wrong (D1's `NOT ANY`).

**D2 turned out broader than first scoped.** The compat model
(`randomModel(r, true)`) disables *member-level* range operators
specifically to dodge D2 as the design doc states it ("route-set member
`AS-BAZ^24-26`"). But the model still draws, regardless of compat, a member
naming a set that does not exist (`RS-MISS0`), one of the wrong class for its
container (a filter-set nested in a route-set), or outright junk text
(`BAD!MEMBER`) — and peval substitutes `0.0.0.0/0` for *any* route-set or
as-set member it cannot resolve, not only one carrying an operator. Example
found by the differential during development (seed 15's model):

```
route-set: rs-s1
members: rs-miss1, FLTR-X
mp-members: RS-S0
```

`RS-S0` itself resolves to nothing (empty: `!iRS-S0,1` answers `D`, since an
empty set and a missing one both do — see `DB.Members`/`DB.Recursive`). peval:

```
$ echo 'RS-S1' | peval
({0.0.0.0/0})
```

— the same `0.0.0.0/0` substitution as D2, triggered by an unresolvable
*member*, not a member-level operator. Applying an outer range operator then
names the window over that substituted `0.0.0.0/0` rather than over RS-S1's
real (mostly empty) membership:

```
$ echo 'RS-S1^31-32' | peval
({0.0.0.0/31, 0.0.0.2/31, 0.0.0.4/31, ...   # every /31 in 0.0.0.0/0
```

This ran for minutes and produced hundreds of megabytes of output before
being killed, while developing this test (never in the checked-in test:
`pevalSafe` excludes it). Since this model draws a missing, wrong-class, or
junk member into most randomly generated sets — by design, so other tests
(`TestModelNormalizeFilter` and the engine's own model tests) hold the
engine's handling of exactly those cases to the model — no as-set or
route-set *name* is safe to compare against peval here. `pevalSafe` therefore
excludes the `"set"` `mFilter` kind entirely, reusing D2 rather than adding a
new number: it is the same `0.0.0.0/0`-substitution bug, just reached through
a wider range of inputs than the one case the design doc's table shows.

**The Linux build echoes its input, and gets D17 wrong.** A peval built with
GNU readline (`scripts/build-irrtoolset.sh`, which CI uses) writes the line it
read before its answer; `pevalAnswer` drops that echo, and `pevalPrefixes`
refuses a range it cannot parse instead of skipping it, so an answer like
D17's `10.0.0.4/33` fails the test rather than vanishing. `pevalSafe` leaves out
a bare AS number under a window beyond /32 (`modelOps`' `^126`, `^127-128`):
the bottle answers `NOT ANY`, correctly, and the Linux build does not (D17).

A bare AS number (`mFilter` kind `"as"`) is otherwise unaffected and stays in
`pevalSafe`: it resolves straight to `-K -r -i origin ASn`, a route lookup
with no `!i` membership walk to corrupt — confirmed with mixed-family and
open-ended operators (`AS1^+`, `AS1^127-128`) producing no hang and a correct,
bounded answer.

## Agreements worth noting

- **`NOT {prefix}` as a whole answer.** peval cannot enumerate an unbounded
  complement, so a filter that denotes "every prefix except some" prints
  `(NOT{p/l, ...})` rather than enumerating it — the correct value, not a
  divergence. `pevalPrefixes` reads the `NOT{` wrapper as the excluded set,
  materialized against every prefix rather than none.
- **Multiple conjuncts for an enumerable filter.** `NormalizeFilter` treats
  NOT as symbolic unconditionally (design §4.2), so `NOT {p} OR (ANY AND
  AS1)` comes back as two conjuncts even though both are pevalSafe-approved
  literals; peval still computes one finite answer for the whole filter. The
  test takes the union of every conjunct's materialized prefixes before
  comparing, rather than assuming (or requiring) a single conjunct.
