# Known divergences from IRRToolSet (rtconfig/peval)

`TestPevalMatchesIRRToolSet` (`resolve/peval_irrtoolset_test.go`) checks
`Expander.NormalizeFilter` against IRRToolSet 5.1.3's `peval` on random IPv4
filters, served by the in-process IRRd in `internal/irrtest`. A throwaway
spike (design doc §3) found ten IRRToolSet bugs running `rtconfig` and
`peval` together against it; they are pinned here so later rtconfig-
differential work (design §9 item 4) reuses the same numbering instead of
rediscovering them, and so a fix on either side is caught by a test instead
of passing unnoticed.

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
| D9 | exit status | 0 after "no object for AS1" | non-zero |
| D10 | peval prints `AS2-AS3`, PeerAS as `AS4294967295` | not re-parseable | `NormalFilter.String` parses back |

D5–D9 are rtconfig/config-generation bugs with no peval-side test yet; they
are listed here only so this file matches the design doc's numbering when a
later task (the rtconfig differential, design §9 item 4) adds one.

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

A bare AS number (`mFilter` kind `"as"`) is unaffected and stays in
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
