# A set reaching AS-ANY in an AS-path regexp — design

Approved 2026-10-17 after an independent five-role review (RFC and registry semantics, engine and API,
downstream consumers, security, testing).

## Problem

RIPE's `aut-num: AS8308` has `import: from AS1887 action pref = 150; accept <AS1887:AS-Peerings:AS8501$>`,
and that as-set has `members: AS-ANY`. `peval.Evaluator.Import` fails the whole policy with
`*resolve.AnySetError`, because `NormalizeFilter` expands every as-set a regexp names and discovery
stops at AS-ANY.

Measured over the local dumps: RIPE has 3 as-sets with `members: AS-ANY` (AS1887:AS-Peerings:AS8501,
AS25192:AS-IX, AS200070:AS-IX) and 1 more that reaches it by nesting (AS1887:AS-Peerings:AS-Received).
They are used 3 times in AS-path regexps (2 aut-nums: AS8308, AS1887), in 2 aut-nums' peerings, and never
in filter position. RADB, APNIC, AFRINIC, LACNIC, ALTDB and NTTCOM have none.

## Semantics

- RFC 2622 §5.3: "The set as-any contains all ASes registered in IRR"; "rs-any contains all routes
  registered in IRR". §5.1 lets `members:` name a set, so `members: AS-ANY` is a legal reference.
- rpsl reads AS-ANY in path and peering position as every AS number (not only registered ones), as it
  already does for a literal AS-ANY (routemodel, rtconfig, peval) and for a set reaching it in a peering
  (`peval.inASSet`). The RFC itself uses AS-ANY as "any peer" (§6 `from AS-ANY`).
- In filter position the RFC meaning is "registered routes", which a generic Source cannot enumerate;
  `everything()` would widen it. So filter position is unchanged: an error.
- Reference tools (bgpq4, IRRd 4.5.3, IRRToolSet 5.1.3) drop an AS-ANY member, so a regexp naming such a
  set matches nothing there. rpsl differs on purpose; the difference is recorded (D19).

## Decisions

1. **Path position only.** In a regexp, a set reaching AS-ANY is an `ASNSet` with `Any()` true: `Has` is
   true for every AS; `List`/`Len` give nothing, so readers check `Any()` first. Such a set is not the
   filter ANY: `<AS-X$>` still needs a non-empty path, `<^AS-X$>` a one-AS path.
2. **Filter position, and every enumerating API, unchanged.** `accept AS-X`, `NOT AS-X`, `AS-X^24`, a set
   template, a route-set reaching AS-ANY or RS-ANY, `ExpandAS`, `ExpandPrefixes`, `EvalFilter`: the same
   `*AnySetError` as today.
3. **Built in a path-only discovery mode, never in the evaluator's shared AS cache.** A path regexp and a
   negated literal share an evaluator; an any-set in the shared cache would make `NOT AS-X` accept
   everything. Discovery runs to the end under every limit (MaxDepth, MaxVisited), so a graph over a
   limit still refuses with `*SetTooLargeError`, and the any-set is charged like any other expansion. An
   any-set reports no missing sets (nothing missing can change "every AS"), as `peval.inASSet` does.
4. **rtconfig refuses it**: a new `CauseAnySet`, all-or-nothing as every cause, in both polarities. No
   option to write "any AS".
5. **Analysis decides it and names it**: peval and consist evaluate the regexp; consist's Lint gives a
   Warning, `lint/any-set`, naming the aut-num's term and the set. A set named in a regexp that reaches
   AS-ANY is reported by its own name (the chain inside it is not recorded).
6. **Divergences recorded**: D19 in resolve/testdata/rtconfig/divergences.md (IRRToolSet: such a set, and a
   literal `<AS-ANY>`, match nothing; rpsl: rtconfig refuses, peval keeps `<AS-X>`), pinned by tests; and
   a row for the existing peering divergence (`peval.inASSet` vs IRRToolSet's `isPeeringMatching`).
7. **Docs**: the RFC citation in resolve/normalize.go becomes §5.3; the literal `accept AS-ANY` under
   NormalizeFilter is documented as a widening approximation of "registered routes"; `RIPE::AS-ANY`'s
   scope stays ignored, documented. A hierarchical name with an AS-ANY component (`AS208301:AS-ANY`) is an
   ordinary set; an object named AS-ANY in a Source is never read.
8. **Release**: rpsl v0.30.0 (API addition and behaviour change). routecheck v0.2 then requires it, checks
   `Any()` in its test oracle, names the set in an Accepted verdict, and reworks its R19 tests.

## Measured

Re-measured on 2026-10-17 over the RIPE dumps in `.data/ripe` (dated 2026-09-27), with shell
one-liners (perl in paragraph mode, continuation lines folded), not a script in the repo.

**As-sets whose `members:`/`mp-members:` list `AS-ANY`** (a member token, comments dropped):

    gzcat ripe.db.as-set.gz | LC_ALL=C perl -00 -ne 's/\n[ \t+]/ /g; my ($n)=/^as-set:\s*(\S+)/mi;
      for my $l (grep { /^(mp-)?members:/i } split /\n/) { (my $v=$l)=~s/^[^:]*://; $v=~s/#.*//;
      for my $m (split /[\s,]+/, $v) { print "$n\t$m\n" if uc($m) eq "AS-ANY" } }'
    AS1887:AS-Peerings:AS8501	AS-ANY
    AS25192:AS-IX	AS-ANY
    AS200070:AS-IX	AS-ANY

**As-sets reaching `AS-ANY`**, directly or by nesting (a fixpoint over every as-set's members):

    AS1887:AS-PEERINGS:AS-RECEIVED
    AS1887:AS-PEERINGS:AS8501
    AS200070:AS-IX
    AS25192:AS-IX
    reaching: 4 of 26766 as-sets

3 direct and 1 by nesting (AS1887:AS-Peerings:AS-Received, whose `members:` names
AS1887:AS-Peerings:AS8501), as above.

**Where the four are named.** Every RIPE dump file, every line naming one of the four: 5 lines in
`ripe.db.as-set.gz` (the four `as-set:` lines and the nesting `members:` line), 7 in
`ripe.db.aut-num.gz`, none elsewhere. The aut-num lines:

    AS8308	import: from AS1887 action pref=150; accept <AS1887:AS-Peerings:AS8501$>
    AS1887	export: to AS8308 announce <AS1887:AS-Customers:AS-Received> OR <AS1887:AS-Peerings:AS-Received$>
    AS1887	import: from AS8501 action pref=150; accept <AS1887:AS-Peerings:AS8501$>
    AS25192	mp-import: afi any.unicast from AS25192:AS-IX accept ANY
    AS25192	mp-export: afi any.unicast to AS25192:AS-IX announce AS-CZNIC
    AS200070	mp-import: afi any.unicast from AS200070:AS-IX accept ANY
    AS200070	mp-export: afi any.unicast to AS200070:AS-IX announce AS-CZNIC

So 3 uses by name in AS-path regexps in 2 aut-nums (AS8308, AS1887), the peerings of 2 aut-nums
(AS25192, AS200070), and none in filter position: the figures above hold. One more use the name
search does not see: AS1887's `import: from AS1887:AS-Peerings action pref=150; accept
<AS1887:AS-Peerings:PeerAS$>` is a set template that, toward AS8501, is AS1887:AS-Peerings:AS8501.
It is the only template in RIPE's aut-nums that can be bound to one of the four
(`AS1887:AS-PEERINGS:PEERAS` or `PEERAS:AS-IX`, searched the same way).

**peval over the dumps** (`TestRealDataPeval`, `RPSL_PEVAL_AS=8308,1887`: the 301 sampled aut-nums
and the two forced in with every peer they name; GOMAXPROCS 4, `GOMEMLIMIT=6GiB`). Before, main's
code (12ed509) with this branch's test (its count of `Any()` sets stubbed to 0, since main's
`ASNSet` has none), `.data/peval-anyset-before.log`; after, this branch,
`.data/peval-anyset-after.log`:

| | before | after |
|---|---|---|
| sessions evaluated | 3,493 | 3,496 |
| clauses | 1,987 | 1,993 |
| `*AnySetError` ("any set") | 3 | 0 |
| regexps naming a set reaching AS-ANY | — | 4 (in 4 attributes, by 0-based `Clause.Index`: AS8308 import #3, AS1887 import #1 (the template) and #4, AS1887 export #2) |
| refused `an AS-path set that reaches AS-ANY`, per vendor | — | 3 (cisco, junos, ciscoxr, bird) |

The three sessions that failed before: AS8308 import from AS1887, AS1887 export to AS8308, AS1887
import from AS8501 (by the template), all IPv4. After, AS8308's import from AS1887 has 2 clauses.

**consist over the dumps** (`TestRealDataConsist`, the full sweep of 39,918 RIPE aut-nums,
`.data/consist-anyset-2.log`; GOMAXPROCS 4, `GOMEMLIMIT=6GiB`, `RPSL_CONSIST_MEMO=1`, which is
result-neutral and what `rpslcheck` always sets). `lint/any-set`: 4 issues, AS8308 1
(AS1887:AS-PEERINGS:AS8501) and AS1887 3 (AS1887:AS-PEERINGS:AS8501 twice — the literal import and
the template bound for AS8501 — and AS1887:AS-PEERINGS:AS-RECEIVED), one per regexp use above.
"not decidable: any set" 0, as the dump has no use in filter position; "not decidable: other" 0;
477,028 pairs checked. A first attempt at background priority without the memo
(`.data/consist-anyset.log`) hit `go test`'s 90-minute timeout before the sweep finished.
