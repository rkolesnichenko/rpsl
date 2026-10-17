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
