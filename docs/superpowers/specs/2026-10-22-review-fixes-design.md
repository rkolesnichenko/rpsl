# v0.30.0 review fixes — design

Approved by the user 2026-10-22. Decision D4: option C, chosen by the user on
2026-10-22.

## Why

A `/code-review` of v0.30.0 (PR #37, any-set, plus PRs #34–#36) gave 11 findings. Each was
cross-checked on 2026-10-22 with a throwaway probe in a scratch worktree (the probes were deleted
and the worktrees removed; only their outputs are quoted here). Ten held. Finding 9 (`pathSet`
duplicates `asSet`) was overstated and is dropped. The engine bugs are small, but two of them
contradict the operating contract in CLAUDE.md (MaxVisited "together"; "nowhere else"). The
contract is what future changes follow, so it has to be true.

## Goals

- Fix the reproduced engine bugs: F2, F3, F7 and F8.
- Settle F4: one rule for how the limits apply to a set that reaches AS-ANY.
- Make the docs true: F1, F5, F6 and F11.
- Make check.sh's gofmt step fail when it lists no files because `git ls-files` failed (F10).
- Add a regression test for every behaviour fix. Each test fails on today's main.

## Non-goals

- F9: no refactor of `pathSet`/`asSet`.
- Statically reporting `lint/any-set` for a term no session decides (F1). See F1 below for why.
- Discovery's own cap and the evaluator's charge are separate (a failing call can fetch past
  MaxVisited before it refuses, for example `AS-A OR AS-B` at 14 fetched 20 sets and then refused
  with "reached 24"). It still refuses, so nothing is answered wrongly. Out of scope; noted here
  so it isn't rediscovered as new.
- Sharing one evaluator between `ev` and `noEx` when `Exclude` is empty. That is an optimisation,
  not a fix.
- Any exported API change. `api/*.txt` must not change (`apisurface -check` passes unchanged).

## Anti-goals

- A fix that makes any `NormalizeFilter`, `ExpandAS`, `EvalFilter` or peval answer **wider**. A
  limit fix may only refuse more (F3) or refuse less where the answer is unchanged (F4).
- A "matches every path" analysis that runs a regexp against a path. consist never evaluates a
  regexp (CLAUDE.md). F2's rule is a property of the regexp's syntax tree, computed without any
  path.
- Silencing `aspa-missing-provider` for the common bogon-style negations
  (`ANY AND NOT <.* AS64512 .*>`). Those still take a full table. A rule that treats any `.` as
  "rejects everything" would be worse than the bug.

## Findings and fixes

Each section gives what reproduced (measured in the cross-check), the fix, and its test.

### F3: MaxVisited is charged on two counters (resolve/normalize.go, expand_more.go)

**Reproduced.** `normalize` builds two `filterEval`s (`ev` and `noEx`), each with its own
`visits int`, and each checks that counter against the full `MaxVisited`. With 10-set chains,
`NormalizeFilter("AS-A AND <AS-B>")` succeeds at `MaxVisited: 14` after fetching 20 distinct sets
(counters were ev=14 and noEx=10). This contradicts NormalizeFilter's doc ("MaxVisited caps the
sets fetched, the filter terms evaluated and the normalization steps taken, together") and
CLAUDE.md.

**Fix.** One budget per `normalize` call. `filterEval.visits` becomes a pointer to a counter that
`normalize` shares between `ev` and `noEx`. `newFilterEval` allocates a fresh one, so every other
caller (`EvalFilter`, `ExpandFilterSet`) keeps a single evaluator with its own budget. `visit()`
is the only place that writes the counter, so the change is local.

The charge records work done. A set expanded by both evaluators (`AS-X AND NOT <AS-X>`) is
discovered twice and charged twice, as it already was on the two counters. This is deliberate
and goes in the normalizer's comment.

**Tests.**
- `TestNormalizeVisitsShared`: the 10-set chain graph. `AS-A AND <AS-B>` is refused with
  `LimitVisited` at 23 and accepted at 24. `AS-A AND NOT AS-B` is refused at 25 and accepted at
  26. The builder takes the exact thresholds from the fixed code; they must equal ev+noEx as the
  probe measured them (14+10 and 15+11).
- `TestAnySetLimits`: its MaxVisited case changes. `<AS-R>` charged 8 on `noEx` plus 1
  normalization step on `ev`, so it now fits at 9 and is refused at 8. The error then comes from
  the evaluator's `visit()`, not from discovery, so its `Name` is empty (`ev.cur` at the top
  level) and `Count` is 9. The test's comment about which side refuses is rewritten to match. F4
  rewrites this test anyway (D4 is C), so its final numbers come from the code with both fixes in.
- Run the whole resolve module. Any other test whose limit sat between the old split charge and
  the new total fails here. The builder updates each one and lists them in the PR.

### F4: one set, two answers under the limits (resolve/expander.go `discover`). **D4: C.**

**Reproduced.** In peering position (`peval.inASSet`, `consist`'s `denoter.expandAS`, both
through `ExpandAS`), `discover` returns `*AnySetError` at the start of the level that holds AS-ANY.
Nothing deeper is fetched or checked against the limits, and peval reads that error as "every
AS". In regexp position (anyLeaf mode, `pathSet`), discovery runs to the end and refuses a graph
over a limit.

Graph: AS-X has members `AS-ANY, AS-C1`, and AS-C1 starts a chain 6 levels deep. At `MaxDepth:
3`, `import: from AS-X accept ANY` gives a clause, while `from AS-X accept <AS-X>` gives
`*SetTooLargeError`. Member order makes no difference.

The PR #37 plan kept the peering behaviour deliberately ("Without [anyLeaf], behaviour and error
are exactly today's"). Its spec's decision 3 chose run-to-the-end for regexps and recorded no
reason beyond "a graph over a limit still refuses". Nothing documents the mismatch.

**Decision D4: C, chosen by the user.** The three options are kept here, with C first, as the
record of what was weighed:

- **C (chosen): regexps stop where peerings stop.** In anyLeaf mode, discovery finishes the
  level whose processing reaches an AS-ANY reference (so every reference on the next level still
  passes the seen/MaxDepth/MaxVisited checks), then returns the any-set without fetching further.
  - The non-anyLeaf path returns `*AnySetError` at exactly the same point, so the two modes share
    one loop and differ only in what they return.
  - One rule: "an expansion that reaches AS-ANY stops after the level that reaches it; whatever
    lies deeper cannot change 'every AS'."
  - It does less work than today and no exported API changes.
  - It also removes most of F8's wasted calls (see F8).
  - It reverses the approved any-set spec's decision 3 and the CLAUDE.md sentence "Discovery still
    runs to the end under MaxDepth and MaxVisited", so both are amended.
  - It answers wider than today only in this sense: a graph that used to refuse as over a limit
    now answers "every AS". That answer is exact, which is why it is allowed under the anti-goal.
- **A: peerings walk to the end too.** peval and consist would need the anyLeaf expansion, which
  is unexported. That means a new exported method (an API addition) or an internal package.
  - Peering checks would fetch more over whois.
  - It keeps decision 3 as written.
  - A peering that matches today could be refused tomorrow over a limit deep in a graph whose
    answer is already known.
- **B: document only.** Keep both behaviours. Write the difference into CLAUDE.md's any-set
  bullet and into `inASSet`'s and `discover`'s comments.

**What "agree" means under C (my call).**
- Peering and regexp agree on where discovery stops and on MaxDepth.
- They cannot agree on MaxVisited at the margin. A regexp is charged on the normalizer's budget for
  its expansion plus each normalization step, and a peering's `ExpandAS` is not. That is F3's
  "together" rule working as intended, not a disagreement.
- Under C, an any-set's charge is every reference that passed discovery's checks (`len(seen)`),
  including the next level's unfetched references. `g.size()` alone would leave those out. So
  the charge equals what discovery bounded.

**Tests (C).**
- `TestAnySetLimits` is rewritten. AS-ANY sits at depth 2. `MaxDepth: 3` with a chain to depth 4
  now gives the any-set (this was `*SetTooLargeError`). `MaxDepth: 1` still gives
  `*SetTooLargeError`, because the reference to AS-ANY itself is past the limit.
- A new table test checks that peering and regexp agree for each graph in a small set
  (AS-ANY shallow with a deep sibling, AS-ANY deep, AS-ANY past the limit): `peval` decides
  `from AS-X accept ANY` and `from AS5 accept <AS-X>` the same way at the same MaxDepth (both
  decided, or both `*SetTooLargeError`). MaxVisited is left at its default.
- `TestConcurrencyDoesNotChangeResults` must keep passing; level-at-a-time discovery is
  unchanged.

### F8: wasted `MembersByRef` calls in anyLeaf mode (resolve/expander.go `fetchOne`)

**Reproduced.** For `<AS-X>` with AS-X reaching AS-ANY, discovery called `MembersByRef` on both
mbrs-by-ref sets (AS-Y and AS-Z), and `expandAS` then threw the claims away. When one of those
calls fails, the whole `NormalizeFilter(<AS-X>)` fails, although its answer never needed the
claims.

Correcting the review: `irrd.Source.MembersByRef` does no I/O. Only `whois.Source` makes a network
query per set (`-i member-of`).

**Fix (my call: in every mode, not only anyLeaf).** Discovery fetches sets without their claims.
Peerings (`ExpandAS` → `inASSet`) waste the same calls before the `*AnySetError`, so doing it in
every mode keeps peering and regexp consistent. Only when discovery ends successfully with no
AS-ANY reached does it fetch the claims, in a second pass:
- over the nodes in discovery order;
- level by level, under `Concurrency` like `fetchLevel`;
- with the same `claimClassOK`/`ClaimAllowed` filter.

Claims never add nested references (`discover` takes them from `nestedRefs(res.set)` only), so the
graph, the limits and the answer are unchanged. `fetchOne` gains a "with claims" flag; `discover`
needs an ordered list of nodes beside its map.

When the expansion reaches AS-ANY, or discovery refuses with a limit, no `MembersByRef` call is
made at all. Every caller that reads claims (`expandAS`,
`expandRanges`, the rtr-set path at expand_more.go:52, the evaluator at expander.go:702) still
gets them, since they all go through `discover`. The answers do not change. The only behaviour
change: a `MembersByRef` error no longer fails an expansion whose answer never needed the claims.

**Tests.**
- `TestDiscoverSkipsClaims`: a counting Source (the probe's shape: embed MemSource, count calls).
  - `<AS-X>` reaching AS-ANY makes 0 `MembersByRef` calls, and so does `ExpandAS(AS-X)`.
  - A graph refused at a limit makes 0.
  - A `MembersByRef` that fails on AS-Z fails neither `NormalizeFilter(<AS-X>)` nor peval's
    `from AS-X accept ANY`.
- `TestClaimsWithoutAnySet`: the same graph without AS-ANY. `pathSet`'s answer and `ExpandAS`'s
  both include the claimants (AS100, AS101) and are equal.
- A new concurrency test. `TestConcurrencyDoesNotChangeResults`'s `randomGraph` has no
  `mbrs-by-ref`/`member-of` objects, and no model test sets `Concurrency`, so nothing covers the
  second pass today. Either extend `randomGraph` with claimants and mbrs-by-ref sets (preferred:
  every test that uses it then covers claims), or add a test that compares serial and parallel
  `ExpandAS`, `ExpandPrefixes` and `NormalizeFilter` over random graphs with claims.
- The existing model tests over every backend (MemSource, Corpus, irrd, whois) must keep passing:
  they hold the answers equal.

### F2: ASPA full-table rule misses a literal AS-ANY or `.` (resolve/consist/aspa.go)

**Reproduced.** With AS1's ASPA listing AS3 only, `ANY AND NOT <AS-R>` (AS-R reaches AS-ANY)
gives no `aspa-missing-provider`. `ANY AND NOT <AS-ANY>` and `ANY AND NOT <.>` each give "imports
a full table from AS9", although all three reject every route that has a path. `onlyNegated`
checks only `p.Sets[].Any()`, and a literal creates no `Sets` entry.

The current set rule is also too broad in the other direction. `ANY AND NOT <AS1 AS-R>` rejects
only paths with AS1 followed by some AS, yet it stops the conjunct counting as a full table.

**Fix: replace "names an any-set" with an exact property, "this negated test rejects every route
that has a path".** Take a regexp R with no `^` or `$` anywhere, which matches a path when it
matches some sub-path of it. R matches every non-empty path if and only if R matches the empty
path or R matches every one-AS path:
- A non-empty path contains the empty sub-path and a one-AS sub-path.
- A one-AS path's only sub-paths are itself and the empty path.

So the test is `nullable(R) || ones(R) == all`.

That is computed over the syntax tree, with no path and no regexp engine:
- `ones(R)` is the set of ASes R accepts as a one-AS path, as "all" or "not known to be all".
- `nullable(R)` is whether R accepts the empty path.
- Rules:
  - `ASPathAny`, a literal `AS-ANY`, or a set with `Sets[n].Any()`: all.
  - A class containing one of those: all. A negated class: not all.
  - `ASPathAlt`: all if any alternative is all.
  - `ASPathSeq`: all if some term is all and every other term is nullable.
  - `ASPathRepeat` with `Min ≤ 1` (`*`, `+`, `?`, `~*`, `~+`, `{0,n}`, `{1,n}`): its inner term's
    value. With `Min ≥ 2`: not all.
  - Anything else (an AS number, a range, a set template, PeerAS, an anchor): not all.
- `nullable` follows the usual rules: a `Seq` is nullable if all its terms are, an `Alt` if any
  alternative is, a `Repeat` with `Min = 0` always.
- A regexp with an anchor anywhere is "not all". The lemma above fails for anchors. For example,
  `<^.$>` rejects only one-AS paths, so it is not a full rejection.

Every "not all" errs toward counting the conjunct as a full table, which keeps today's default (a
negation is assumed to leave something). `onlyNegated` drops its `Sets` loop and the conjunct is
excluded when some negated path test is "all".

Result:
- `NOT <.>`, `NOT <AS-ANY>`, `NOT <AS-R>`, `NOT <.* AS-R .*>`, `NOT <[AS1 AS-ANY]>` and
  `NOT <AS1*>` (nullable) exclude the conjunct.
- `NOT <AS1 AS-R>`, `NOT <.* AS64512 .*>` and `NOT <^AS-R>` do not.

The function lives in consist, unexported (`rejectsEveryPath(p resolve.PathMatch) bool`). Two
spellings stay apart to avoid confusion: the code's "ruling F1" (aspa.go:39) is the ASPA
full-table ruling, and this document's "F1" is the review finding below.

**Tests.**
- The table test `TestASPAMissingProvider` (resolve/consist/aspa_test.go:62, through `lintASPA`)
  gains a row for each shape above.
- `TestASPAAnySetPath` (aspa_test.go:163), today's pin for ruling F1, stays and gains the literal
  `<AS-ANY>` and `<.>` policies from the probe; all three give no `aspa-missing-provider`.
- A direct unit test of `rejectsEveryPath` covers the edge shapes:
  - `<.+>`: all.
  - `<.{2}>`: not all.
  - `<(AS1|.)>`: all.
  - `<AS1? .>`: all.
  - `<AS1? AS2?>`: all (nullable).
  - `<^.$>`: not all (anchored).

**Docs.** Every place that states the rule being replaced:
- `docs/diagnostics.md`'s `aspa-missing-provider` entry: "no negated AS-path test that rejects
  every route with a path (`NOT <.>`, `NOT <AS-ANY>`, a set reaching `AS-ANY`)".
- CLAUDE.md:233 ("…with only negated tests, none naming a set that reaches AS-ANY").
- docs/rpslcheck.md:176.
- The comment on `fullTable` (ruling F1).
- CHANGELOG.

**Real data.** Run `RPSL_CONSIST_ASPA=1` `TestRealDataConsist` over a sample on main and on the
branch. Compare the `lint/aspa-missing-provider` counts and explain every changed aut-num. The
expectation, not yet measured, is zero or a handful, since RIPE's two any-set regexps (AS8308,
AS1887) are positive.

### F7: rtconfig class refusal depends on item order (resolve/rtconfig/regex.go)

**Reproduced, corrected.** A range of 1024 or more ASes is refused on its own: `<[AS1-AS5000]>`
gives `CausePathShape` on all four vendors, as `TestTranslatePathRefuses` intends. The defect is
that `[AS-ANY AS1-AS5000]` and `[. AS1-AS5000]` are written as "any AS" because a range after an
any-AS item is never checked, while `[AS1-AS5000 AS-ANY]` and `[AS1-AS5000 .]` are refused.
Behaviour inherited from before 9c0a3ce.

**Fix.** A class that contains an any-AS item is any AS. Its ranges are not written, so they are
not checked either, wherever they sit. Every item is still read, so a set reaching AS-ANY anywhere
in the class is still refused with `CauseAnySet`. In code: collect the ranges as the loop goes;
after the loop, if `anyAS`, return any; otherwise check and expand them. The `continue` and its
"as before" comment go.

Negated classes are already refused (`CauseNegatedClass`) before the loop, so nothing changes for
them.

**Tests.** `TestTranslateClassAnyOrder`, for all four vendors and both polarities:
- `[AS-ANY AS1-AS5000]`, `[AS1-AS5000 AS-ANY]`, `[. AS1-AS5000]` and `[AS1-AS5000 .]` give
  identical output (any AS).
- `[AS1-AS5000]` is still `CausePathShape`.
- `[AS1-AS5000 AS-R]` with AS-R an any-set is `CauseAnySet`.

cfgsim decides each written list the same way as the class's meaning. Check that the IRRToolSet
differential is unaffected: neither the goldens nor D1–D20 use a class mixing AS-ANY and a range.
If one does, it is recorded.

### F1: `lint/any-set` misses a term no session decides (docs only)

**Reproduced.** `from AS2 10.0.0.2 at 10.0.0.1 accept <AS-R$>` gives only `lint/undecided (peer
router not given)`; without the routers it gives `lint/any-set`. The term is still reported, under
`lint/undecided`.

**Fix, my call: documentation, not a static walk.** A static walk would need:
- a regexp walk the `lint/missing-set` walk deliberately does not do;
- a full path-mode expansion per set, not a `GetSet`;
- a peer to bind set templates, which the static walk has none of.

That is a feature, not a fix, for a case with a measured RIPE count of zero (the 3 regexp uses are
in AS8308 and AS1887, without routers).

`docs/diagnostics.md`'s `lint/any-set` entry gains: "Reported for terms a session decides; a term
Lint cannot decide (one naming routers, for example) is `lint/undecided` instead, and the any-set
in it is not reported." The comment on `anySets` says the same.

### F5: CLAUDE.md says "nowhere else" (docs only)

The any-set bullet's first sentence becomes: "**A set reaching AS-ANY is every AS in an AS-path
regexp and in a peering (`peval.inASSet`, `consist`'s denoter, D20), and nowhere else.**" The
limits sentence ("Discovery still runs to the end under MaxDepth and MaxVisited") becomes, per D4:
"an expansion that reaches AS-ANY stops after the level that reaches it, in either position;
references on that next level still pass MaxDepth and MaxVisited."

The approved any-set spec (docs/superpowers/specs/2026-10-17-any-set-design.md, decision 3) gains a
dated amendment note pointing to this document. Its original text stays.

### F6, F10, F11: small fixes

- **F6** (resolve/consist/consist_realdata_test.go:44): the doc comment says what the code does:
  "Every lint/any-set issue is kept and logged at the end (the progress line every 2,000 aut-nums
  carries the count)."
- **F10** (scripts/check.sh): `gofiles` captures `git ls-files` into a variable first and returns
  non-zero when it fails. The gofmt step then calls `bad "could not list Go files"`. The capture
  stays NUL-safe: a temp file or a `while read -d ''` loop, whichever the builder keeps
  POSIX-sh-clean. `set -o pipefail` is not used: check.sh is `#!/bin/sh`. Test by hand: run the
  step from a directory outside any repo and see it FAIL.
- **F11** (resolve/testdata/rtconfig/divergences.md): move the D18 row of "Where each is pinned"
  before D19. `TestDivergencesDocumented` and its rtconfig counterpart must still pass.

## Constraints

- Engine purity: no new `net` import in resolve, peval, consist or rtconfig.
- `TestConcurrencyDoesNotChangeResults` and the model tests pass with `-race`.
- `go run ./internal/apisurface -check` passes with no `api/` change.
- `FilterMemo` stays result-neutral. F3 changes when an answer is an error, and the memo key
  already includes `visited`, so no memo change is expected. The builder confirms
  `TestPeerReadsGoThroughAccessor` and the memo-equality tests pass.

## Verification before done

- `GOMAXPROCS=4 scripts/check.sh` under the memory guard, plus `FUZZTIME=15s` for
  FuzzNormalizeFilter and FuzzTranslateRegexp.
- Real data, one run at a time with a memory cap:
  - `TestRealDataConsist` with `RPSL_CONSIST_SAMPLE` and `RPSL_CONSIST_ASPA=1`, on main and on the
    branch. Diff the counts and explain each change (F2, F3).
  - `TestRealDataPeval` with `RPSL_PEVAL_AS=AS8308,AS1887`. Their sessions decide as before (F4,
    F8).
- An independent reviewer on the full diff before merging (shell-and-delegation rules).

## Left to the builder

- The exact shape of the shared visit budget (a `*int` or a small struct).
- The test names, and the exact F3 thresholds as measured on the fixed code.
- How `discover` keeps node order for F8's second pass.
- How F10's NUL-safe capture is written.
- The CHANGELOG wording. Each behaviour change goes under "Changed" or "Fixed": F2's rule, F3's
  stricter MaxVisited, F4 (regexps stop at AS-ANY), F7, and F8's error behaviour.

## My calls (for the reader to check)

- F1 is fixed in the docs, not with a static walk.
- F2 uses the exact "rejects every path" rule, which also narrows today's any-set rule. The
  rejected alternative is "any `.`/AS-ANY atom", which would silence warnings for bogon
  negations.
- F3 charges a set expanded by both evaluators twice, as work done.
- F4 (C): peering and regexp agree on where discovery stops and on MaxDepth, not on MaxVisited at
  the margin. An any-set is charged `len(seen)`.
- F8 defers claims in every discovery mode, not only anyLeaf, and adds a concurrency test with
  claimants.
- F6 is fixed in the comment, not by logging as found.
- The any-set spec is amended with a dated note rather than rewritten.
- F9 is dropped.
