# v0.30.0 review fixes — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the reproduced v0.30.0 review findings: F2, F3, F4 (option C), F7 and F8 in code;
F1, F5, F6 and F11 in the docs; F10 in check.sh.

**Architecture:**
- The engine fixes are local to `resolve`:
  - one MaxVisited budget per `normalize` call;
  - discovery that stops after the level reaching AS-ANY, in both modes;
  - claims fetched only after a discovery that ended without AS-ANY.
- `consist` gets a syntax-tree property, "this negated regexp rejects every path", for the ASPA
  full-table rule.
- `rtconfig`'s class translation stops depending on item order.
- No exported API changes.

**Tech Stack:** Go 1.23 (multi-module, go.work). Tests run from `resolve/` for the resolve module.

**Spec:** `docs/superpowers/specs/2026-10-22-review-fixes-design.md`. Read it first: every task
argues from it, and its section names (F1–F11) are used below.

## Global Constraints

- No exported API change: `go run ./internal/apisurface -check` (from the repo root) passes
  with `api/` untouched.
- Engine purity: `cd resolve && go list -deps . ./peval ./rtconfig ./consist ./irrdq ./rpki`
  shows no `net`.
- No answer of `NormalizeFilter`, `ExpandAS`, `ExpandPrefixes`, `EvalFilter` or peval gets wider.
  The only allowed changes:
  - F3: more refusals at the MaxVisited margin.
  - F4: an any-set answered where a limit deeper than AS-ANY used to refuse it.
  - F8: a `MembersByRef` error no longer fails an answer that did not need claims.
- consist never evaluates a regexp against a path. F2's rule is computed over the syntax tree only.
- Heavy runs (check.sh, real data) go one at a time: `GOMAXPROCS=4`, `GOMEMLIMIT` set, under a
  memory watchdog, never beside each other.
- Commit messages follow the repo's style: lower-case package prefix, as in
  `resolve: share one MaxVisited budget across a normalization`.

## Review Focus

1. **`Exclude` together with the shared budget (F3).** `Exclude` set and a filter mixing positive
   literals and negated sets: the answer equals the pre-change answer whenever both fit. Task 1
   pins this: `TestExcludeModel` keeps passing, plus one explicit case.
2. **AS-ANY at the top (F4).** `ExpandAS(AS-ANY)` and `<AS-ANY>`: `*AnySetError` with no fetch, and
   any AS respectively. Neither depends on the new stop rule. Task 2 pins it.
3. **A scoped reference reaching AS-ANY (F4).** `RIPE::AS-X` stops at the same level as `AS-X`.
   Task 2 pins it.
4. **A `MembersByRef` error on a graph without AS-ANY (F8).** It still fails the expansion; it is
   never swallowed. Task 3 pins it.
5. **Cancellation between discovery and the claims pass (F8).** A context cancelled after
   discovery returns `ctx.Err()`, never a claim-less answer. Task 3 pins it.

---

### Task 1: One MaxVisited budget per normalization (F3)

**Files:**
- Modify: `resolve/expand_more.go`
  - `filterEval.visits` (~line 196);
  - `newFilterEval` (~line 212);
  - `visit` (~line 324).
- Modify: `resolve/normalize.go`
  - `normalize` (~line 164): share the budget;
  - the `normalizer` comment (~line 194): "charged twice, as work done".
- Test: `resolve/normalize_test.go`: new `TestNormalizeVisitsShared`; update `TestAnySetLimits`.

**Interfaces:**
- Produces: `filterEval.visits` becomes `*int`. `newFilterEval` allocates a fresh one, and
  `normalize` sets `n.noEx.visits = n.ev.visits`. Nothing outside these files reads it (a grep
  for `\.visits` in resolve/*.go shows only expand_more.go:325 and the unrelated `v.visits` at
  expander.go:668).

- [ ] **Step 1: Write `TestNormalizeVisitsShared`**

  Graph: two 10-set chains, as the cross-check probe built them.
  - `AS-A` → `AS-A1` → … → `AS-A9` → `AS1`, and likewise for B, ending at `AS2`.
  - Built with `asSet(name, next)` and `corpus(t, …)`.
  - Add the routes `10.1.0.0/16` from AS1 and `10.2.0.0/16` from AS2.

  Cases, `NormalizeFilter` at the given `MaxVisited`:

  | filter | refused (`LimitVisited`) at | fits at |
  |---|---|---|
  | `AS-A AND <AS-B>` | 23 | 24 |
  | `AS-A AND NOT AS-B` | 25 | 26 |
  | `AS-A OR AS-B` (one evaluator, unchanged) | 23 | 24 |

  The first two rows are the probe's ev+noEx sums (14+10 and 15+11). If the fixed code measures
  differently, stop and report it rather than editing the numbers.

  Add one `Exclude` case (Review Focus 1). `Expander{Exclude: Exclusion{Sets: [AS-A5]}}` on
  `AS-A AND NOT AS-B` at the default limits gives the same `NormalFilter.String()` as on main.
  Record main's string in the test as the expected value; take it by running the test on main
  first.

- [ ] **Step 2: Run it and see the first two rows fail**

  Run: `cd resolve && go test -run TestNormalizeVisitsShared -count=1 .`
  Expected: FAIL. `AS-A AND <AS-B>` fits at 14 today.

- [ ] **Step 3: Share the counter**

  `visit(n)` adds to `*ev.visits` and compares that against `maxVisited()`. Rewrite the
  normalizer comment's charge sentence: "Every step, in either evaluator, is charged against one
  MaxVisited budget; a set both evaluators expand is discovered, and charged, twice."

- [ ] **Step 4: Update `TestAnySetLimits`'s MaxVisited half**

  Under the shared budget, `<AS-R>` is charged 1 normalization step plus 8, so 9.
  - At `MaxVisited: 8`: discovery fits, and the evaluator refuses with `LimitVisited`, empty
    `Name` and `Count` 9.
  - At `MaxVisited: 9`: the any-set.
  - Rewrite the comment above it to say which side refuses.

  Task 2 rewrites this test again; keep this edit minimal.

- [ ] **Step 5: Run the resolve module and fix tests that sat on the old margin**

  Run: `cd resolve && go test -count=1 ./... > /tmp/t1.txt 2>&1; echo $?`, then read the file.
  - Expected: 0.
  - For each other failing test whose limit sat between the split and the shared charge, update
    its threshold and list it in the commit message.
  - A failure that is not a limit threshold is a bug: stop and report.

- [ ] **Step 6: Commit**

  ```bash
  git add resolve/expand_more.go resolve/normalize.go resolve/normalize_test.go
  git commit -m "resolve: share one MaxVisited budget across a normalization"
  ```

---

### Task 2: Discovery stops after the level reaching AS-ANY, in both modes (F4, option C)

**Files:**
- Modify: `resolve/expander.go`
  - `discover` (~line 326) and its doc comment;
  - `setGraph` (~line 296): a `reached int` field, set to `len(seen)` when discovery returns, and
    `size()` returns it;
  - `expandAS`'s comment.
- Test: `resolve/normalize_test.go` (`TestAnySetLimits`, rewritten);
  `resolve/expander_test.go` (new `TestDiscoverStopsAtAnySet`).
- Test: new `resolve/peval/anyset_limits_test.go` (`TestAnySetPeeringAndRegexpAgree`).
- Docs:
  - CLAUDE.md, the any-set bullet's limits sentence: replace "Discovery still runs to the end
    under MaxDepth and MaxVisited (over a limit is `*SetTooLargeError`)" with "An expansion that
    reaches AS-ANY stops after the level that reaches it, in either position; references on that
    next level still pass MaxDepth and MaxVisited (over a limit is `*SetTooLargeError`)".
  - `docs/superpowers/specs/2026-10-17-any-set-design.md`: under decision 3, add a dated line,
    "Amended 2026-10-22: discovery stops after the level reaching AS-ANY, as a peering's does;
    see 2026-10-22-review-fixes-design.md F4."

**Interfaces:**
- Consumes: Task 1's shared budget. `TestAnySetLimits`'s numbers below assume it.
- Produces: `setGraph.size()` = every reference that passed discovery's checks. For a graph
  without AS-ANY, that is `len(nodes)+len(missing)`, unchanged.

Behaviour of `discover` after the change:
- The depth-0 check stays: a top reference that is AS-ANY gives `*AnySetError`.
- While a level is processed, every nested reference passes the `seen`/exclusion/MaxDepth/
  MaxVisited checks as today.
- A reference to AS-ANY is marked (not appended to `next`).
- After the whole level is processed, if one was marked:
  - without anyLeaf, return `*AnySetError` (the same point the old start-of-level check hit);
  - with anyLeaf, record it in `g.any` and return the graph.
- Either way, nothing past that level is fetched.

- [ ] **Step 1: Write `TestDiscoverStopsAtAnySet`**

  Uses a counting Source: the existing `getSetByRef` in normalize_test.go.

  Graph: AS-X has members `AS-ANY, AS-C1`; the chain AS-C1 → AS-C2 → … → AS-C5 → AS5.
  - Level 0 (AS-X) is fetched, and its references AS-ANY and AS-C1 pass the checks. AS-ANY is
    marked, and discovery stops before level 1. So both modes fetch exactly `{AS-X}`:
    - `NormalizeFilter(<AS-X>)` at `MaxDepth: 3`: an any-set. Today it fetches AS-X, AS-C1,
      AS-C2 and AS-C3 and refuses.
    - `ExpandAS(AS-X)` at default limits: `*AnySetError`, unchanged from today.
  - Review Focus 2: `ExpandAS(AS-ANY)` gives `*AnySetError` with zero fetches; `<AS-ANY>`
    normalizes with no `Sets` entry and zero fetches.
  - Review Focus 3: the same graph with every object in source RIPE, reached through
    `<RIPE::AS-X>`, fetches only `RIPE::AS-X` and gives the any-set.

- [ ] **Step 2: Rewrite `TestAnySetLimits`**

  Same graph as today:
  - AS-R has members `AS-MID, AS-C1`;
  - AS-MID has members `AS-ANY, AS-GONE`;
  - the chain AS-C1 → AS-C2 → AS-C3 → AS-C4 → AS5.

  AS-ANY's reference is found while processing level 1, so discovery stops after it.
  `seen` = {AS-R, AS-MID, AS-C1, AS-ANY, AS-GONE, AS-C2} = 6.

  `NormalizeFilter(<AS-R>)`:
  - `MaxDepth: 1`: `*SetTooLargeError{LimitDepth}`.
  - `MaxDepth: 2`: any-set.
  - `MaxDepth: 3`: any-set. This is the case today's test refuses.
  - `MaxVisited: 5`: discovery refuses, `Name` AS-R, `Count` 6.
  - `MaxVisited: 6`: the evaluator refuses, `Count` 7 (1 step + 6).
  - `MaxVisited: 7`: any-set.

- [ ] **Step 3: Write `TestAnySetPeeringAndRegexpAgree` in package peval**

  Build a MemSource from RPSL texts with `rpsl.ParseObject` + `rpsl.Decode` (a small local helper;
  peval has none taking texts). Two aut-nums:
  - AS1: `import: from AS-X accept ANY` (peering position);
  - AS2: `import: from AS5 accept <AS-X>` (regexp position).

  Graphs for AS-X:
  - (a) members `AS-ANY, AS-C1`, with a 6-deep chain from AS-C1;
  - (b) AS-X → AS-D1 → AS-D2, and AS-D2's members are `AS-ANY`;
  - (c) graph (a) with the member order reversed.

  For each graph and each `MaxDepth` from 1 to 7, `Import` toward peer AS5 (`Session{Local: 1 or 2,
  Peer: 5, AF: v4}`): both decide, or both fail with `*resolve.SetTooLargeError`. MaxVisited stays
  at its default (spec F4, "What agree means").

- [ ] **Step 4: Run the three tests and see them fail**

  Run: `cd resolve && go test -run 'TestDiscoverStopsAtAnySet|TestAnySetLimits' -count=1 . ; go test -run TestAnySetPeeringAndRegexpAgree -count=1 ./peval`
  Expected: FAIL. Today anyLeaf fetches the whole chain and refuses at MaxDepth 3.

- [ ] **Step 5: Change `discover` as described above. Set `g.reached = len(seen)` on return; `size()` returns `g.reached`**

- [ ] **Step 6: Run the module, including concurrency and the models**

  Run: `cd resolve && go test -count=1 ./... > /tmp/t2.txt 2>&1; echo $?`, then read the file.
  Expected: 0. `TestConcurrencyDoesNotChangeResults` (its AS-REACH graph) and the filter/policy
  models must pass unchanged.

- [ ] **Step 7: Update the docs listed under Files, then commit**

  ```bash
  git add resolve/expander.go resolve/expander_test.go resolve/normalize_test.go \
    resolve/peval/anyset_limits_test.go CLAUDE.md docs/superpowers/specs/2026-10-17-any-set-design.md
  git commit -m "resolve: stop discovery after the level reaching AS-ANY, in a regexp as in a peering"
  ```

---

### Task 3: Fetch claims only after discovery ends without AS-ANY (F8)

**Files:**
- Modify: `resolve/expander.go`
  - `fetchOne(ctx, ref)` (~line 418) gains `withClaims bool`;
  - a new `fetchClaims(ctx context.Context, g *setGraph) error`;
  - `discover` keeps `order []types.SetRef` (nodes in discovery order) on `setGraph`.
- Test: new `resolve/claims_test.go`.

**Interfaces:**
- Consumes: Task 2's `discover`.
- Produces:
  - `fetchOne(ctx, ref, false)` returns the set only.
  - `fetchClaims` runs after a successful discovery with `len(g.any) == 0`:
    - it walks `g.order` level by level, so a level's fetches run together as in `fetchLevel`,
      under `Concurrency`;
    - it fills each node's `claims` with today's `claimClassOK` + `ClaimAllowed` filter;
    - it returns the first error in `g.order` order, and `ctx.Err()` if cancelled.
  - Every reader of `nd.claims` is unchanged: expander.go:208, :605, :702 and expand_more.go:52.

Keep the level boundaries: store, per level, the start index into `order`, or store the levels
themselves. Results must not depend on `Concurrency`.

- [ ] **Step 1: Write the tests in `resolve/claims_test.go`**

  `countingSource` embeds `*MemSource` and counts `MembersByRef` calls under a mutex. It takes an
  optional `failOn` set name, whose `MembersByRef` returns an error.

  Graph (the probe's):
  - `as-set: AS-X`, members `AS-ANY, AS-Y`;
  - `as-set: AS-Y`, members `AS2, AS-Z`, `mbrs-by-ref: ANY`;
  - `as-set: AS-Z`, members `AS3`, `mbrs-by-ref: MNT-A`;
  - `aut-num: AS100` with `member-of: AS-Y` and `mnt-by: MNT-A`;
  - `aut-num: AS101` with `member-of: AS-Z` and `mnt-by: MNT-A`;
  - `mntner: MNT-A`;
  - all in source TEST.

  - `TestDiscoverSkipsClaims`:
    - `NormalizeFilter(<AS-X>)` and `ExpandAS(AS-X)` each make 0 `MembersByRef` calls.
    - With `failOn: "AS-Z"`, `NormalizeFilter(<AS-X>)` succeeds with `Any()`.
    - A copy of the graph under `MaxDepth: 1` that refuses makes 0 calls.
  - `TestClaimsWithoutAnySet`: the same graph with AS-W (members `AS1, AS-Y`) as the top.
    - `ExpandAS(AS-W)` = `[1 2 3 100 101]`, and `pathSet`'s answer through `<AS-W>` is equal.
    - With `failOn: "AS-Z"`, both fail with that error (Review Focus 4).
  - `TestClaimsPassHonoursCancel` (Review Focus 5): a `MembersByRef` that cancels the context
    and then returns. `ExpandAS(AS-W)` returns `context.Canceled`.
  - `TestConcurrencyWithClaims`:
    - 200 seeds. Each draws 6 sets `AS-C0..AS-C5`:
      - random AS members and nested `AS-Cj` (cycles allowed);
      - each with probability 1/2 `mbrs-by-ref: MNT-A`;
      - each with 0–2 claimant aut-nums (`member-of: AS-Cj`, `mnt-by: MNT-A`), each claimant with
        one route.
    - Compare serial with `Concurrency` 2, 8 and 64 for `ExpandAS(AS-C0)`,
      `ExpandPrefixes(AS-C0)` and `NormalizeFilter(<AS-C0>)`. Compare `String()` and `Missing()`.

    This is a new generator, not `randomGraph`: `randomGraph`'s BFS oracle does not model claims,
    so adding claimants there would break every test that uses it (the spec's preferred option,
    set aside for that reason).

- [ ] **Step 2: Run them and see `TestDiscoverSkipsClaims` fail (2 calls today)**

  Run: `cd resolve && go test -run 'TestDiscoverSkipsClaims|TestClaimsWithoutAnySet|TestClaimsPassHonoursCancel|TestConcurrencyWithClaims' -count=1 -race .`

- [ ] **Step 3: Implement the deferral as in Interfaces; call `fetchClaims` at the end of `discover` when `len(g.any) == 0`**

- [ ] **Step 4: Run the four tests, then the module under `-race`**

  Run: `cd resolve && go test -race -count=1 ./... > /tmp/t3.txt 2>&1; echo $?`, then read the file.
  Expected: 0. The backend model tests (irrd and whois over fake servers) hold every answer equal.

- [ ] **Step 5: Commit**

  ```bash
  git add resolve/expander.go resolve/claims_test.go
  git commit -m "resolve: fetch indirect members only after a discovery that needs them"
  ```

---

### Task 4: The ASPA full-table rule reads "rejects every path" (F2)

**Files:**
- Modify: `resolve/consist/aspa.go`:
  - the comment on `fullTable` (~line 31);
  - `onlyNegated` (~line 50) drops its `Sets` loop and excludes a conjunct when a negated path
    test `rejectsEveryPath`.
- Create: `resolve/consist/pathall.go`: `rejectsEveryPath(p resolve.PathMatch) bool` and its
  helpers, unexported.
- Test: new `resolve/consist/pathall_test.go`; `resolve/consist/aspa_test.go`
  (`TestASPAMissingProvider` rows, `TestASPAAnySetPath`).
- Docs:
  - `docs/diagnostics.md`, the `lint/aspa-missing-provider` entry (~line 172);
  - CLAUDE.md:233 ("…none naming a set that reaches AS-ANY" → "…none rejecting every route with
    a path");
  - `docs/rpslcheck.md:176`.

**Interfaces:**
- Produces: `rejectsEveryPath(p resolve.PathMatch) bool`, true exactly when `p.RE.Body` has no
  `ASPathStart`/`ASPathEnd` anywhere and (`nullable(body)` || `onesAll(body, p.Sets)`).

`onesAll` and `nullable` are defined over `policy.ASPathExpr`; spec F2 lists the rules. The
type switch is exhaustive over the 12 node types:

| node | `onesAll` | `nullable` |
|---|---|---|
| `ASPathAny` | true | false |
| `ASPathSet` named AS-ANY (EqualFold) | true | false |
| `ASPathSet` with `Sets[name].Any()` | true | false |
| other `ASPathSet`, `ASPathASN`, `ASPathASNRange`, `ASPathSetTemplate`, `ASPathPeerAS` | false | false |
| `ASPathClass` not negated | some item `onesAll` | false |
| `ASPathClass` negated | false | false |
| `ASPathAlt` | some alternative `onesAll` | some alternative `nullable` |
| `ASPathSeq` | some term `onesAll` and every other term `nullable` | every term `nullable` (an empty Seq: true) |
| `ASPathRepeat` | `Min ≤ 1` and inner `onesAll` | `Min == 0` or inner `nullable` |
| `ASPathStart`, `ASPathEnd` | unreachable: anchored regexps are rejected first | |

- [ ] **Step 1: Write `TestRejectsEveryPath` (table, `pathall_test.go`)**

  Build each `PathMatch` with `policy.ParseASPathRegexp`; `AS-R` maps to `resolve.NewAnyASNSet()`
  and `AS-S` to an ordinary set.

  true:
  - `.`, `AS-ANY`, `AS-R`, `.* AS-R .*`, `[AS1 AS-ANY]`, `[AS-R]`;
  - `AS1*` (nullable), `AS1? AS2?` (nullable);
  - `.+`, `(AS1|.)`, `AS1? .`.

  false:
  - `AS1 AS-R`, `.* AS64512 .*`, `^AS-R`, `^.$`, `AS-R$`;
  - `.{2}`, `[^AS1]`, `AS-S`, `PeerAS`, `AS1`.

- [ ] **Step 2: Add rows to `TestASPAMissingProvider` and cases to `TestASPAAnySetPath`**

  - `TestASPAMissingProvider`, no issue: `ANY AND NOT <.>`, `ANY AND NOT <AS-ANY>`,
    `ANY AND NOT <AS1*>`.
  - `TestASPAMissingProvider`, the `missingAS2` issue: `ANY AND NOT <.* AS64512 .*>`.
  - `TestASPAAnySetPath`:
    - Add `import: from AS9 accept ANY AND NOT <AS-ANY>` and `… ANY AND NOT <.>` to its
      no-issue loop.
    - Add a second loop that expects exactly one `aspa-missing-provider` issue (from AS9) for
      `import: from AS9 accept ANY AND NOT <AS1 AS-R>`. This is the narrowing; its `anyR` is the
      any-set.
    - Its comment gains: "and so does a literal AS-ANY or `.`; a negated test that rejects only
      some paths (`NOT <AS1 AS-R>`) still leaves a full table".

- [ ] **Step 3: Run them and see the new cases fail**

  Run: `cd resolve && go test -run 'TestRejectsEveryPath|TestASPAMissingProvider|TestASPAAnySetPath' -count=1 ./consist`

- [ ] **Step 4: Implement `pathall.go` and change `onlyNegated`. Rewrite `fullTable`'s comment to state the new rule (it is still ruling F1)**

- [ ] **Step 5: Run the consist package, then update the three docs listed under Files**

  Run: `cd resolve && go test -count=1 ./consist ./internal/rpslcheck > /tmp/t4.txt 2>&1; echo $?`
  Expected: 0. If an rpslcheck golden changes, inspect the diff. Regenerate it with
  `RPSL_RPSLCHECK_UPDATE=1` only when every changed line is explained by the new rule.

- [ ] **Step 6: Commit**

  ```bash
  git add resolve/consist/ docs/diagnostics.md docs/rpslcheck.md CLAUDE.md
  git commit -m "consist: a full table excludes a negated test that rejects every path"
  ```

---

### Task 5: rtconfig class translation independent of item order (F7)

**Files:**
- Modify: `resolve/rtconfig/regex.go`, `translator.members`, the `ASPathClass` case (~lines 72–113).
- Test: `resolve/rtconfig/regex_test.go`, new `TestTranslateClassAnyOrder`.

**Interfaces:** none. This is internal to `translator`.

- [ ] **Step 1: Write `TestTranslateClassAnyOrder`**

  For every `Vendors()` and both polarities, via `Generator.WriteASPathList` with the
  `pathMatch` helper (regex_test.go:17):
  - `[AS-ANY AS1-AS5000]`, `[AS1-AS5000 AS-ANY]`, `[. AS1-AS5000]` and `[AS1-AS5000 .]` write
    the same bytes as `.` alone.
  - `[AS1-AS5000]` is `CausePathShape`.
  - `[AS1-AS5000 AS-R]` and `[AS-R AS1-AS5000]`, with AS-R an any-set (`anySetText`'s shape,
    regex_test.go), are `CauseAnySet`.

- [ ] **Step 2: Run it and see the reversed orders fail**

  Run: `cd resolve && go test -run TestTranslateClassAnyOrder -count=1 ./rtconfig`

- [ ] **Step 3: Collect range items during the loop; after it, return any if `anyAS`, otherwise check (`maxClassRange`) and expand them. Remove the `continue` and its "as before" comment**

- [ ] **Step 4: Run rtconfig, then the IRRToolSet differential if `peval`/`rtconfig` are on PATH**

  Run: `cd resolve && go test -count=1 ./rtconfig ./internal/cfgsim . -run 'Rtconfig|Translate|Divergences' > /tmp/t5.txt 2>&1; echo $?`
  Expected: 0, with no golden change.

- [ ] **Step 5: Commit**

  ```bash
  git add resolve/rtconfig/regex.go resolve/rtconfig/regex_test.go
  git commit -m "rtconfig: a class holding any AS is any AS, whatever its order"
  ```

---

### Task 6: Docs and check.sh (F1, F5, F6, F10, F11)

**Files:**
- Modify: `docs/diagnostics.md`, the `lint/any-set` entry (~line 140), for F1. Append the
  sentence from spec F1.
- Modify: `resolve/consist/lint.go`, the comment on `anySets`, for F1, saying the same.
- Modify: CLAUDE.md, the any-set bullet's first sentence, for F5. Exact text in spec F5.
- Modify: `resolve/consist/consist_realdata_test.go:44`, for F6. Exact text in spec F6.
- Modify: `resolve/testdata/rtconfig/divergences.md:63-65`, for F11. Move the D18 row before
  D19.
- Modify: `scripts/check.sh` `gofiles` and the gofmt step, for F10.

**Interfaces:** none.

- [ ] **Step 1: F10, check.sh**

  `gofiles` writes `git ls-files -z …` to a temp file (`mktemp`, removed by the function) and
  returns 1 when git fails. The gofmt step then becomes
  `files=$(mktemp) && gofiles > "$files" || bad "could not list Go files"`, then
  `xargs -0 gofmt -l < "$files"`, keeping today's status test. Keep it `#!/bin/sh`: no
  `pipefail`.

- [ ] **Step 2: Verify F10 by hand**

  Copy `scripts/check.sh` into the scratchpad directory and run just its gofmt section from a
  directory outside any repo.
  Expected: `FAIL: could not list Go files`. Then run `sh -n scripts/check.sh` (exit 0).

- [ ] **Step 3: Make the text edits for F1, F5, F6 and F11**

- [ ] **Step 4: Run the doc-contract tests**

  Run: `cd resolve && go test -count=1 -run 'Divergences|Docs' ./... > /tmp/t6.txt 2>&1; echo $?`
  Expected: 0 (`TestDivergencesDocumented`, `TestRpslconfDocs` and friends).

- [ ] **Step 5: Commit**

  ```bash
  git add docs/diagnostics.md resolve/consist/lint.go CLAUDE.md \
    resolve/consist/consist_realdata_test.go resolve/testdata/rtconfig/divergences.md scripts/check.sh
  git commit -m "docs, check.sh: review fixes F1, F5, F6, F10, F11"
  ```

---

### Task 7: CHANGELOG, full verification, real data, review

**Files:**
- Modify: `CHANGELOG.md`, `[Unreleased]`.
  - Changed:
    - F3: MaxVisited is one budget per normalization;
    - F4: a regexp's any-set stops at AS-ANY;
    - F2: the ASPA full-table rule;
    - F7.
  - Fixed: F8 (a failing `MembersByRef` no longer fails an answer that needs no claims).

- [ ] **Step 1: Write the CHANGELOG entries and commit them (`changelog: review fixes`)**

- [ ] **Step 2: Full check**

  Run: `GOMAXPROCS=4 GOMEMLIMIT=6GiB scripts/check.sh > /tmp/check.txt 2>&1; echo $?` under the
  memory watchdog, then read the file.
  Expected: 0, and `apisurface -check` passes with no `api/` diff.

- [ ] **Step 3: Fuzz the touched parsers and normalizers**

  Run: `FUZZTIME=15s` for `FuzzNormalizeFilter` (resolve) and `FuzzTranslateRegexp`
  (resolve/rtconfig), as `scripts/fuzz.sh` runs them.
  Expected: no failure.

- [ ] **Step 4: Real data, main vs branch, one run at a time**

  1. `git worktree add ../rpsl-main main`.
  2. In each tree, run `RPSL_REALDATA=$PWD/../.data RPSL_CONSIST_SAMPLE=2000 RPSL_CONSIST_ASPA=1
     go test -timeout 60m -run TestRealDataConsist -v ./consist > <tree>-consist.txt 2>&1; echo $?`
     from `resolve/`. Use `GOMAXPROCS=4` and `GOMEMLIMIT=6GiB`.
  3. Diff the summary counts (`lint/aspa-missing-provider`, "not decidable: any set", limits,
     timeouts). Explain every changed aut-num by F2, F3 or F4, or stop and report.
  4. `RPSL_REALDATA=… RPSL_PEVAL_AS=AS8308,AS1887 go test -run TestRealDataPeval -v .` in both
     trees. Every session of AS8308 and AS1887 decides identically.
  5. `git worktree remove ../rpsl-main`.

- [ ] **Step 5: Independent review**

  Dispatch a fresh reviewer on `git diff main...review-fixes` with the spec. Fix its Critical and
  Important findings, re-run Step 2, then report to the user. No push or PR without the user's
  word.
