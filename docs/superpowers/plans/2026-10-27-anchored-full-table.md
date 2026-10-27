# One-sided anchors in the ASPA full-table rule — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Change `rejectsEveryPath` (resolve/consist/pathall.go) in two ways:
- A negated AS-path test anchored on one side (`^R` or `R$`) gets the answer of its unanchored
  form.
- A top-level alternation is judged branch by branch.

`ANY AND NOT <^AS-R>`, `NOT <^.>` and the like then stop counting as a full table for
`lint/aspa-missing-provider`.

**Architecture:**
- **Scope.** All code is in `resolve/consist/pathall.go`.
- **`rejectsEveryPath`.** It splits a top-level `ASPathAlt` into branches. Each branch, or the
  whole body, goes through a new `everyPath`, which drops one leading `ASPathStart` and/or one
  trailing `ASPathEnd` from the term list.
  - If both were dropped, the answer is "not all".
  - Otherwise the answer is today's `nullable(rest) || onesAll(rest)`.
- **Guard.** `hasAnchor(rest)` stays as a documented guard.
- **Tests.** A brute-force soundness test checks the rule against `routemodel.MatchPath`.

**Tech Stack:** Go 1.23, multi-module, wired by go.work. Run the resolve module's tests from
`resolve/`.

**Spec:** `docs/superpowers/specs/2026-10-27-anchored-full-table-design.md`. Read it first. Its
"The rule", "Results" and "Tests" sections are the requirements, and the Results table is the
exact answer list.

## Global Constraints

- Regexps anchored at both ends (`^R$`) stay "not all". The user approved leaving that rule out.
- Never "all" for a regexp that leaves a path: every "not known" stays "not all".
- No exported API change. `go run ./internal/apisurface -check` passes, and `api/` is untouched.
- Engine purity holds: `cd resolve && go list -deps . ./peval ./rtconfig ./consist ./irrdq ./rpki`
  shows no `net`.
- `routemodel` is used only from test files. No non-test code matches a regexp against a path.
- Heavy runs go one at a time, never beside each other:
  - under `/Users/roman/DEV/rpsl/.superpowers/sdd/tools/memguard.sh 8 <timeout_s> <cmd>`;
  - with `MEMGUARD_NORMAL_PRIORITY=1`, `GOMAXPROCS=4` and `GOMEMLIMIT=6GiB` set;
  - a chain of commands goes through `sh -c '…'`.
- `<ws>` is this plan's workspace, the directory `sdd-workspace` prints for this plan file.
- Commit messages take a lower-case package prefix (`resolve/consist: …`).
- zsh: redirect a command's output to a file and print `$?` on the next line. Never read a
  status through a pipe.

## Review Focus

1. **A body that is a bare anchor or empty.** `<^>`, `<$>` and `<>` are all, `<^$>` is not. A
   bare `ASPathStart` is not a `Seq`, so `terms` must wrap it. Pinned by Results rows in
   `TestRejectsEveryPath` (Task 1).
2. **An anchor that is only at an edge of a nested group,** such as `(^AS-R) AS1` or
   `^(AS-R$)`. Only the top-level term list is stripped, so these stay "not all". The
   soundness test draws nested groups with anchors (Task 1).
3. **An unanchored alternation.** Its answer must not change: branch by branch, then
   `nullable || onesAll`, is the same as the old whole-body test. Pinned by the existing
   `(AS1|.)` row (true) and a new `(AS1|AS2)` row (false) (Task 1).
4. **A set in `p.Sets` that is missing,** for example a set that was never expanded.
   `onesAll` treats it as "not all", unchanged, so `^AS-X` with AS-X absent from `Sets` is
   "not all". Pinned by a row using a name absent from the test's `sets` (Task 1).
5. **A full-table conjunct whose negation is anchored and names a set reaching AS-ANY, in
   both families** (`mp-import`). It goes through the same `fullTable` per conjunct. Pinned by
   an `mp-import` row in `TestASPAAnySetPath` (Task 2).

---

### Task 1: `rejectsEveryPath` reads one-sided anchors and top-level alternations

**Files:**
- Modify: `resolve/consist/pathall.go` (`rejectsEveryPath` and its doc comment, :9-22; a new
  `everyPath`)
- Test: `resolve/consist/pathall_test.go`

**Interfaces:**
- Produces: the same `rejectsEveryPath(p resolve.PathMatch) bool`, with new answers.
  `hasAnchor`, `nullable` and `onesAll` are unchanged.

- [ ] **Step 1: Write the failing tests**

1. In `TestRejectsEveryPath`:
   - Flip `{"^AS-R", false}` and `{"AS-R$", false}` to `true`.
   - Add every regexp of the spec's Results table with its "New" answer:
     - true: `^.`, `.$`, `^`, `$`, `^AS1*`, `^.* AS-R`, `AS-R$ | AS1$`, `^AS1 | AS-R`;
     - false: `^$`, `^AS-R+$`, `^AS1`, `^[AS1 AS2]`, `^AS-R AS1`, `AS1 ^ AS-R`, `^(^AS-R)`.
   - Add the Review Focus rows:
     - true: `<>`, written as the empty string;
     - false: `(^AS-R) AS1`, `^(AS-R$)`, `(AS1|AS2)`, and `^AS-X`, where AS-X is not in
       `sets`.
   - If a row does not parse, record that in a ruling and drop it. Do not change the parser.
2. New `TestRejectsEveryPathSound`, in the same file. Its rules are in the spec under Tests:
   - Atoms: AS1, AS2, `.`, AS-R (`resolve.NewAnyASNSet()`), AS-S (`resolve.NewASNSet(1)`),
     `[AS1 AS2]`, `[^AS1]`.
   - Operators: `*`, `+`, `?`, `{2}`. Sequences and alternations two levels deep. `^` and `$`
     at the edges, and sometimes in the middle or inside a group.
   - Seed `rand.New(rand.NewPCG(1, 0))`.
   - Each regexp is rendered as text and parsed with `policy.ParseASPathRegexp`. On a parse
     error, draw again.
   - Soundness: for every regexp `rejectsEveryPath` calls all, `routemodel.MatchPath` must
     return true for every path of length 1 to 3 over {AS1, AS2, AS3}. A `MatchPath` error is
     `t.Fatalf`.
   - Metamorphic: for every anchor-free regexp R it calls all, it must also call `^R` and `R$`
     all (re-rendered and re-parsed).
   - Non-vacuity: count the true answers per kind (no anchor, `^` only, `$` only, top-level
     alternation with an anchor) and `t.Errorf` for any kind with zero.
   - Draw enough regexps for non-zero counts, while `go test -run TestRejectsEveryPathSound`
     stays under 1 s.

- [ ] **Step 2: Run them and watch them fail**

Run (from `resolve/`):
`go test -count=1 -run 'TestRejectsEveryPath' ./consist > <ws>/t1-red.txt 2>&1; echo $?`

Expected:
- 1;
- `rejectsEveryPath(<^AS-R>) = false, want true` and `rejectsEveryPath(<AS-R$>) = false, want
  true`, with similar failures for the other new true rows;
- `TestRejectsEveryPathSound` fails on its non-vacuity check for `^` and `$`. Soundness itself
  holds today, because the code never says true for an anchored regexp.

- [ ] **Step 3: Implement**

Add `everyPath(e policy.ASPathExpr, sets map[types.SetName]resolve.ASNSet) bool` in
pathall.go, following the spec's pseudocode. `rejectsEveryPath` gives a top-level `ASPathAlt` to
`everyPath` one branch at a time, and any other body to `everyPath` whole.

The `hasAnchor(rest)` check gets a comment: "never changes an answer, since nullable and
onesAll treat an anchor as an atom that matches nothing. It keeps the safety argument local."

The doc comment is rewritten to state the one-sided reduction, why it holds (the empty prefix
and the one-AS prefix), and that a regexp anchored at both ends is not counted.

- [ ] **Step 4: Run them and watch them pass, then the package**

Run (from `resolve/`):
`go test -count=1 ./consist > <ws>/t1-green.txt 2>&1; echo $?`

Expected: 0. Read the soundness test's non-vacuity counts with `-v -run
TestRejectsEveryPathSound`, and record them in the ledger.

- [ ] **Step 5: Commit**

```bash
git add resolve/consist/pathall.go resolve/consist/pathall_test.go
git commit -m "resolve/consist: a one-sided anchor rejects every path when its unanchored form does"
```

- [ ] **Step 6: Mutation, one at a time, each reverted with `git checkout resolve/consist/pathall.go`**

This runs on the code committed in Step 5.

1. Judge an `ASPathAlt` body whole, without the branch step. Expected: the
   `AS-R$ | AS1$` and `^AS1 | AS-R` rows fail.
2. Treat `left && right` like one side. Expected: `^$`, and `^AS-R+$` or the soundness test,
   fail.

Run each with `go test -count=1 -run 'TestRejectsEveryPath' ./consist > <ws>/t1-mut<N>.txt
2>&1; echo $?`, and record which tests fail.

There is no mutation for `hasAnchor(rest)`. That rested on a wrong premise, corrected in the
spec after the final review: a `TestRejectsEveryPath` row now pins the check.

### Task 2: The ASPA rule's tests, the model's menu and the docs

**Files:**
- Test: `resolve/consist/aspa_test.go` (`TestASPAMissingProvider` :62, `TestASPAAnySetPath` :177)
- Test: `resolve/aspa_model_test.go` (`aspaFilters` :78-85)
- Modify:
  - `resolve/consist/aspa.go:32-41` (`fullTable`'s doc)
  - `docs/diagnostics.md:181-182`
  - `docs/rpslcheck.md:176`
  - `CLAUDE.md:235`
  - `docs/rpsl-go-design.md:1120-1121`
  - `CHANGELOG.md` (`[Unreleased]`)

**Interfaces:**
- Consumes: Task 1's `rejectsEveryPath` answers.

- [ ] **Step 1: Write the tests**

1. `TestASPAMissingProvider`:
   - rows `NOT <^.>` and `NOT <.$>`, each `import: from AS2 accept ANY AND NOT <…>` with
     `aspa(1, 3)`, want nil;
   - a row `NOT <^[AS1 AS2]>`, which wants the `missingAS2` issue, like the existing
     `negated regexp` row.
2. `TestASPAAnySetPath`: add to its list of imports with no issue
   - `import: from AS9 accept ANY AND NOT <^AS-R>`,
   - `import: from AS9 accept ANY AND NOT <AS-R$>`,
   - `mp-import: from AS9 accept ANY AND NOT <^AS-R>`.
3. `aspaFilters`: append `"ANY AND NOT <^.>"` to `partial`. First read how the model's oracle
   uses `partial` (aspa_model_test.go:101-110 and wherever `im.full` is read). If anything
   there assumes more about `partial` than "not a full table", rule on it in the ledger and
   adapt.

- [ ] **Step 2: Run them**

Run (from `resolve/`):
`go test -count=1 -run 'TestASPAMissingProvider|TestASPAAnySetPath' ./consist > <ws>/t2-aspa.txt 2>&1; echo $?`

Expected: 0, since Task 1 is in. To show these rows can fail, run the same command with
Task 1's pathall.go reverted (`git stash` is not used: `git show HEAD~1:resolve/consist/pathall.go
> resolve/consist/pathall.go`, then `git checkout resolve/consist/pathall.go`). Expected: the
`NOT <^.>`, `NOT <.$>`, `<^AS-R>` and `<AS-R$>` rows fail, and `NOT <^[AS1 AS2]>` passes.

- [ ] **Step 3: The model**

Run (from `resolve/`, under memguard, 8 GB, 1800 s):
`go test -count=1 -run 'TestModelASPA' . > <ws>/t2-model.txt 2>&1; echo $?`

Expected: 0.

- [ ] **Step 4: Docs**

Each text is from the spec's Docs section:
- `fullTable`'s doc gains `NOT <^AS-R>` and `NOT <^.>` among the shapes that leave no table.
- diagnostics.md and rpslcheck.md: "a regexp anchored at one end counts as its unanchored form;
  one anchored at both ends never counts".
- CLAUDE.md: "(a regexp, unanchored or anchored at one end, that is nullable or matches every
  one-AS path, or a top-level alternation with such a branch, …)".
- rpsl-go-design.md:1120: the current rule.
- The CHANGELOG `### Changed` line.

Re-wrap to each file's width.

- [ ] **Step 5: Commit**

```bash
git add resolve/consist/aspa_test.go resolve/aspa_model_test.go resolve/consist/aspa.go docs/diagnostics.md docs/rpslcheck.md CLAUDE.md docs/rpsl-go-design.md CHANGELOG.md
git commit -m "resolve/consist: anchored negations in the ASPA full-table rule, tests and docs"
```

### Task 3: Verification (the controller runs this; it is not dispatched)

**Files:** none changed, unless a step finds a fault.

- [ ] **Step 1: Full check, under the guard**

  Run from the repo root:

  `MEMGUARD_NORMAL_PRIORITY=1 .superpowers/sdd/tools/memguard.sh 8 3600 env GOMAXPROCS=4 GOMEMLIMIT=6GiB scripts/check.sh > <scratchpad>/check.txt 2>&1; echo $?`

  Expected: 0, `check: ok`, and `git status` clean.

- [ ] **Step 2: Real data with ASPA on, main against the branch, one run at a time**

  1. `git worktree add <scratchpad>/rpsl-main main`.
  2. In each tree, from `resolve/` and under the guard as above, run:

     `RPSL_REALDATA=/Users/roman/DEV/rpsl/.data RPSL_CONSIST_ASPA=1 RPSL_CONSIST_SAMPLE=2000 GOMAXPROCS=4 GOMEMLIMIT=6GiB go test -count=1 -timeout 60m -run TestRealDataConsist -v ./consist > <scratchpad>/<tree>-consist-aspa.txt 2>&1; echo $?`
  3. Compare the summary counts, including each `lint/aspa-*` count:
     - every count that is not a time-budget count must be equal;
     - explain each changed aut-num from the test's logged examples;
     - stop and report if a count changes without an explanation.

     The expectation is no change.
  4. `git worktree remove <scratchpad>/rpsl-main`.

- [ ] **Step 3: Independent review**

  Dispatch a fresh reviewer on the most capable model with the branch's review package, the
  spec and this plan's Review Focus. Fix its Critical and Important findings, then re-run Task 1
  Step 4 and Task 3 Step 1. Report to the user. Push and open a PR only when the user says so.
