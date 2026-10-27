# One-sided anchors in the ASPA full-table rule — design

Approved by the user 2026-10-27. The both-ends rule is left out, as recommended.

## Why

`lint/aspa-missing-provider` warns when an aut-num imports a full table from a peer that its
ASPA does not list. A conjunct is a full table only if none of its negated AS-path tests rejects
every route with a path (`fullTable`, resolve/consist/aspa.go:42). Since v0.30.1 that question is
answered on the regexp's syntax tree by `rejectsEveryPath` (resolve/consist/pathall.go). For a
regexp with no anchor, the answer is "nullable, or matches every one-AS path".

Any regexp with `^` or `$` anywhere is "not all" today. So `ANY AND NOT <^AS-R>`, with AS-R
reaching AS-ANY, counts as a full table, although it rejects every route with a path: the first
AS of any path is in AS-R. `ANY AND NOT <^.>` and `ANY AND NOT <AS-R$>` count the same way. The
result is a false `aspa-missing-provider` warning. v0.30.1's CHANGELOG states the gap
("anchored forms such as `NOT <^AS-R>` now count as a full table"), and its design left it open
because the lemma behind the rule was proved only for unanchored regexps.

It is a real gap, but not one RIPE shows today. Measured on 2026-10-27 over the local dumps,
first lines of `import:`/`mp-import:` only (continuation lines were not scanned):

| Registry | Import lines | With `NOT <` | Anchored | Naming a set or `.` |
|---|---|---|---|---|
| RIPE | 377,000 | 36 | 35 | 0 |
| RADB | not counted | not counted | 7 | 3 |

- **RIPE:** all 35 anchored ones are `NOT <^[AS…]>`, a class of plain AS numbers, which stays
  "not all" under any rule.
- **RADB:** none of its three is in a full-looking conjunct. Two sit beside a positive as-set
  filter, and one in `NOT ANY AND …`. One of them is anchored at both ends:
  `NOT <^AS-ITSBRASIL-CUSTOMER+$>`.
- **ARIN and AFRINIC:** 1 each, a plain-AS class.

So the expected real-data change is zero. The fix is about correctness for the policies people
can write.

## Goals

1. A regexp anchored on one side, `^R` or `R$` with no other anchor in R, rejects every path
   exactly when the unanchored `R` does: `nullable(R) || onesAll(R)`. One-sided regexps become
   as complete as unanchored ones. Neither is fully exact, because `onesAll` reads sets and
   classes syntactically: a class of ranges covering every AS is not recognised. That stays.
2. A top-level alternation is judged branch by branch. `<AS-R$ | AS1$>` rejects every path when
   some branch, judged as a regexp of its own, does. This is my call, because the parser's own
   doc example (`<AS1$|AS2$>`) is exactly this shape.
3. Never wrong in the other direction: whenever `rejectsEveryPath` says true, the regexp
   matches every non-empty path. A brute-force test against `routemodel.MatchPath` holds that.
4. Every place that states the rule says the new one.

## Non-goals

- **A regexp anchored at both ends** (`^R$`) stays "not all". It asks a different question, "is
  every whole path in L(R)", which the lemma does not answer. **Open for the user:** a small
  sound rule could be added. It would cover `^.*$`, `^.+$` and `^AS-R+$` (a repeat with
  `Min ≤ 1`, no maximum, and an inner term that matches every AS, and Seq and Alt built from
  that). My recommendation is to leave it out: the one shape seen in real data is in a conjunct
  that is never a full table, and the follow-up was about one-sided anchors.
- **Anchors anywhere else** stay "not all": mid-sequence (`AS1 ^ AS2`), inside a repeat, a
  class, or a nested group. Only one leading `^` and one trailing `$` of the top-level sequence
  (or of a top-level branch) are removed. `hasAnchor` on what is left keeps everything else out.
- `peval`, `rtconfig` and `routemodel` are untouched: they match or translate paths, and this
  rule only classifies. `lint/any-set` and what a set reaching AS-ANY means are untouched.
- No other ASPA rule changes.

## Anti-goals

- A rule that ever says "rejects every path" for a regexp that leaves a path. That would hide a
  real full table and silence a real warning. Every "not known" stays "not all", as today.
- Evaluating a regexp against a path in non-test code (CLAUDE.md's guardrail). The answer stays
  on the syntax tree.

## The change

### The AST shapes it relies on

The parser collapses a one-term sequence and a one-branch alternation (policy/regexp.go:292 and
:307), and anchors are atoms of `Body` (:13-14). So:
- `<^AS-R>` is `ASPathSeq{Terms: [ASPathStart, ASPathSet]}`;
- `<^>` is a bare `ASPathStart`;
- `<AS-R>` is a bare `ASPathSet`;
- `<>` is an empty `ASPathSeq`, which matches every path.

`terms(e)` below means `e.Terms` for an `ASPathSeq` and `[e]` otherwise.

### The rule

```
rejectsEveryPath(p):
    if p.RE == nil or p.RE.Body == nil: false
    if Body is an ASPathAlt: true if some branch b has everyPath(b)
    else: everyPath(Body)

everyPath(e):
    ts := terms(e)
    left  := ts non-empty and ts[0] is ASPathStart   → drop it
    right := ts non-empty and ts[last] is ASPathEnd  → drop it
    rest  := the remaining terms as one expression (a Seq, or the single term)
    if hasAnchor(rest): false
    if left and right: false                         // non-goal above
    return nullable(rest) || onesAll(rest, p.Sets)
```

`terms` is applied to the term list after the `^` is dropped, so `<^$>` drops both, leaves an
empty rest, and is "not all" because it is anchored at both ends. That answer is correct: `<^$>`
matches only the empty path.

**Why one side reduces to the unanchored test.** `^R` matches a path when some prefix of the
path is in L(R). Every non-empty path has two prefixes in particular: the empty one and its
first AS alone. A one-AS path has only those two. So `^R` matches every non-empty path exactly
when R is nullable or R matches every one-AS path. That is the same condition as unanchored R,
whose lemma rests on the same two sub-paths. `R$` is the mirror case, with suffixes and the last
AS.

**Why branch by branch is sound.** If one branch matches every non-empty path, so does the
alternation. The converse fails (`<^AS1 | ^[^AS1]>` covers every path, but neither branch does),
so a miss stays "not all", which is the safe direction. Unanchored alternations go through
`nullable` and `onesAll` as today, so their answers do not change.

`rejectsEveryPath` stays unexported in consist. `hasAnchor`, `nullable` and `onesAll` are
reused unchanged.

### Results

| Regexp (negated, `AS-R` reaching AS-ANY) | Today | New |
|---|---|---|
| `^AS-R`, `AS-R$`, `^.`, `.$`, `^`, `$`, `^AS1*`, `^.* AS-R` | not all | **all** |
| `AS-R$ \| AS1$`, `^AS1 \| AS-R` | not all | **all** |
| `^.$`, `^$`, `^AS-R+$` | not all | not all (both ends) |
| `^AS1`, `^[AS1 AS2]`, `^AS-R AS1`, `AS1 ^ AS-R`, `^(^AS-R)` | not all | not all |
| `.`, `AS-R`, `AS1*`, `AS1 AS-R` (no anchor) | unchanged | unchanged |

## Tests

Test-first, in resolve/consist.

- **`TestRejectsEveryPath`** (pathall_test.go:11). This change is meant to change answers, so
  existing rows flip:
  - `{"^AS-R", false}` and `{"AS-R$", false}` at :29 become `true`. They are the RED.
  - `{"^.$", false}` must not change.
  - New rows: every regexp in the Results table, with its "New" answer. The real-data shape
    `^[AS1 AS2]` stays false.
- **`TestASPAMissingProvider`** (aspa_test.go). New rows, each through the rule's real entry
  point:
  - `ANY AND NOT <^AS-R>` and `ANY AND NOT <AS-R$>` give no `aspa-missing-provider`;
  - `ANY AND NOT <^[AS1 AS2]>` still gives one.
- **`TestRejectsEveryPathSound`** (new, pathall_test.go). Random small regexps:
  - Atoms: AS1, AS2, `.`, AS-R (reaches AS-ANY), AS-S (holds AS1 only), `[AS1 AS2]`,
    `[^AS1]`. Operators: `*`, `+`, `?`, `{2}`. Sequences and alternations two levels deep. `^`
    and `$` at the edges, and sometimes in the middle.
  - Each regexp is rendered as text and parsed with `policy.ParseASPathRegexp`. One that does
    not parse is drawn again.
  - Soundness: whenever `rejectsEveryPath` says true, `routemodel.MatchPath` accepts every path
    of length 1 to 3 over {AS1, AS2, AS3}.
  - A `MatchPath` error fails the test. It is never skipped. The generator draws only shapes
    `routemodel` supports (no `~` repeats, small counts), so an error means the generator needs
    fixing, and skipping errors could quietly drop the true cases. (This was raised by the
    builder check.)
  - Metamorphic: for an anchor-free R that `rejectsEveryPath` calls all, it also calls `^R` and
    `R$` all.
  - Non-vacuity: the test counts the true answers per kind (no anchor, `^`, `$`, top-level
    alternation) and fails if any count is zero.
  - Seeded with a fixed seed. The builder picks the number of draws so the test runs in well
    under a second.
  - `resolve/consist` may import `resolve/internal/routemodel`, since both are inside the
    resolve module.
- **The ASPA model** (resolve/aspa_model_test.go:80). `"NOT <^AS64999>"` is in the "full" menu
  and stays full under the new rule (`AS64999` is not every AS), so it does not flip. The model
  gains one anchored filter that rejects every path, on the not-full side (`ANY AND NOT <^.>`),
  so the model sees the new rule. First check what the oracle assumes about that list, which
  is that `partial` filters are never a full table.

## Verification before done

1. The two flipped rows fail before the change and pass after it. The new soundness test passes
   and reports non-zero counts for every kind.
2. Mutation, one run each:
   - drop the branch-by-branch step: the alternation rows fail;
   - treat `left and right` like one side: `^.$` and `^$` fail, and so does the soundness test.

   No mutation is planned for `hasAnchor(rest)`. `nullable` and `onesAll` already treat an
   anchor as an atom that never matches, which can only make an answer "not all". So removing
   the check changes no answer, and no test could catch it. It stays as a guard, with a comment
   saying so, because it keeps the safety argument visible in one place. (This was raised by
   the builder check.)
3. `scripts/check.sh` under memguard (`GOMAXPROCS=4`, `GOMEMLIMIT`, 8 GB cap): `check: ok`.
4. Real data, with ASPA on: `RPSL_CONSIST_ASPA=1` `TestRealDataConsist` on the seeded
   2,000-aut-num sample, main against the branch, one run at a time under memguard. The rule is
   reached only through the ASPA lint, so a run without `RPSL_CONSIST_ASPA` cannot see it. The
   `lint/aspa-*` counts are compared, and each changed aut-num is explained. The expectation,
   from the measurement under **Why**, is no change.

## Docs

Every place that states the rule:
- The `rejectsEveryPath` doc comment (pathall.go:9-16) and `fullTable`'s shape list
  (aspa.go:34-40). The list gains `NOT <^AS-R>` and `NOT <^.>` among the shapes that leave no
  table.
- `docs/diagnostics.md:181`: "and an anchored regexp never counts" becomes "a regexp anchored at
  one end counts as its unanchored form; one anchored at both ends never counts".
- `docs/rpslcheck.md:176`: the same change.
- `CLAUDE.md:235`: "(an unanchored regexp that is nullable or matches every one-AS path, …)"
  becomes "(a regexp, unanchored or anchored at one end, that is nullable or matches every
  one-AS path, or a top-level alternation with such a branch, …)".
- `docs/rpsl-go-design.md:1120` still says "no negated AS-path test naming a set that reaches
  `AS-ANY`", the wording from before v0.30.1. It gets the current rule, including this change.
- CHANGELOG `[Unreleased]`, `### Changed`: "`resolve/consist`: a negated AS-path test anchored at
  one end (`NOT <^AS-R>`, `NOT <^.>`, `NOT <AS-R$>`), or a top-level alternation with a branch
  that rejects every path, now rejects every route with a path, as its unanchored form does,
  and its conjunct is no full table for `lint/aspa-missing-provider`."

## Left to the builder

- The generator's exact shape and draw count, within the rules above.
- Where in pathall.go the alternation step and the anchor stripping go, and their helper names.
- Whether the ASPA model's new entry needs anything more than the one menu line.

## Release

No API change, and fewer false warnings, so this is a fix. It rides in v0.31.0 with
`SetName.IsAny`. Whether v0.31.0 ships now or later is the user's call.
