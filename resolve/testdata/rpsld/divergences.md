# Known divergences from IRRd 4.5.3

`rpsld` answers as IRRd 4.5.3 does on the same data
(`resolve/testdata/irrd/golden`, recorded from IRRd in Docker by
`resolve/internal/irrdoracle`'s `TestRecord`). It differs only in the cases
below; each is pinned by `resolve/irrdq`'s `TestGoldens` (the `diverges` map)
with `rpsld`'s own answer, so a change on either side fails a test.

| Case | IRRd 4.5.3 | rpsld | Why |
| --- | --- | --- | --- |
| `session/v`, `session/not-persistent`, `session/blank-first`, `session/crlf`, `session/spaces-first`, `session/blank-in-session`, `eof/v`, `eof/session` | `IRRd -- version 4.5.3` | `IRRd -- version 4.5.3 (rpsld <version>)` | Clients detect IRRd 4 by the prefix (bgpq4 decides on `!a` by it) and IRRToolSet needs the word "version"; the parenthesis says what answers. |
| `session/pipeline`, `ripe/in-session` | `IRRd -- version 4.5.3` (its `!v`) | `IRRd -- version 4.5.3 (rpsld <version>)` | Each holds a `!v`, answered as above. `session/pipeline`'s `!g` answer, which IRRd gives in hash order and `rpsld` sorts, is compared as a multiset and is no divergence; `ripe/in-session` also ends in a plain lookup without `-T`, refused (below), and serves its objects as loaded. |
| `m/mntner,MNT-A`, `m/person,JD1-RIPE` | The object (`A…`) | `F Class mntner is not kept by this mirror` (`person` likewise) | Refinement 11: the mirror keeps the routing classes only. An `!m` of any other class `object.RIPE` or `object.IRRd` lists is refused, never answered `D`, which would pass an object it does not hold off as missing. A class neither profile lists stays IRRd's `D`. |
| `ripe/-T mntner MNT-A` | The two maintainers | `%% ERROR: Class mntner is not kept by this mirror` | Refinement 11, for `-T`: a class either profile lists but the mirror does not keep is refused; an unknown class stays IRRd's "No entries" (`ripe/-T foo AS65001`). |
| `ripe/AS65001`, `ripe/as65001`, `ripe/AS65001 AS65002`, `ripe/AS-NOSUCH`, `ripe/-s ripe AS-FOO`, `ripe/-K AS-NORM`, `ripe/-s RADB AS-NORM`, `ripe/192.0.2.0/24`, `ripe/rtr1.example.net`, `ripe/MNT-A`, `ripe/JD1-RIPE`, `session/q-bare`, `rpki/-s RPKI 192.0.2.0/24` | The objects IRRd's text search finds (an aut-num, routes, a set, an inet-rtr, two maintainers, a person), or `%  No entries found for the selected source(s).` | `%% ERROR: This mirror keeps only the routing classes, so it cannot answer a lookup of <key> whole; ask with -T and any of as-set, route-set, rtr-set, filter-set, peering-set, aut-num, inet-rtr, route, route6` | Refinement 11 as ruled in Task 6's review: a plain (primary-key) lookup is refused unless `-T` names only classes the mirror keeps. Without `-T`, IRRd's `text_search` answers with classes the mirror lacks: an AS number with the as-blocks covering it, a prefix or an address with inetnums and inet6nums, and any other key with persons and roles whose name holds it. Any answer would be partial and "No entries" possibly false. With such a `-T` the answer is whole and is given (`ripe/-T as-set AS-FOO`, `ripe/-r -T aut-num AS65001`, `ripe/-T route 192.0.2.0/24`). A `-T` naming a known class the mirror does not keep is refused (below); one naming only unknown classes stays IRRd's "No entries" (`ripe/-T foo AS65001`). Route searches (`-x`, `-l`, `-L`, `-M`), which search only routes, and inverse searches are answered as IRRd answers them. `ripe/in-session` ends in such a lookup (`AS-NOSUCH`). |
| `ripe/-i mnt-by MNT-B` | Every object `MNT-B` maintains | `%% ERROR: Inverse search on mnt-by is not served by this mirror: it keeps the routing classes only` | Refinement 11: `mnt-by`, `admin-c`, `tech-c`, `zone-c`, `person` and `role` name objects of every class, most of which the mirror does not keep, so no answer it could give would be whole. `!o<mntner>`, IRRd's inverse search on `mnt-by`, gets the same answer as an `F` line (`TestNotServed`). |
| `ripe/-i foo bar` | `… not supported for foo,only supported for attributes: role, mnt-by, person, origin, members, zone-c, mp-members, mbrs-by-ref, member-of, admin-c, tech-c` | `… not supported for foo, only supported for attributes: origin, member-of, mbrs-by-ref, members, mp-members` | Refinement 11: the list names the attributes the mirror answers, and only those; IRRd's lists a Python set (hash order) and lacks the space after its comma. |
| `m/an,AS65001`, `m/rt,192.0.2.0/24-AS65001` | `D` | The object, as `!maut-num` and `!mroute` give it | Refinement 12: IRRToolSet's `rtconfig` asks `!m` with its legacy class names `an`, `ir` and `rt`, which IRRd 4.5.3 does not know, so against IRRd it gets nothing. |
| `TestRouteSearchOptions` (a unit test: no golden) | `!r192.0.2.0/24,o,l`: `F An internal error occurred while processing this query.` (IRRd splits the parameter into exactly two parts) | `F Invalid route search option: o,l` | rpsld names the bad option instead of failing. |
| `TestNotServed` (a unit test: no golden) | Answers `!e` (set exclusion for `!a`/`!i…,1`), `!J` (database status as JSON), `!o<mntner>` (objects that maintainer maintains), `!fno-rpki-filter`, `!fno-scope-filter`, `!fno-route-preference-filter`, and the RIPE-style `-a` (the default sources again), `-t` (a class template), `-q sources` and `-g` (NRTMv3) | `F Command !<command> is not served by this mirror` (`!o`: `F Inverse search on mnt-by is not served by this mirror: it keeps the routing classes only`); RIPE-style `%% ERROR: Flag -<flag> is not served by this mirror` | Refinement 10: commands outside what a mirror of the routing classes answers. `rpsld` does not filter by scope or route preference, so it has nothing to switch off; it hides RPKI-invalid routes in RPKI-aware mode without a per-connection exception. |
| `TestInvalidMembersServed` (a unit test: no golden can show it) | Refuses a whole as-set or route-set on import when one `members:`/`mp-members:` item fails to parse, or when a route-set's `members:` holds an IPv6 prefix (IRRd reads that attribute as IPv4 only), so the set is not there at all | Serves the set as the library parses it: every valid item, normalized, and an item it cannot read as written, upper-cased | rpsld serves every object the library parses and does not emulate IRRd's import validation. IRRd's loader refuses such an object, so the fixture cannot hold one and no golden can be recorded. |

Object text is served as the registry published it, not re-rendered as
IRRd renders it (attribute names lower-cased, values padded to column 16,
lists rejoined with commas): golden cases of kind `objects` are compared
after `irrdoracle.Normalize` applies IRRd's rewrites to both sides.

Answers IRRd gives in hash or database order (`!g`, `!6`, `!a`, `!r …,o`,
multi-object answers) are sorted by `rpsld`; those cases are compared as
multisets.

## RFC mode

With `-rfc` (`irrdq.SnapshotOptions.RFC`), `!i<set>,1` and `!a` answer the
engine's RFC 2622 expansion (`resolve.Expander` over the session's selected
registries, in precedence order, RPKI-filtered in RPKI-aware mode) instead
of IRRd's. They differ from IRRd exactly where
`resolve/testdata/bgpq4/divergences.md` says the engine and IRRd/bgpq4
differ; every other command is answered as without `-rfc`
(`TestRFCModeChangesNothingElse` replays every recorded golden exchange
both ways).

| Case | IRRd 4.5.3 | rpsld `-rfc` | Why |
| --- | --- | --- | --- |
| `TestRFCMode`, `TestRFCModeDiffers`, `TestRFCModeScoped`, `TestRFCModeLimits` (unit tests: IRRd has no RFC mode to record) | A range operator on a member drops it from `!i…,1` (`RS-IN^25`, `AS1^24`; `TestRFCModeDiffers`' RS-OP); a route-set listed in an as-set is followed from a route-set root (its RS-TOP); `src-members:` is not read; `AS-ANY` and `RS-ANY` are missing sets, so a set listing one expands without it (its AS-Z) | Operators applied (RFC 2622 §5.2-5.3, ranges in RPSL notation: RS-OP is `10.0.0.0/8^24 192.0.2.0/24^25 198.51.100.0/24^+`, IRRd mode `198.51.100.0/24^+`); a route-set in an as-set not followed (§5.1: RS-TOP is `10.2.0.0/16`, IRRd mode adds RS-Y's `10.3.0.0/16 203.0.113.0/24`); `src-members:` honoured, a scoped reference looked up in its registry whether selected or not (`TestRFCModeScoped`); an expansion reaching `AS-ANY` or `RS-ANY` refused: `F AS-ANY denotes the whole registry: not expanded in RFC mode`; a limit refused with the engine's error (`F resolve: expansion of AS-L1 exceeds MaxDepth (1): reached 2`, and likewise for MaxVisited and MaxPrefixes: `TestRFCModeLimits`), never a partial answer | `-rfc` is for clients that want RFC 2622's answer from an IRRd-speaking server, and the engine's answer is that: it refuses what it cannot expand rather than quietly dropping it. A missing set, a set of another class, or a route-set given to `!a`, is `D` as in IRRd. On the fixture, 18 recorded `!i…,1`/`!a` exchanges of the plain goldens are answered otherwise (`i1/AS-FOO`, `i1/as-foo`, `i1/AS-BAR`, `i1/RS-FOO`, `i1/AS-RADBONLY`, `i1/AS-ANY`, `i1/RS-ANY`, `i1/RS-NOLEN`, `i1/RS-LOWER`, `i1/AS-LOWER`, `a/aAS-FOO`, `a/a4AS-FOO`, `a/a6AS-FOO`, `a/aAS-BAR`, `a/aAS-RADBONLY`, `a/aAS-ANY`, `a/aas-foo`, `a/aAS-LOWER`: all but `i1/RS-NOLEN` the AS-ANY or RS-ANY refusal, since RS-FOO, AS-BAR, AS-RADBONLY, RS-LOWER and AS-LOWER reach AS-ANY through AS-FOO; `i1/RS-NOLEN` is `206.197.238.0/32` alone, its `^+` being the /32 itself), and 2 of the rpki ones (`rpki/!aAS-FOO`, `rpki/!iRS-FOO,1`); the others agree. |

## Server behaviour

How `rpsld` treats a connection (`resolve/irrdserver`), as opposed to what
it answers. No golden case can show it, so each row names the
`resolve/irrdserver` tests that pin it (`TestDivergencesDocumented` checks
that each named test exists there). Every limit is refused with an `F` line
and its reason, never with a cut-short answer.

| Case | IRRd 4.5.3 | rpsld | Why |
| --- | --- | --- | --- |
| `TestLimitDefaults`, `TestIdleTimeout` (the limits' defaults) | Waits 30 s for a command (`SOCKET_DEFAULT_TIMEOUT`, 30.03 s measured), `!t` setting 1-1000 s per connection | The same 30 s and `!t` (`Limits.IdleTimeout`); its own limits besides: `MaxConns` 256, `MaxLine` 1 MiB, `MaxReply` 256 MiB, `QueryTime` 60 s | The idle timeout is IRRd's, so clients tuned to IRRd see no change; the other four bound what one client can take from a server that answers from memory. |
| `TestMaxConns` | Queues a connection past its `max_connections` (10) until one ends | Closes a connection past `MaxConns` as soon as it is accepted, unanswered | A queued client waits with no sign of why; a closed one can retry or go elsewhere at once. |
| `TestMaxLine` | Has no line limit: a 1 MB line was answered | A line over `MaxLine` bytes is answered `F Line too long: over <MaxLine> bytes` and the connection closed (as soon as that many bytes have arrived, newline or not) | No command needs a line that long, and an unbounded line is unbounded memory. |
| `TestMaxReply`, `TestQueryTime` | Not recorded | An answer over `MaxReply` bytes is `F Answer larger than <MaxReply> bytes`; a command still evaluating after `QueryTime` is `F Query took longer than <QueryTime>`. Both keep the connection, as an IRRd error does (a one-shot connection closes as after any command) | An answer is never cut short, so the limit is decided before anything is sent; and an answer that grows with the data (`!r…,M`, `-M`: ARIN's is about 52 MB) stops being built as soon as it passes `MaxReply` (`irrdq.Session.SetMaxReply`, held by `irrdq`'s `TestBudgetStopsBuilding`), so a far larger one costs a connection a small multiple of the limit, not its own size. |
