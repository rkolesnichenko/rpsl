# Known divergences from IRRd 4.5.3

`rpsld` answers as IRRd 4.5.3 does on the same data
(`resolve/testdata/irrd/golden`, recorded from IRRd in Docker by
`resolve/internal/irrdoracle`'s `TestRecord`). It differs only in the cases
below; each is pinned by `resolve/irrdq`'s `TestGoldens` (the `diverges` map)
with `rpsld`'s own answer, so a change on either side fails a test.

| Case | IRRd 4.5.3 | rpsld | Why |
| --- | --- | --- | --- |
| `session/v`, `session/not-persistent`, `session/blank-first`, `session/crlf`, `session/spaces-first`, `session/blank-in-session` | `IRRd -- version 4.5.3` | `IRRd -- version 4.5.3 (rpsld <version>)` | Clients detect IRRd 4 by the prefix (bgpq4 decides on `!a` by it) and IRRToolSet needs the word "version"; the parenthesis says what answers. |
| `session/pipeline`, `ripe/in-session` | `IRRd -- version 4.5.3` (its `!v`) | `IRRd -- version 4.5.3 (rpsld <version>)` | Each holds a `!v`, answered as above. The rest of each is no divergence: `session/pipeline`'s `!g` answer, which IRRd gives in hash order and `rpsld` sorts, is compared as a multiset, and `ripe/in-session`'s objects are served as loaded (below). |
| `m/mntner,MNT-A`, `m/person,JD1-RIPE` | The object (`A…`) | `F Class mntner is not kept by this mirror` (`person` likewise) | Refinement 11: the mirror keeps the routing classes only. An `!m` of any other class `object.RIPE` or `object.IRRd` lists is refused, never answered `D`, which would pass an object it does not hold off as missing. A class neither profile lists stays IRRd's `D`. |
| `ripe/-T mntner MNT-A` | The two maintainers | `%% ERROR: Class mntner is not kept by this mirror` | Refinement 11, for `-T`: a class either profile lists but the mirror does not keep is refused; an unknown class stays IRRd's "No entries" (`ripe/-T foo AS65001`). |
| `ripe/MNT-A`, `ripe/JD1-RIPE`, `session/q-bare` | The objects of that primary key (two maintainers; a person), or `%  No entries found for the selected source(s).` for `q` | `%% ERROR: This mirror keeps only the routing classes; it cannot answer a lookup of <key>` | Refinement 11: a plain lookup of a key that is no AS number, prefix or address, set name, or route or inet-rtr held could name a maintainer, a person (IRRd also matches part of a person's or role's name) or another class the mirror lacks, so "No entries" would be a guess. A `-T` naming only classes the mirror keeps makes the answer certain, and it is given. |
| `ripe/-i mnt-by MNT-B` | Every object `MNT-B` maintains | `%% ERROR: Inverse search on mnt-by is not served by this mirror: it keeps the routing classes only` | Refinement 11: `mnt-by`, `admin-c`, `tech-c`, `zone-c`, `person` and `role` name objects of every class, most of which the mirror does not keep, so no answer it could give would be whole. |
| `ripe/-i foo bar` | `… not supported for foo,only supported for attributes: role, mnt-by, person, origin, members, zone-c, mp-members, mbrs-by-ref, member-of, admin-c, tech-c` | `… not supported for foo, only supported for attributes: origin, member-of, mbrs-by-ref, members, mp-members` | Refinement 11: the list names the attributes the mirror answers, and only those; IRRd's lists a Python set (hash order) and lacks the space after its comma. |
| `m/an,AS65001`, `m/rt,192.0.2.0/24-AS65001` | `D` | The object, as `!maut-num` and `!mroute` give it | Refinement 12: IRRToolSet's `rtconfig` asks `!m` with its legacy class names `an`, `ir` and `rt`, which IRRd 4.5.3 does not know, so against IRRd it gets nothing. |
| `TestRouteSearchOptions` (a unit test: no golden) | `!r192.0.2.0/24,o,l`: `F An internal error occurred while processing this query.` (IRRd splits the parameter into exactly two parts) | `F Invalid route search option: o,l` | rpsld names the bad option instead of failing. |
| `TestNotServed` (a unit test: no golden) | Answers `!e` (set exclusion for `!a`/`!i…,1`), `!J` (database status as JSON), `!fno-rpki-filter`, `!fno-scope-filter`, `!fno-route-preference-filter`, and the RIPE-style `-a` (the default sources again), `-t` (a class template), `-q sources` and `-g` (NRTMv3) | `F Command !<command> is not served by this mirror`; RIPE-style `%% ERROR: Flag -<flag> is not served by this mirror` | Refinement 10: commands outside what a mirror of the routing classes answers. `rpsld` does not filter by scope or route preference, so it has nothing to switch off; it hides RPKI-invalid routes in RPKI-aware mode without a per-connection exception. |
| `TestInvalidMembersServed` (a unit test: no golden can show it) | Refuses a whole as-set or route-set on import when one `members:`/`mp-members:` item fails to parse, or when a route-set's `members:` holds an IPv6 prefix (IRRd reads that attribute as IPv4 only), so the set is not there at all | Serves the set as the library parses it: every valid item, normalized, and an item it cannot read as written, upper-cased | rpsld serves every object the library parses and does not emulate IRRd's import validation. IRRd's loader refuses such an object, so the fixture cannot hold one and no golden can be recorded. |

Object text is served as the registry published it, not re-rendered as
IRRd renders it (attribute names lower-cased, values padded to column 16,
lists rejoined with commas): golden cases of kind `objects` are compared
after `irrdoracle.Normalize` applies IRRd's rewrites to both sides.

Answers IRRd gives in hash or database order (`!g`, `!6`, `!a`, `!r …,o`,
multi-object answers) are sorted by `rpsld`; those cases are compared as
multisets.
