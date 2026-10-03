# Known divergences from IRRd 4.5.3

`rpsld` answers as IRRd 4.5.3 does on the same data
(`resolve/testdata/irrd/golden`, recorded from IRRd in Docker by
`resolve/internal/irrdoracle`'s `TestRecord`). It differs only in the cases
below; each is pinned by `resolve/irrdq`'s `TestGoldens` (the `diverges` map)
with `rpsld`'s own answer, so a change on either side fails a test.

| Case | IRRd 4.5.3 | rpsld | Why |
| --- | --- | --- | --- |
| `session/v`, `session/not-persistent`, `session/blank-first`, `session/crlf`, `session/spaces-first`, `session/blank-in-session` | `IRRd -- version 4.5.3` | `IRRd -- version 4.5.3 (rpsld <version>)` | Clients detect IRRd 4 by the prefix (bgpq4 decides on `!a` by it) and IRRToolSet needs the word "version"; the parenthesis says what answers. |
| `session/pipeline` | `IRRd -- version 4.5.3` (its `!v`) | `IRRd -- version 4.5.3 (rpsld <version>)` | It holds a `!v`, answered as above. Its `!g` answer, which IRRd gives in hash order and `rpsld` sorts, is compared as a multiset and is no divergence. |
| `TestInvalidMembersServed` (a unit test: no golden can show it) | Refuses a whole as-set or route-set on import when one `members:`/`mp-members:` item fails to parse, or when a route-set's `members:` holds an IPv6 prefix (IRRd reads that attribute as IPv4 only), so the set is not there at all | Serves the set as the library parses it: every valid item, normalized, and an item it cannot read as written, upper-cased | rpsld serves every object the library parses and does not emulate IRRd's import validation. IRRd's loader refuses such an object, so the fixture cannot hold one and no golden can be recorded. |

Object text is served as the registry published it, not re-rendered as
IRRd renders it (attribute names lower-cased, values padded to column 16,
lists rejoined with commas): golden cases of kind `objects` are compared
after `irrdoracle.Normalize` applies IRRd's rewrites to both sides.

Answers IRRd gives in hash or database order (`!g`, `!6`, `!a`, `!r …,o`,
multi-object answers) are sorted by `rpsld`; those cases are compared as
multisets.
