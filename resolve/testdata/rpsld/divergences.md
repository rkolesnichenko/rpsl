# Known divergences from IRRd 4.5.3

`rpsld` answers as IRRd 4.5.3 does on the same data
(`resolve/testdata/irrd/golden`, recorded from IRRd in Docker by
`resolve/internal/irrdoracle`'s `TestRecord`). It differs only in the cases
below; each is pinned by `resolve/irrdq`'s `TestGoldens` (the `diverges` map)
with `rpsld`'s own answer, so a change on either side fails a test.

| Case | IRRd 4.5.3 | rpsld | Why |
| --- | --- | --- | --- |
| `session/v`, `session/not-persistent`, `session/blank-first`, `session/crlf`, `session/spaces-first`, `session/blank-in-session` | `IRRd -- version 4.5.3` | `IRRd -- version 4.5.3 (rpsld <version>)` | Clients detect IRRd 4 by the prefix (bgpq4 decides on `!a` by it) and IRRToolSet needs the word "version"; the parenthesis says what answers. |

Object text is served as the registry published it, not re-rendered as
IRRd renders it (attribute names lower-cased, values padded to column 16,
lists rejoined with commas): golden cases of kind `objects` are compared
after `irrdoracle.Normalize` applies IRRd's rewrites to both sides.

Answers IRRd gives in hash or database order (`!g`, `!6`, `!a`, `!r …,o`,
multi-object answers) are sorted by `rpsld`; those cases are compared as
multisets.
