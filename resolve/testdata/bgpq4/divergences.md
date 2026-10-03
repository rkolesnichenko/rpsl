# Known divergences from bgpq4

`TestBgpq4Differential` expands random IRRs with the engine and with bgpq4
(1.16), served by the in-process IRRd in `internal/irrtest`, and requires the
same AS numbers and prefixes. It leaves out the cases below, where the two
knowingly differ. `TestBgpq4KnownDivergences` pins each one — the engine's
answer and bgpq4's — so a change on either side fails a test instead of
passing unnoticed.

| Case | Example | Engine | bgpq4 | Why |
| --- | --- | --- | --- | --- |
| `single-length-range` | `192.0.2.0/24^26` | the four /26s | nothing | A bgpq4 bug, reported as [bgp/bgpq4#135](https://github.com/bgp/bgpq4/issues/135): `sx_prefix_range_parse` leaves the upper bound at 0 when `^n` has no `-m`, so the range is empty. RFC 2622 §2 defines `^n` as the length-n more-specifics. `^26-26` works in both. |
| `operator-on-set-member` | `RS-INNER^25` | RS-INNER's prefixes under `^25` | nothing | RFC 2622 §5.2 allows a range operator on a set member. IRRd looks `RS-INNER^25` up as a set name, finds none and drops it from `!i…,1` (IRRd 4.5.3, recorded in `resolve/testdata/irrd/golden/plain.txt`, case `i1/RS-FOO`), so bgpq4 gets nothing for it. |
| `operator-on-as-member` | `AS65001^25` in a route-set | AS65001's routes under `^25` | nothing | Same as above, for an AS number (RFC 2622 §5.3). |
| `route-set-in-as-set` | `as-set: AS-X` listing `RS-Y` | RS-Y is not followed | RS-Y's AS members are added | RFC 2622 §5.1: an as-set lists AS numbers and as-sets only. Following a route-set would let it add ASes to the as-set. |
| `as-any` | `AS-ANY` as a member | `AnySetError` | ignored (no such set) | `AS-ANY` denotes every AS; the engine refuses to expand it rather than quietly drop it (see the design doc, §8.3). |
| `src-members` | AS-SRC lists AS-DUP and has `src-members: RADB::AS-DUP`; RIPE and RADB both hold AS-DUP | AS64602 (RADB's, as src-members: asks) | AS64601 (RIPE's, by -S precedence) | Neither bgpq4 nor IRRd implements draft-ietf-grow-rpsl-registry-scoped-members; the engine does. rpslq over IRRd agrees with bgpq4 unless given --src-members. |

## Agreements worth noting

- **A prefix range starting below its prefix length** (`2001::/23^16-48`,
  found in RIPE's `fltr-iana-allocated-v6`): all three refuse it. bgpq4 reports
  `Invalid prefix-range … min 16 < masklen 23` and drops the member; IRRd
  rejects the object ("operator start (16) must be equal to or longer than
  prefix length (23)"); the engine leaves the member out with an Error
  (`TestBgpq4RejectsRangeBelowPrefixLength`). Only the RIPE Database accepts it.
- **Host bits** (`192.0.2.1/24`): both read the network, `192.0.2.0/24`.
- **A member without a length** (`192.0.2.1`, in ARIN's `rs-HCHBNET`): all
  three read the host prefix. IRRd stores it as `192.0.2.1/32` (so does
  `irrtest`), and bgpq4 reads a bare address as a /32 or /128 itself; the random
  IRRs write some host-prefix members so.
- **Indirect members**: IRRd folds `mbrs-by-ref` members into `!i`; the engine
  resolves them itself with the same rules (maintainer and same source), and the
  two agree on every random IRR.

## rpslq

`rpslq` writes bgpq4's text for bgpq4's command line (`TestRpslqMatchesBgpq4`,
`TestRpslqVendorsMatchBgpq4`, `TestRpslqExceptMatchesBgpq4`), except as above
and below. `TestRpslqKnownDivergences` pins each case.

| Case | Example | rpslq | bgpq4 | Why |
| --- | --- | --- | --- | --- |
| `except-in-route-set` | `RS-TOP EXCEPT RS-BAD AS-BAD` | RS-BAD and AS-BAD left out | both kept | bgpq4's stoplist applies only while it recurses through as-sets; route-sets it has the server expand (`!i…,1`). The engine leaves an excluded set out wherever it meets it. |
| `depth-limit` | `-L 2` over AS-TOP → AS-MID → AS-LOW | fails: the sets nest deeper than `-L 2` allows | AS-LOW left out, silently | Both count the named set as the first level. The engine never truncates a result silently (design §8.3), so rpslq refuses where bgpq4 drops; for the same reason it refuses `-L 1`, with which bgpq4 leaves every nested set out. `TestRpslqDepthLimit` pins it. |
| `source-with-depth` | `-L 8 RIPE::AS-TOP` | RIPE's AS-TOP plus, from its unscoped self-reference, RADB's AS-TOP | the default sources' AS-TOP | With `-L` or EXCEPT, bgpq4 takes its client-side path for the named sets, which sends no `!s` for them: the `SOURCE::` is ignored. rpslq still honors it for the top; its self-reference resolves like any other unscoped set. |
| `source-cycle` | `-S RADB RIPE::AS-TOP`, RIPE's AS-TOP listing AS-TOP | RIPE's AS-TOP plus, from its unscoped self-reference, RADB's AS-TOP | RIPE's AS-TOP alone | IRRd's `!i` removes the set's own name from its answer (`members_for_set` in `irrd/server/query_resolver.py`), so bgpq4, asking `!sRIPE` then `!iAS-TOP`, never sees the self-reference. The engine's scope never cascades: the unscoped self-reference is a node of its own, resolved by `-S` like any other unscoped set, and `irrd.Source` restores it from the object on a scoped lookup. `TestRpslqSourcePrefixMatchesBgpq4` skips sets that list themselves for this reason. |
| `source-route-set` | `RIPE::AS1 RS-X`, RS-X listing RS-Y | RS-X expanded whole | RS-X's prefix members only | Once any object has a `SOURCE::`, bgpq4 asks for every route-set with `!i` rather than `!i…,1`, and reads only the prefixes in the answer (nested sets and AS numbers are "unable to parse"). |
| `source-as-number` | `RIPE::AS65003` | the routes AS65003 has in RIPE | nothing | bgpq4 reads the object as an AS number, `RIPE::AS65003`, which it cannot parse, and drops it. |
| `max-length-full` | `-m 32 10.0.0.0/30^+` | every prefix of the range | `10.0.0.0/30` alone | bgpq4 stores `-m` only when it is shorter than an address, and otherwise reads a range's upper bound as 0 — the same slip as `single-length-range`. `-m 32` should change nothing. |

rpslq also refuses some command lines bgpq4 accepts and makes nothing of: an
AS list or as-path filter over a route-set or a prefix (bgpq4 ignores them), a
`-F` template with an unknown directive or a lone `%` or `\` at its end (bgpq4
prints part of each line, or reads past the template), and a `SOURCE::` on a
prefix or after EXCEPT, or with `--server-expand` (IRRd's `!a` would keep the
nested sets in that registry too). `TestRpslqSourceDivergences` pins the
`source-*` cases; `TestRpslqSourcePrefixMatchesBgpq4` holds the rest of
`SOURCE::` to bgpq4.
