# Engine differential — input snapshot

This directory holds the in-memory IRR snapshot that feeds the bgpq4
differential test in `resolve/`. It is synthetic, not anonymized real data:
every ASN is in the documentation ranges (`AS64500`–`AS64511`,
`AS65000`+) and every prefix is from `192.0.2.0/24` (TEST-NET-1),
`198.51.100.0/24` (TEST-NET-2), `203.0.113.0/24` (TEST-NET-3), or
`2001:db8::/32`. There are no live registry handles.

The snapshot is small on purpose. The point is to be readable: a regression
should be diagnosable by reading the input and the golden output side-by-side,
not by re-running an opaque fixture. The bgpq4 differential against a
production IRR (gated on `RPSL_BGPQ4_SERVER` / `RPSL_BGPQ4_SET`) is the live
counterpart.

## Files

| File | Contents |
| --- | --- |
| `as-sets.txt` | `as-set` objects with direct and nested membership, plus a deliberate cycle. |
| `route-sets.txt` | `route-set` objects with prefix-range members and nested set references. |
| `routes.txt` | `route` / `route6` objects providing the origin → prefix mapping the engine joins on. |

## Regenerating the golden output

Golden expansions live under `../golden/` and are committed hand-curated —
there is no `-update` flag. The intended workflow when editing this snapshot
is:

1. Edit the synthetic objects under `testdata/snapshot/`.
2. Run `go test -run TestGoldenExpansion ./resolve` — the test will fail with
   a diff showing the engine's new output.
3. If the new output is the *expected* answer, copy it into the corresponding
   golden file under `../golden/` (preserving the leading `#`-comment header
   that documents what set is being expanded).
4. Cross-check against `bgpq4` if it's a non-trivial change: that is the
   reference the goldens were originally captured from.

Then re-run the test — it must pass on the next attempt.
