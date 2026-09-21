# Engine differential — golden expansions

This directory holds the expected output of `resolve.Expander.ExpandAS` and
`ExpandPrefixes` against the synthetic snapshot in `../snapshot/`. Files are
plain text, one ASN or prefix per line, sorted; lines starting with `#` are
comments and ignored by `readGolden`.

`TestGoldenExpansion` (`resolve/diff_golden_test.go`) reads these files and
fails if the engine's output drifts — that drift is either a bug to root-cause
or an intentional change that needs to be reflected here.

| File | What it represents |
| --- | --- |
| `as-example.asn` | `Expander.ExpandAS(AS-EXAMPLE)` — transitive member ASNs. |
| `as-example.v4` | `Expander.ExpandPrefixes(AS-EXAMPLE)` with `AFI=AFIv4`. |
| `rs-example.v4` | `Expander.ExpandPrefixes(RS-EXAMPLE)` with `AFI=AFIv4`. |

## Origin

These are hand-checked expected expansions of the synthetic snapshot. bgpq4
cannot run against an offline snapshot, so they are not bgpq4 output; the header
comments record the equivalent `bgpq4` command (e.g. `bgpq4 -j -l x AS-EXAMPLE`)
for cross-checking the same sets against a live registry.

The optional live `bgpq4` differential (`diff_bgpq4_test.go`, gated on
`RPSL_BGPQ4_SERVER` / `RPSL_BGPQ4_SET`) checks the same property against a
live registry rather than against the offline goldens.

## Updating

See `../snapshot/README.md`. There is no `-update` flag — goldens are
hand-edited so the diff is reviewable.
