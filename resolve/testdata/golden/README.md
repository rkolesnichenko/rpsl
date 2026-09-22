# Engine differential — golden expansions

This directory holds the expected output of `resolve.Expander.ExpandAS` and
`ExpandPrefixes` against the synthetic snapshot in `../snapshot/`. Files are
plain text, one ASN or prefix per line, sorted; lines starting with `#` are
comments and ignored by `readGolden`.

`TestGoldenExpansion` (`resolve/diff_golden_test.go`) reads these files and
fails if the engine's output drifts — that drift is either a bug to root-cause
or an intentional change that needs to be reflected here.

| Files | What they represent |
| --- | --- |
| `<set>.asn` | The AS numbers of an as-set (`ExpandAS`). |
| `<set>.v4`, `<set>.v6` | The IPv4 or IPv6 prefixes of a set (`ExpandPrefixes`). |

`TestGoldenExpansion` lists the basket: nested and cyclic as-sets, the same
as-set written as a folded list, indirect members that are honored and
rejected (wrong maintainer, another source, `mbrs-by-ref: ANY`), a set defined
in two sources, missing nested sets, and route-sets with range operators,
IPv6 `mp-members` and nested route-sets and as-sets.

## Origin

Every golden is bgpq4's own output: `bgpq4` run on the snapshot served by the
in-process IRRd in `internal/irrtest`, with the command in each file's header.
`TestGoldensAreBgpq4Output` re-runs bgpq4 and fails if a golden no longer
matches it; it skips when bgpq4 is not installed (CI installs it). The snapshot
avoids the cases where the engine and bgpq4 knowingly differ
(`../bgpq4/divergences.md`).

## Updating

After editing the snapshot, regenerate the goldens from bgpq4 and review the
diff:

    go test -run TestGoldensAreBgpq4Output -update ./resolve

`TestGoldenExpansion` then checks the engine against them.
