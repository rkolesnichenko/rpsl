# rpslq for bgpq4 users

`rpslq` writes router filters from IRR data — prefix lists, route-filters,
as-path lists, AS sets — with bgpq4's command line and bgpq4's output, line for
line, on the rpsl engine. If you run bgpq4 today, your command lines work
unchanged:

```sh
rpslq -h whois.radb.net -S RADB,RIPE -6Ab AS-EXAMPLE    # BIRD, IPv6, aggregated
rpslq -h whois.radb.net -JEA -l POLICY/TERM AS-EXAMPLE  # Junos route-filter
rpslq -h whois.radb.net -f 65000 AS-EXAMPLE             # Cisco as-path list
rpslq -h whois.radb.net AS-EXAMPLE EXCEPT AS-BAD AS666  # leaving some out
```

## Install

Download the archive for your platform from the
[latest release](https://github.com/rkolesnichenko/rpsl/releases/latest) —
Linux and macOS on amd64 and arm64, Windows on amd64 — and check it against
the release's `SHA256SUMS`:

```sh
curl -LO https://github.com/rkolesnichenko/rpsl/releases/download/v0.19.0/rpslq_v0.19.0_linux_amd64.tar.gz
curl -LO https://github.com/rkolesnichenko/rpsl/releases/download/v0.19.0/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS      # macOS: shasum -a 256 --ignore-missing -c SHA256SUMS
tar -xzf rpslq_v0.19.0_linux_amd64.tar.gz && ./rpslq -v
```

The binaries are static (no cgo), built from the released module with
`-trimpath`; `go version -m rpslq` shows the exact module versions inside. On
macOS a binary downloaded with a browser is quarantined; clear it with
`xattr -d com.apple.quarantine rpslq`. With a Go toolchain you can build it
instead:

```sh
go install github.com/rkolesnichenko/rpsl/resolve/cmd/rpslq@latest
```

## What is the same

- **The command line.** Every option bgpq4 has, read as bgpq4 reads them
  (bundled flags like `-6Ab`, `-lNAME`), with bgpq4's defaults — including the
  server (`rr.ntt.net`) and `-S` from `$IRRD_SOURCES`.
- **The output, byte for byte**, for every vendor — Cisco IOS and IOS XR,
  Junos, Arista, OpenBGPD, BIRD, JSON, Nokia SR OS (classic and MD-CLI) and SR
  Linux, MikroTik v6 and v7, Huawei and XPL, `-F` formats — and every kind of
  list, with aggregation (`-A`, a port of bgpq4's own algorithm) and the
  shapes (`-R`, `-r`, `-m`, `-s`, `-W`, `-w`, …).
- **What bgpq4 refuses, rpslq refuses**, with an exit code of 2 for a command
  line that cannot be served and 1 for an expansion that failed.

The test suite runs the bgpq4 1.16 binary against the same IRRd-like server as
rpslq, over the full vendor/kind/shape matrix and thousands of random IRRs, and
requires identical text; live against RADB the two agree on sets as large as
AS-HURRICANE.

## What rpslq adds

rpslq's own options are long, so they never clash with bgpq4's:

- **`--rpki vrps.json`** — RPKI-aware, as IRRd 4 is (RADB runs it so): the
  routes the VRPs make RPKI invalid are left out, from any source, and a
  `--dump` gains each VRP as a route of the registry `RPKI`, as RADB serves
  them. With the registries' own dumps and a VRP export (rpki-client,
  Routinator), rpslq writes what bgpq4 gets from RADB, offline; `--slurm`
  amends the VRPs (RFC 8416).
- **`--dump file`** — expand from IRR dumps (gzip or plain, repeatable) with no
  server at all; `-S` chooses the registries in them.
- **`--whois`** — query a plain whois server (the RIPE Database) instead of an
  IRRd.
- **`SOURCE::OBJECT`** (`RIPE::AS-FOO`) as bgpq4 means it — the object in that
  registry, what it reaches in the default sources — where bgpq4 itself slips
  (see below); `RIPE::AS65001` takes that AS's routes from RIPE alone.
- **`-d`** — trace every question asked of the source, its answer and how long
  it took, to stderr.
- **`--ranges`** — write RPSL's ranges as they are (`10.0.0.0/8^+`) rather than
  every prefix they hold; **`-P`** writes RPSL notation, one entry per line.
- **`--timeout d`** — give up after d (default 5m).

## Where they differ, on purpose

- **Who expands as-sets.** Plain `bgpq4` asks the IRRd server to expand an
  as-set (`!a`); rpslq expands it with its own engine, as `bgpq4 -L` does,
  under RFC 2622's rules and with every limit checked. `--server-expand` gives
  bgpq4's default: one query, the server's answer.
- **Nesting deeper than `-L`** fails rather than silently leaving the deeper
  sets out, as bgpq4 does.
- **RPSL where bgpq4 slips**: a single-length range `^26` (bgpq4 bug
  [#135](https://github.com/bgp/bgpq4/issues/135)), a range operator on a set
  or AS member, `EXCEPT` inside route-sets, a route-set listed in an as-set (not
  followed, per RFC 2622 §5.1), `AS-ANY` (refused), `-m 32`, and corners of
  `SOURCE::`.

Each difference is pinned by a test against the bgpq4 binary and listed, with
examples, in [`resolve/testdata/bgpq4/divergences.md`](../resolve/testdata/bgpq4/divergences.md).
Anything else that differs is a bug: please
[report it](https://github.com/rkolesnichenko/rpsl/issues) with both command
lines and outputs.
