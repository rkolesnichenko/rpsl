# rpslconf for IRRToolSet users

`rpslconf` is IRRToolSet's `RtConfig` and `peval` on the rpsl engine: policy
evaluated straight from IRR data — imports, exports, defaults — for a session,
a peer, or a bare filter, with the engine's set-expansion, range operators and
limits behind it. This release ships peval mode only: a filter evaluated to
its normal form, the same job IRRToolSet's `peval` does. Template mode, which
reads `RtConfig`'s `@RtConfig` command language and writes router
configuration, arrives in v0.22.0 (see the bottom of this page).

```sh
rpslconf -h whois.radb.net -e 'AS-EXAMPLE AND NOT {192.0.2.0/24}'
```

## Install

With a Go toolchain:

```sh
go install github.com/rkolesnichenko/rpsl/resolve/cmd/rpslconf@latest
```

Static release binaries, as `rpslq` has, arrive with the config printers in
v0.22.0.

## peval mode

`-e '<filter>'` evaluates an RPSL filter — the same grammar `import:`,
`export:` and `filter-set` values use (RFC 2622 §5.4, RFC 4012 §2.5's `afi`
prefix) — and prints its *normal form*: disjunctive normal form, with
prefix lists folded and everything else (AS-path regexps, community tests)
kept as written. `-peer AS<n>` binds `PeerAS` and any `AS1:AS-CUST:PeerAS`
template in the filter to that AS, for filters that name the peer rather
than a fixed AS; without `-peer`, a filter that uses `PeerAS` fails.

A leading `afi <list>` clause, exactly as `mp-import:`/`mp-export:` write it,
selects the address family the expansion runs in (`afi ipv6.unicast
AS-EXAMPLE`); a filter with no `afi` clause is evaluated for IPv4, as
IRRToolSet's `peval` reads one. A *SAFI* in the list does not narrow anything
— RPSL has no way to say a set member is multicast-only — so `ipv4.multicast`
means the same as `ipv4.unicast` here.

The output is `NormalFilter.String()`: one line of RPSL that
`policy.ParseFilter` reads back to a filter matching the same routes.
`NOT ANY` means the filter matches nothing.

Against RADB, an as-set's IPv6 routes (illustrative — the actual prefixes are
whatever AS-HURRICANE's members announce today):

```sh
$ rpslconf -h whois.radb.net -e 'afi ipv6.unicast AS-HURRICANE'
{2001:470::/32, 2400:8901::/32, ...}
```

A filter naming the peer, and a missing set:

```sh
$ rpslconf -h whois.radb.net -e 'PeerAS' -peer AS64500
{198.51.100.0/24, ...}

$ rpslconf -h whois.radb.net -e 'AS-DOES-NOT-EXIST'
NOT ANY
```

(The last case is a warning, not an error: a missing set expands to nothing,
so the filter — correctly — matches nothing. `rpslconf` also warns on stderr
for every set a filter named that it could not find.)

## Differences from IRRToolSet's `peval`

A throwaway spike (spec §3) ran IRRToolSet 5.1.3's `peval` against the same
IRR data and found it wrong in several places. `rpslconf` does not reproduce
these; each is a pinned divergence, not an oversight:

- **NOT over an AS-derived term.** `AS-FOO AND NOT AS10` and `NOT AS10` both
  print `NOT ANY` from IRRToolSet's `peval` — it drops the term instead of
  computing the difference. `rpslconf` computes AS-FOO's routes less AS10's,
  as RFC 2622 defines NOT (design divergence D1).
- **A range operator on a route-set member it cannot resolve.**
  IRRToolSet's `peval` substitutes `0.0.0.0/0` — hijack-relevant, since a
  filter meant to exclude specific prefixes instead admits everything.
  `rpslconf` expands the member's real routes under the operator, or reports
  it missing (D2).
- **IPv6 ranges.** IRRToolSet's `peval` enumerates an IPv6 `^+`/`^-` range
  (and a v6 filter-set) prefix by prefix, without a cap — in effect,
  forever, for anything wider than a few bits. `rpslconf` keeps a range as a
  range (D3).
- **Exit status.** IRRToolSet's `peval` exits 0 even after "no object found
  for AS1" — a script cannot tell success from failure by the exit code.
  `rpslconf` exits non-zero on any evaluation error (D9).
- **Output that reads back.** IRRToolSet's `peval` prints AS ranges as
  `AS2-AS3` and an unbound `PeerAS` as `AS4294967295`, neither of which RPSL
  or this library's own parser accepts. `NormalFilter.String()` always
  parses back with `policy.ParseFilter` (D10).
- **Regexps and community tests are kept, not dropped.** Where a term has no
  finite answer in prefixes, `rpslconf` keeps it symbolic in the normal
  form (`<^ AS1 .* $>`, a community test) rather than silently leaving it
  out of the printed filter — dropping it would make the filter look more
  permissive, or more restrictive, than it is.

Each of D1–D10 is pinned by a test and listed, with the input that shows
it, in
[`resolve/testdata/rtconfig/divergences.md`](../resolve/testdata/rtconfig/divergences.md).
`TestPevalMatchesIRRToolSet` (`resolve/peval_irrtoolset_test.go`) runs
IRRToolSet's `peval` itself against random filters and compares it with
`NormalizeFilter`, but only on the shapes IRRToolSet gets right — prefix
lists, bare AS numbers, AND, OR, and NOT over prefix lists, all IPv4 — since
IRRToolSet substitutes `0.0.0.0/0` for any set member (not only an
operator-qualified one) it cannot resolve, which would fail the comparison
for reasons that have nothing to do with `rpslconf`. See that file for the
narrower `pevalSafe` allow-list and why.

## Flags

Flags use IRRToolSet's single-dash style, read with Go's `flag` package
(which also accepts a double dash):

| Flag | Meaning |
| --- | --- |
| `-h` | host (default `whois.radb.net`) |
| `-p` | port (default 43) |
| `-s` | sources |
| `-whois` | query over whois instead of IRRd |
| `-dump FILE` | read a dump instead of a server; repeatable |
| `-e FILTER` | peval mode: print the filter's normal form |
| `-peer AS` | the AS `PeerAS` denotes |
| `-timeout` | give up after this long (default 60s) |

Exit codes: 0 success, 1 an evaluation error (a filter that failed to
normalize, a limit, `PeerAS` with no `-peer`), 2 a command line `rpslconf`
cannot use (no `-e`, an unparseable `-peer`, a bad flag).

## Coming in v0.22.0

Template mode: reading `RtConfig`'s `@RtConfig` command language from stdin
and writing router configuration for Cisco IOS/IOS-XE, Junos, IOS-XR and
BIRD 2 — an aut-num's import/export/default policy for a session, rendered
as a route-map/policy-statement/route-policy/filter, held to IRRToolSet's
own `rtconfig` on the shapes it renders correctly. See
[the design spec](superpowers/specs/2026-09-29-policy-evaluation-rtconfig-design.md)
§7–§9 for the printers, the capability table per vendor, and the test plan.
