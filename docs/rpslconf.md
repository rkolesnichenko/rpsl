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
AS-EXAMPLE`); a filter with no `afi` clause is evaluated for both families,
IPv4 and IPv6 — unlike IRRToolSet's `peval`, which reads one as
`ipv4.unicast`. Write `afi ipv4.unicast` for IRRToolSet's reading. The list is
read greedily: `afi ipv4 any` is IPv4 and the filter `ANY`, but in
`afi ipv4 any AND AS1` the `any` is a family and the filter `AND AS1` an
error; write `afi ipv4 (ANY AND AS1)`. A *SAFI* in the list does not narrow anything
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
- **Exit status.** IRRToolSet exits 0 even after it fails — rtconfig after
  "no object for AS1" (D9) — so a script cannot tell success from failure by
  the exit code. `rpslconf -e` exits 1 on an error (a filter that does not
  parse, an unbound `PeerAS`, a limit, a server it cannot reach) and 2 on a
  bad command line; a set it cannot find is a warning on stderr, since the
  set denotes nothing. D9 itself, about template mode, arrives with it.
- **Output that reads back.** IRRToolSet's `peval` prints AS ranges as
  `AS2-AS3` and an unbound `PeerAS` as `AS4294967295`, neither of which RPSL
  or this library's own parser accepts. `NormalFilter.String()` always
  parses back with `policy.ParseFilter` (D10).
- **Regexps and community tests are kept, not dropped.** Where a term has no
  finite answer in prefixes, `rpslconf` keeps it symbolic in the normal
  form (`<^ AS1 .* $>`, a community test) rather than silently leaving it
  out of the printed filter — dropping it would make the filter look more
  permissive, or more restrictive, than it is.

Each of D1–D10 is listed, with the input that shows it, in
[`resolve/testdata/rtconfig/divergences.md`](../resolve/testdata/rtconfig/divergences.md).
No test yet runs IRRToolSet to show one of them: D1 and D2 are kept out of
the differential below (its `pevalSafe` allow-list refuses the shapes that
trigger them) rather than compared. `rpslconf`'s own side is held for some:
D4 by `TestImportIPv6SessionIgnoresLegacyImport` (`resolve/peval`), and D10
by the model tests, which parse every normal form back. D3 and D5–D9 have no
test; D5–D9 belong to template mode.
`TestPevalMatchesIRRToolSet` (`resolve/peval_irrtoolset_test.go`) runs
IRRToolSet's `peval` itself against random filters and compares it with
`NormalizeFilter`, but only on the shapes IRRToolSet gets right — prefix
lists, bare AS numbers, AND, OR, and NOT over prefix lists, all IPv4 — since
IRRToolSet substitutes `0.0.0.0/0` for any set member (not only an
operator-qualified one) it cannot resolve, which would fail the comparison
for reasons that have nothing to do with `rpslconf`. See that file for the
narrower `pevalSafe` allow-list and why.

## What a vendor cannot say

A printer never approximates: a construct a vendor's configuration cannot express is refused. The error wraps `rtconfig.ErrUnsupported` and names the vendor, the term, and one of these causes (`rtconfig.Cause*`). When a vendor refuses a policy, it writes nothing for it.

| Cause | Meaning |
|---|---|
| `a via clause (import-via:, export-via:)` | route-server policies (draft-ietf-grow-rpsl-via) are evaluated by peval but rendered by no printer yet |
| `a SAFI other than unicast` | a multicast session |
| `two AS-path regexps that must both match` | IOS and Junos OR the as-path lists of one entry or term |
| `a negated AS-path class [^…]` | no dialect has a negated AS class |
| `same-AS repetition (~*, ~+, ~{m,n}) over more than one AS` | `~*` over a set or class is not a regular language over paths |
| `an AS-path regexp shape the vendor's path syntax lacks` | an inner anchor for Junos or BIRD, alternation or repetition for BIRD, a count over 32 for IOS, a class of more than 1024 ASes |
| `a community that is neither a:b nor a well-known one` | large and extended communities are not typed yet |
| `an exact community match (community == {…})` | where the vendor has no exact match, or cannot combine one with other tests |
| `an action other than pref, med, community, aspath.prepend and next-hop` | another RP-attribute |
| `an action value the vendor cannot set` | `med = igp_cost` or `next-hop = self` where the vendor has none, a pref or med that is not a number, `community = {}` on Junos |
| `a pref above MaxPreference` | pref N becomes local-preference MaxPreference−N, which would be negative |
| `a default: the vendor has no configuration for` | every vendor but IOS; on IOS, a default with actions, or with networks other than exact IPv4 prefixes (D6) |
| `networks the vendor has no configuration for` | Junos and BIRD |
| `a filter that is not a single list of that kind` | access_list of a filter with a regexp or community test, or of several conjuncts |

## Terms peval cannot decide

A term that might cover the session, but can't be decided, is reported as a warning. It is never guessed. The reason is one of these (`peval.Why*`); the last two are followed by the protocol's name.

| Reason | Meaning |
|---|---|
| `peer router not given` | the peering names the peer's router, and the session does not |
| `local router not given` | the peering names a local router (`at …`), and the session does not |
| `peering regexp` | a peering written as an AS-path regexp names no set of sessions |
| `unknown peering` | a peering of a kind this version does not know |
| `PeerAS beyond a via peering names no single AS` | an import-via:/export-via: whose remote peering is not one AS binds PeerAS to nothing |
| `protocol` | a policy for routes of another protocol (RFC 2622 §6.4) |
| `into` | a policy for routes into another protocol |

## Capabilities by vendor

Generated from `rtconfig.Capabilities()`; `TestRpslconfDocs` holds this table to the code.

<!-- capabilities -->
| Feature | cisco | junos | ciscoxr | bird | Refused with |
|---|---|---|---|---|---|
| two AS-path regexps in one clause, both to match | no | no | yes | yes | `two AS-path regexps that must both match` |
| alternation, or repetition of an AS, in an AS-path regexp | yes | yes | yes | no | `an AS-path regexp shape the vendor's path syntax lacks` |
| ^ or $ inside an AS-path regexp | yes | no | yes | no | `an AS-path regexp shape the vendor's path syntax lacks` |
| a negated AS-path class [^…] | no | no | no | no | `a negated AS-path class [^…]` |
| community == {…} as a clause's only community test | yes | no | no | yes | `an exact community match (community == {…})` |
| community == {…} negated, or beside other community tests | no | no | no | yes | `an exact community match (community == {…})` |
| med = igp_cost | yes | yes | yes | no | `an action value the vendor cannot set` |
| next-hop = self | no | yes | yes | no | `an action value the vendor cannot set` |
| default: (rtconfig's default command) | yes | no | no | no | `a default: the vendor has no configuration for` |
| networks, v6networks | yes | no | yes | no | `networks the vendor has no configuration for` |
| import-via:, export-via: | no | no | no | no | `a via clause (import-via:, export-via:)` |
| a multicast SAFI | no | no | no | no | `a SAFI other than unicast` |
<!-- /capabilities -->

## Flags

Flags use IRRToolSet's single-dash style, read with Go's `flag` package
(which also accepts a double dash):

| Flag | Meaning |
| --- | --- |
| `-h` | host, or `host:port` (default `whois.radb.net`) |
| `-p` | port, when `-h` names none (default 43) |
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
