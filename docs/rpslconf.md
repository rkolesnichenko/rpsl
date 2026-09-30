# rpslconf for IRRToolSet users

`rpslconf` is IRRToolSet's `RtConfig` and `peval` on the rpsl engine: policy
evaluated straight from IRR data — imports, exports, defaults — for a
session, a peer, or a bare filter, with the engine's set-expansion, range
operators and limits behind it. Both of IRRToolSet's modes ship. **Template
mode** (the default) reads an `@RtConfig` template from stdin and writes
router configuration — Cisco IOS/IOS-XE, Junos, Cisco IOS-XR or BIRD 2 — for
the sessions and lists it names. **peval mode** (`-e`) evaluates one bare
filter to its normal form, without a template.

```sh
rpslconf -h whois.radb.net -config junos < router.tmpl > router.conf
rpslconf -h whois.radb.net -e 'AS-EXAMPLE AND NOT {192.0.2.0/24}'
```

## Install

With a Go toolchain:

```sh
go install github.com/rkolesnichenko/rpsl/resolve/cmd/rpslconf@latest
```

Static release binaries, as `rpslq` has, ship alongside `rpslq`'s: each
[release](https://github.com/rkolesnichenko/rpsl/releases/latest) carries
`rpslconf` for Linux and macOS (amd64, arm64) and Windows (amd64), with
`SHA256SUMS`. `rpslconf -v` prints the binary's version.

## Template mode

Template mode (the default — no `-e`) reads an IRRToolSet-style `@RtConfig`
template from stdin, line by line, and copies it to stdout, with each
`@RtConfig` command replaced by the router configuration, list, or printed
value it asks for. Everything else — surrounding configuration, comments,
blank lines — is copied through byte for byte. A line is a command when it
starts with `@RtConfig` (in any case) followed by a space, a tab, or nothing;
anything else is copied as written. `-config` chooses the dialect: `cisco`
(the default), `junos`, `ciscoxr` or `bird`.

```sh
rpslconf -h whois.radb.net -config junos < router.tmpl > router.conf
```

### A worked example

Given this IRR data —

```
route: 10.2.0.0/16
origin: AS2
source: TEST

route: 10.2.128.0/17
origin: AS2
source: TEST

as-set: AS-FOO
members: AS10, AS11
source: TEST

aut-num: AS1
as-name: ONE
import: from AS2 action pref = 10; community.append(1:100); accept AS2 AND NOT {10.2.128.0/17}
import: from AS2 accept ANY AND NOT community(2:666) AND <^AS2 AS-FOO*$>
source: TEST
```

— and this template, naming AS1's own router (10.0.0.1) and its session with
AS2 (10.0.0.2):

```
@RtConfig import AS1 10.0.0.1 AS2 10.0.0.2
```

`-config cisco` writes:

```
!
no route-map MyMap_2_1
!
no ip prefix-list pl100
ip prefix-list pl100 seq 5 permit 10.2.0.0/16
!
route-map MyMap_2_1 permit 1
 match ip address prefix-list pl100
 set local-preference 990
 set community 1:100 additive
!
no ip as-path access-list 100
ip as-path access-list 100 permit ^_2(_(10|11))*$
!
no ip community-list standard cl100
ip community-list standard cl100 deny 2:666
ip community-list standard cl100 permit internet
!
route-map MyMap_2_1 permit 2
 match as-path 100
 match community cl100
!
route-map MyMap_2_1 deny 3
!
router bgp 1
 neighbor 10.0.0.2 remote-as 2
 neighbor 10.0.0.2 route-map MyMap_2_1 in
!
```

`-config junos` writes:

```
policy-options {
    policy-statement policy_2_1-sub-1 {
        term permit-1 {
            from {
                route-filter 10.2.0.0/16 exact;
            }
            then accept;
        }
        term rest {
            then reject;
        }
    }
    community policy_2_1-comm-1 members [ 1:100 ];
    as-path policy_2_1-path-1 "2 (10|11)*";
    community policy_2_1-comm-2 members [ 2:666 ];
    policy-statement policy_2_1-sub-2 {
        term not-comm-1 {
            from community policy_2_1-comm-2;
            then reject;
        }
        term rest {
            then accept;
        }
    }
    policy-statement policy_2_1 {
        term entry-1 {
            from {
                policy policy_2_1-sub-1;
            }
            then {
                local-preference 990;
                community add policy_2_1-comm-1;
                accept;
            }
        }
        term entry-2 {
            from {
                policy policy_2_1-sub-2;
                as-path policy_2_1-path-1;
            }
            then {
                accept;
            }
        }
        term reject {
            then reject;
        }
    }
}
protocols {
    bgp {
        group peer-10.0.0.2 {
            type external;
            peer-as 2;
            neighbor 10.0.0.2 {
                import policy_2_1;
                family inet {
                    unicast;
                }
            }
        }
    }
}
```

`-config ciscoxr` writes:

```
!
prefix-set pl100-permit
  10.2.0.0/16
end-set
!
as-path-set as100
  ios-regex '^_2(_(10|11))*$'
end-set
!
community-set cs100
  2:666
end-set
!
route-policy MyMap_2_1
  if destination in pl100-permit then
    set local-preference 990
    set community (1:100) additive
    done
  endif
  if as-path in as100 and not community matches-every cs100 then
    done
  endif
  drop
end-policy
!
router bgp 1
 neighbor 10.0.0.2
  remote-as 2
  address-family ipv4 unicast
   route-policy MyMap_2_1 in
  !
 !
!
```

BIRD 2 cannot repeat a set within an AS-path regexp (`AS-FOO*`; see
Capabilities, below), so its second `import:` line reads
`accept ANY AND NOT community(2:666) AND <^AS2 .* AS-FOO$>` instead — a
wildcard segment followed by one member of AS-FOO, which every vendor here
can express. `-config bird` then writes:

```
filter MyMap_2_1 {
  if (net ~ [ 10.2.0.0/16 ]) then {
    bgp_local_pref = 990;
    bgp_community.add((1,100));
    accept;
  }
  if (bgp_path ~ [= 2 * [10, 11] =]) && !((2,666) ~ bgp_community) then {
    accept;
  }
  reject;
}
protocol bgp peer_10_0_0_2 {
  local 10.0.0.1 as 1;
  neighbor 10.0.0.2 as 2;
  ipv4 {
    import filter MyMap_2_1;
    export none;
  };
}
```

Both examples come straight from `resolve/rtconfig`'s own tests
(`TestIOSImportGolden`, `TestXRImportGolden`, `TestBIRDImportGolden`, and the
Junos writer over the same fixture as the other three) — `go test ./rtconfig`
holds this page's prose to nothing, but the printers themselves are held to
these exact bytes.

## Commands

| Command | Arguments | Writes |
| --- | --- | --- |
| `import AS rtr AS rtr` | local AS, local router, peer AS, peer router | the import policy `peval` evaluates for that session, attached to the neighbour |
| `export AS rtr AS rtr` | as `import` | the export policy, attached the same way |
| `default AS AS` | local AS, peer AS | the default routes for that pair (`default:` has no peering, so no router) |
| `set knob = value` | one of the knobs below | nothing directly; changes a naming or numbering knob for the commands that follow |
| `access_list filter <filter>` | an RPSL (mp-)filter | a prefix list / access-list / prefix-set for the filter's prefix ranges — one conjunct, prefix ranges and negated ranges only |
| `aspath_access_list filter <filter>` | a filter that is one AS-path regexp, or `NOT` one | an AS-path list/set for it |
| `printprefixes "format" filter <filter>` | a print format, a filter | every prefix the filter's ranges hold, one at a time, through the format |
| `printprefixranges "format" filter <filter>` | as `printprefixes` | every range itself (not each prefix it holds), through the format |
| `networks AS` | an AS number | route/network statements originating that AS's IPv4 routes |
| `v6networks AS` | an AS number | as `networks`, for IPv6 |

`prefix_acl_no`, `aspath_acl_no`, `community_acl_no` and
`cisco_access_list_no` (below) must be set before the first
`import`, `export`, `access_list` or `aspath_access_list` command: each of
those four writes a numbered list or map, and `rpslconf` refuses a numbering
knob set after one has already been written. `default`, `printprefixes`,
`printprefixranges`, `networks` and `v6networks` write nothing numbered, so
they never fix the numbering — a `set` of a numbering knob is still allowed
after any of them.

| Knob | Default | Sets |
| --- | --- | --- |
| `cisco_map_name` | `MyMap_%d_%d` | the route-map/route-policy name pattern (peer AS, then a count) |
| `junos_policy_name` | `policy_%d_%d` | the Junos policy-statement name pattern |
| `cisco_map_first_no` | 1 | the first route-map/route-policy entry's sequence number |
| `cisco_map_increment_by` | 1 | the step between entries |
| `prefix_acl_no` | 100 | the first prefix list/prefix-set number |
| `aspath_acl_no` | 100 | the first AS-path list/set number |
| `community_acl_no` | 100 | the first community list/set number |
| `cisco_access_list_no` | 100 | the first plain `access_list` number |
| `cisco_max_preference` | 1000 | pref *N* becomes local-preference *max−N*; a pref above it is refused (`CausePref`) |
| `sources` | the server's own precedence | the registries queried from here on; reopens the connection |

A `set` of `0` means the default, since `Naming`'s zero fields take
`DefaultNaming()`'s — the same rule `resolve/rtconfig.Generator.Names` follows
for a caller driving it directly.

`rpslconf` recognizes, and refuses, several more `@RtConfig` commands rather
than silently misrendering them: `printsuperprefixranges`,
`configureRouter`, `importGroup`, `exportGroup`, `importPeerGroup`,
`static2bgp`, `inbound_pkt_filter`, `outbound_pkt_filter`, `pkt_filter`.
`configureRouter` and `importGroup` are deferred because IRRToolSet's own
rendering of them is wrong (D7, D8 below) and there is no oracle yet to hold
a correct rendering to; the rest have no oracle either.

`printprefixes`/`printprefixranges`'s format is literal text with `%`
operators — `%p` the range's address, `%l` its prefix length, `%L` the
address size minus the length, `%n`/`%m` the range's low/high length window,
`%k`/`%K` the mask and its inverse, `%%` a literal `%` — and `\` escapes
(`\n`, `\t`, `\\`). Both commands' filter must normalize to at most one
conjunct of prefix ranges, with no AS-path regexp, community test or `NOT` —
even a negated range; a filter matching nothing prints nothing, and anything
else is refused.

## Sessions and BIRD

Cisco IOS, Junos and IOS-XR each attach a policy to its neighbour as they
write it: an `import`/`export` command's output already includes the
`neighbor`/`group`/`route-policy` clause naming the map just written. BIRD 2
cannot: one `protocol bgp` block names both a neighbour's import and export
filters, so it cannot be written until both are known. `WriteImport` and
`WriteExport` only record the attachment for BIRD; `WriteSessions` writes one
`protocol bgp NAME { … }` per neighbour, at the end of the output, once every
`import`/`export`/`default` command has run. Template mode calls it
automatically after the template is exhausted; a caller driving
`rtconfig.Generator` directly calls it last, once. For the other three
vendors `WriteSessions` writes nothing — each has already written its own
attachment.

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
| `-config` | template mode: the configuration `format` — `cisco` (default), `junos`, `ciscoxr` or `bird` |
| `-e FILTER` | peval mode: print the filter's normal form |
| `-peer AS` | peval mode: the AS `PeerAS` denotes |
| `-timeout` | give up after this long (default 60s) |
| `-v` | print rpslconf's version and exit |

`-peer` belongs to peval mode; giving it without `-e` is a command-line
error. Template mode takes no `-e`/`-peer`: a template names its own sessions
and AS numbers.

## Exit status

0 on success, in either mode. 1 on any error once the command line itself
parses: a filter that fails to parse or normalize, `PeerAS` with no `-peer`,
a limit or a timeout, a server `rpslconf` cannot reach, a malformed
`@RtConfig` line, a template's `import`/`export`/`default` naming an
aut-num that does not exist (D9, below), or a construct a vendor's printer
refuses (`*rtconfig.UnsupportedError`). 2 on the command line itself: an
unknown or malformed flag, an unexpected positional argument (the template
is always read from stdin, never named on the command line), an unknown
`-config` vendor, `-peer` given outside peval mode, or a `-peer` value that
is not an AS number. A term `peval` cannot decide, and a set a filter names
that is not found, are warnings on stderr rather than failures: neither
stops the rest of the template from running.

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
| `an action value the vendor cannot set` | `med = igp_cost` or `next-hop = self` where the vendor has none, a pref or med that is not a number, a next-hop address of the other family than the session's (an IPv4 next-hop on an IPv6 session, or the reverse), `community = {}` on Junos |
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

On a sample of RIPE's own import and export policies (opt-in,
`RPSL_REALDATA`; `TestRealDataPeval`), every evaluated session rendered
cleanly for all four vendors — no refusal, and no configuration `cfgsim`
could not read back. The table below is what an *unusual* policy meets, not
what real data hits often: no frequency is claimed for any row.

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

## Differences from IRRToolSet

A throwaway spike (design §3) ran IRRToolSet 5.1.3's `rtconfig` and `peval`
against the same IRR data and found them wrong in several places; writing
this release's plan found three more, and the rtconfig and peval
differentials (`resolve/rtconfig_irrtoolset_test.go`,
`resolve/peval_irrtoolset_test.go`) found four after that. `rpslconf` does
not reproduce any of them; each is a pinned divergence, not an oversight,
listed here in numeric order regardless of which mode it belongs to.

- **D1 — NOT over an AS-derived term.** `AS-FOO AND NOT AS10` and `NOT AS10`
  both print `NOT ANY` from IRRToolSet's `peval` — it drops the term instead
  of computing the difference. `rpslconf` computes AS-FOO's routes less
  AS10's, as RFC 2622 defines NOT.
- **D2 — a range operator on a route-set member it cannot resolve.**
  IRRToolSet's `peval` substitutes `0.0.0.0/0` — hijack-relevant, since a
  filter meant to exclude specific prefixes instead admits everything.
  `rpslconf` expands the member's real routes under the operator, or reports
  it missing.
- **D3 — IPv6 ranges.** IRRToolSet's `peval` enumerates an IPv6 `^+`/`^-`
  range (and a v6 filter-set) prefix by prefix, without a cap — in effect,
  forever, for anything wider than a few bits. `rpslconf` keeps a range as a
  range.
- **D4 — an IPv6-only mp-import: still gets an IPv4 entry.** For an aut-num
  whose import policy is IPv6-only, IRRToolSet's `rtconfig` writes an IPv4
  route-map entry with no match condition — permitting all IPv4 traffic by
  omission. `rpslconf` writes no IPv4 entry for such a session
  (`TestImportIPv6SessionIgnoresLegacyImport`, `resolve/peval`).
- **D5 — import-via:/export-via: are silently ignored.** IRRToolSet's
  `rtconfig` and `peval` both drop a route-server policy (`import-via:`,
  `export-via:`) as though the aut-num had none. `resolve/peval` evaluates
  it like any other policy; the printers, which do not yet render a via
  clause, refuse it explicitly (`a via clause (import-via:, export-via:)`)
  rather than silently omitting it.
- **D6 — default: is rendered incompletely, or not at all.** IRRToolSet's
  `rtconfig` drops the `pref` action from a Cisco `default:` and reports
  "default not implemented" for any `default:` on Junos. `rpslconf`'s IOS
  printer renders the pref; the other vendors correctly refuse a `default:`
  they have no configuration for, rather than silently dropping part of it.
- **D7 — configureRouter drops router-specific clauses.** IRRToolSet's
  `configureRouter` command silently omits clauses tied to one particular
  router. `rpslconf` does not implement `configureRouter` — it is one of the
  deferred commands (Commands, above) rather than a reproduction of the bug.
- **D8 — importGroup with a template writes an empty policy.** Given a
  peer-group template, IRRToolSet's `importGroup` silently renders nothing.
  `rpslconf` does not implement `importGroup` either — also deferred.
- **D9 — exit status.** IRRToolSet exits 0 even after it fails — `rtconfig`
  after "no object for AS1" — so a script cannot tell success from failure
  by the exit code. `rpslconf` exits 1 on an error in either mode and 2 on a
  bad command line (Exit status, above); a set it cannot find is a warning
  on stderr, since the set denotes nothing.
- **D10 — output that reads back.** IRRToolSet's `peval` prints AS ranges as
  `AS2-AS3` and an unbound `PeerAS` as `AS4294967295` — even in its own
  queries (`!iAS1:AS-CUST:AS4294967295,1`) — neither of which RPSL or this
  library's own parser accepts. `NormalFilter.String()` always parses back
  with `policy.ParseFilter`.
- **D11 — IOS-XR: a negated exact community test refuses too much.**
  IRRToolSet's `rtconfig` renders `NOT community.contains(5:666)` as
  `community matches-any <*> and not …`, which IOS-XR reads as requiring
  some community to be present — a route with none is refused. `rpslconf`'s
  IOS-XR printer accepts a route with no community too, as its own IOS
  rendering already does.
- **D12 — Junos: two tests in one clause are ORed, not ANDed.** Given a
  clause with both a community test and a prefix list, IRRToolSet's
  `rtconfig` (without `-junos_and_not_or`) writes two `from policy`
  subroutines chained as a Junos policy chain — either one deciding is
  enough, so the community test alone can decide the clause. `rpslconf`'s
  Junos printer chains its subroutines so that all of a clause's tests must
  hold, as RPSL's AND requires.
- **D13 — a session the aut-num has no policy for keeps the router's
  default.** Given no matching import/export, IRRToolSet's `rtconfig` writes
  nothing and warns, leaving the neighbour on whatever the router's own
  default policy already is. `rpslconf` writes a policy that refuses every
  route for such a session: an aut-num with the attribute but no covering
  term denotes no route, not "leave it alone".
- **D14 — IOS-XR: NOT ANY (and ANY) end the policy early.** Given a clause
  peval finds is ANY or NOT ANY, IRRToolSet's `rtconfig` writes `drop`,
  which under IOS-XR's RPL also ends the route-policy — so a later clause,
  which might otherwise accept some of those routes, never runs.
  `rpslconf`'s IOS-XR printer writes nothing for a NOT ANY clause (it
  denotes no route) and lets evaluation fall through to what follows.
- **D15 — IOS: an undefined policy is not the same as a route-map that
  denies.** For a session whose policy denotes no route (`accept NOT ANY`,
  or a peer AS with no matching routes), IRRToolSet's `rtconfig` attaches
  `neighbor … route-map NAME in` for a route-map it never writes and never
  clears — so whatever the router already holds under that name, if
  anything, decides the session. `rpslconf` writes an explicit route-map
  that denies every route for such a session.
- **D16 — IOS-XR: a negated regexp alone produces configuration that will
  not load.** A clause whose only AS-path test is a negated regexp
  (`NOT <AS65004>`) makes IRRToolSet's `rtconfig` write an `as-path-set`
  holding `permit .*` — a shell-glob wildcard, not RPL, which the router
  rejects. `rpslconf`'s IOS-XR printer writes `not as-path in …` directly,
  with no as-path-set needed for it.
- **D17 — a range-operator window beyond /32 misbehaves on the Linux
  build.** For an IPv4 route under a window entirely past the longest
  possible prefix (`AS65001^127-128`, `^126`, `^40`), the Homebrew bottle of
  `peval` correctly answers `NOT ANY`: no IPv4 prefix is longer than /32.
  The Linux build (`scripts/build-irrtoolset.sh`) instead enumerates
  prefixes, some of them invalid (`10.0.0.4/33`), with no consistent
  pattern. `NormalizeFilter` always answers `NOT ANY` for such a window.

Each is listed, with the input that shows it, in
[`resolve/testdata/rtconfig/divergences.md`](../resolve/testdata/rtconfig/divergences.md),
which also says where every one is pinned by a test — so a fix on either side
is caught rather than passing unnoticed. D1 and D2 (and, on the Linux build,
D17) are also kept out of `TestPevalMatchesIRRToolSet`'s comparison rather
than compared, since IRRToolSet's own bug there would fail the test for
reasons that have nothing to do with `rpslconf`; D3 and D5–D9 have no
peval-side test of their own beyond D4's and D9's.
`TestPevalMatchesIRRToolSet` (`resolve/peval_irrtoolset_test.go`) runs
IRRToolSet's `peval` itself against random filters and compares it with
`NormalizeFilter`, but only on the shapes IRRToolSet gets right — prefix
lists, bare AS numbers, AND, OR, and NOT over prefix lists, all IPv4 — since
IRRToolSet substitutes `0.0.0.0/0` for any set member (not only an
operator-qualified one) it cannot resolve, which would fail the comparison
for reasons that have nothing to do with `rpslconf`. See that file for the
narrower `pevalSafe` allow-list and why. `TestRtconfigMatches` and
`TestRtconfigGoldens` (`resolve/rtconfig_irrtoolset_test.go`) run the
equivalent comparison for template mode, against IRRToolSet's `rtconfig`.

## Testing against IRRToolSet

`TestRtconfigMatches` and `TestRtconfigGoldens` compare `rpslconf`'s
template-mode output against IRRToolSet 5.1.3's own `rtconfig`, and
`TestPevalMatchesIRRToolSet` compares peval mode against its `peval`, both
run over the same in-process `irrtest` server. `scripts/build-irrtoolset.sh
[PREFIX]` builds `rtconfig` and `peval` from source (`release-5.1.3`, at
`-O0`: the default `-O2` build crashes printing any prefix set) and installs
them under `PREFIX/bin` (default `$HOME/.cache/irrtoolset-5.1.3/bin`) —
natively on Linux, or in a Docker container elsewhere, with wrapper scripts
that reach a server on the host's loopback through `host.docker.internal`.
Add that directory to `PATH` before running the tests; CI does this, so the
differentials run on every push.

Homebrew's bottle (`brew install irrtoolset`) also works, but only for Cisco
IOS: the arm64 build ignores its command-line options, so it always writes
Cisco configuration regardless of `-config junos`/`-config ciscoxr`/BIRD's
equivalent, and the tests run only the vendors a working binary actually
produces.

The goldens in `resolve/testdata/rtconfig/golden/` let `TestRtconfigGoldens`
compare `rpslconf` against IRRToolSet's checked-in output even with neither
build installed. `RPSL_RTCONFIG_UPDATE=1 go test -run TestRtconfigGoldens
./resolve` rewrites them from a live `rtconfig`; review the diff before
committing it — a golden that silently drifted from `rtconfig`'s real output
would defeat the test's purpose.
