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
| `operator-on-set-member` | `RS-INNER^25` | RS-INNER's prefixes under `^25` | nothing | RFC 2622 §5.2 allows a range operator on a set member. IRRd returns `RS-INNER^25` from `!i…,1` as an unresolved name, which bgpq4 cannot use. |
| `operator-on-as-member` | `AS65001^25` in a route-set | AS65001's routes under `^25` | nothing | Same as above, for an AS number (RFC 2622 §5.3). |
| `route-set-in-as-set` | `as-set: AS-X` listing `RS-Y` | RS-Y is not followed | RS-Y's AS members are added | RFC 2622 §5.1: an as-set lists AS numbers and as-sets only. Following a route-set would let it add ASes to the as-set. |
| `as-any` | `AS-ANY` as a member | `AnySetError` | ignored (no such set) | `AS-ANY` denotes every AS; the engine refuses to expand it rather than quietly drop it (see the design doc, §8.3). |

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
