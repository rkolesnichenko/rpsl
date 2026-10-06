# ASPA data, an RPSL-vs-ASPA cross-check, and NRTMv4 signature algorithms

Status: design approved in brainstorming · 2026-10-06 · planned v0.25.0

## 1. Summary

ASPA (Autonomous System Provider Authorization) lets an AS sign the list of
its transit providers in the RPKI. RIPE NCC, ARIN and APNIC issue them; on
2026-10-06 rpki-client's public export held 3,413 validated ASPAs, and BIRD,
OpenBGPD and arouteserver consume them. Validators already put them in the
JSON export `resolve/rpki` reads, and `ReadJSON` skips them.

This release reads them, and compares them with what the IRR says about the
same AS: the policies its aut-num states and the as-sets it announces. No
standard, IRRd, bgpq4 or arouteserver performs that comparison. It compares
registry data only, never a BGP path, so it stays inside the scope guardrail
(CLAUDE.md: AS-path regexps are never evaluated against paths).

It also lets the NRTMv4 client verify the signature algorithms the protocol
lets a server use besides ES256.

Three pieces:

1. `resolve/rpki`: an `ASPAs` type validated to the ASPA profile, read from
   the validator export (§3).
2. `resolve/consist`: three lint rules comparing an aut-num with ASPAs,
   on when `Checker.ASPAs` is set; `rpslcheck -rpki FILE` (§4, §5).
3. `resolve/nrtm4`: ES384, ES512, Ed25519, RS256 and PS256 beside ES256,
   with the algorithm bound to the key (§6).

### Decisions taken in brainstorming

1. **Scope: data and the cross-check.** Not data alone (nothing in the repo
   would use it), and not path verification (ASPA's upstream/downstream path
   check evaluates AS paths: a separate `bgp`/`verify` consumer's job).
2. **Rules:** provider missing from ASPA, stale ASPA provider, customer set
   member's ASPA not naming the announcer. Not "no ASPA for an AS with
   providers": most ASes have none today, so it would be noise.
3. **Approach A:** the rules are `consist.Lint` rules, so they reach
   `rpslcheck`'s modes, output, goldens and sweep totals unchanged. Not a
   separate package (it would re-implement peer discovery, session
   evaluation and sweeps), and not inside `resolve/rpki` (which would then
   import `peval`).
4. **ASPA SLURM deferred.** draft-ietf-sidrops-aspa-slurm-04 expired on
   2026-05-20; it does not say whether an assertion replaces or adds to a
   customer's existing ASPA; rpki-rs spells the filter key `customerAsid`
   where the draft says `customerAsn`; no validator applies it. `ApplySLURM`
   stays RFC 8416 version 1, and a version 2 file stays an error.
5. **Signature algorithms ride along** in the same release: small,
   standard-library only, and spec-allowed today.

### Facts this design rests on (checked 2026-10-06)

- **Profile:** draft-ietf-sidrops-aspa-profile-29 (WG consensus, waiting for
  write-up; not an RFC). `ASProviderAttestation ::= SEQUENCE { version [0]
  INTEGER DEFAULT 0, customerASID CAS, providers ProviderASSet }`, with
  `CAS ::= INTEGER (1..4294967295)` and `PAS ::= INTEGER (0..4294967295)`.
  §3.3: "The customerASID value MUST NOT appear in any PAS in the providers
  field"; "The elements of providers MUST be ordered in ascending numerical
  order"; "Each value of PAS MUST be unique"; AS0 "MUST NOT appear alongside
  any other elements", and means the customer "does not use any providers
  for transit". §5.2: several ASPAs for one customer merge into the union of
  their providers, AS0 removed when other values are present. §5.5
  recommends a cap of 4,000 to 10,000 providers per customer. The per-AFI
  provider field was removed in -14 (mid-2023).
- **rpki-client** (output-json.c, 8.5 and later): top-level `"aspas"`,
  entries `{"customer_asid": 43, "expires": 1791385200, "providers": [293]}`,
  providers plain integers, no `ta`. 8.0–8.4 wrote
  `"provider_authorizations": {"ipv4": […], "ipv6": […]}` instead.
- **Routinator** (src/output.rs, 0.13.0 and later, with `enable-aspa`):
  `{"customer": "AS64496", "providers": ["AS64497", …], "ta": "ripe"}`;
  `jsonext` adds `source`. Its manual's `afi` field is stale: the code emits
  none.
- **arouteserver** 1.25 accepts both shapes.
- **Live data** (rpki-client console, 2026-10-06): 3,405 unique VAPs, every
  provider list sorted and unique, none listing its customer, 65 AS0-only,
  the longest with 230 providers. NTT's export, which
  `scripts/fetch-irr-dumps.sh rpki` already fetches for the RPKI tests, is
  rpki-client output with `"aspas"` (3,273 on 2026-09-27).
- **NRTMv4:** draft-ietf-grow-nrtm-v4-11 (RFC Editor queue): "Mirror clients
  MUST implement ES256. Mirror servers MAY use ES256 or other digital
  signature algorithms from the IANA JOSE Algorithms registry; the algorithm
  MUST NOT be "none", a MAC algorithm, or Deprecated or Prohibited. It is
  RECOMMENDED to use ES256 or other Recommended or Recommended+ algorithms."
  The IANA registry marks `ES256` Recommended+, `RS256` Recommended,
  `ES384`, `ES512`, `PS256`, `Ed25519` and `Ed448` Optional, and `EdDSA`
  **Deprecated** (RFC 9864 §2.2). RIPE and IRRd 4.5.3 sign with ES256 on a
  P-256 key today.

## 2. Architecture

```
types ← object ← resolve ← resolve/rpki  (ASPAs: data, no policy)
                        ↖ resolve/peval ← resolve/consist (+ ASPA rules; imports resolve/rpki)
                                                ↖ resolve/internal/rpslcheck (-rpki)
resolve/nrtm4 (signature algorithms; independent of the above)
```

Imports stay downward: `consist` gains an import of `resolve/rpki`, which
imports neither `peval` nor `consist`. Neither `rpki` nor `consist` opens a
socket; `cd resolve && go list -deps . ./peval ./rtconfig ./consist ./irrdq`
must still show no `net`, and `resolve/rpki` is added to that check.

## 3. ASPA data (`resolve/rpki`)

### 3.1 API

```go
// ASPA is one validated ASPA payload (draft-ietf-sidrops-aspa-profile-29):
// Customer names the ASes it may send routes to as a customer.
type ASPA struct {
	Customer  types.ASN   // never 0
	Providers []types.ASN // ascending, unique, never Customer; [0] alone: no transit providers
}

// MaxProviders caps one customer's providers, after merging: the top of
// the profile's recommended 4,000 to 10,000 (§5.5).
const MaxProviders = 10_000

// ASPAs is an immutable set of ASPAs, at most one per customer, safe for
// concurrent use. The zero value holds none.
type ASPAs struct{ /* customer -> merged providers */ }

// NewASPAs validates each ASPA (§3.2) and merges those of one customer
// (§3.3). It copies its input.
func NewASPAs(as []ASPA) (*ASPAs, error)

// ReadASPAs reads the ASPAs of a relying-party validator's JSON export (§3.4).
func ReadASPAs(r io.Reader) (*ASPAs, error)

// Providers returns customer's providers, ascending, and whether it has an
// ASPA at all. ok with no providers is an AS0 ASPA: the customer declares
// no transit providers. The slice is a copy.
func (s *ASPAs) Providers(customer types.ASN) (providers []types.ASN, ok bool)

// Len returns the number of customers with an ASPA.
func (s *ASPAs) Len() int

// All yields the merged ASPAs, ascending by customer; an AS0 ASPA has
// Providers [0].
func (s *ASPAs) All() iter.Seq[ASPA]
```

`Providers` returns no AS0, so a caller asking "is P a provider of C" never
has to special-case it; `All` returns the ASPA as the profile writes it.

### 3.2 Validation (profile §3.3), strict

`NewASPAs` refuses, naming the customer:

- a `Customer` of 0;
- `Providers` empty, not ascending, holding a duplicate, or holding
  `Customer`;
- 0 alongside any other provider;
- more than `MaxProviders` providers, before or after merging.

A validator exports only payloads it has validated, so a violation means a
broken or misread file, not data to repair. This matches how `ReadJSON`
treats a malformed ROA.

### 3.3 Merging (profile §5.2)

Several ASPAs for one customer become one: the union of their providers,
ascending. If the union holds AS0 and anything else, AS0 is removed; the
merged ASPA is AS0-only exactly when every input for that customer was.

### 3.4 Reading (`ReadASPAs`)

- The input is a JSON object; only its top-level `"aspas"` array is read,
  one record at a time (as `ReadJSON` reads `"roas"`), so memory follows the
  ASPAs, not the file. Other members (`metadata`, `roas`, `bgpsec_keys`, …)
  are skipped. `"aspas"` twice is an error.
- A record is an object with, exactly as spelled:
  - the customer as `customer_asid` (rpki-client) or `customer`
    (Routinator) — exactly one of the two;
  - `providers`, an array.
  Other keys (`expires`, `ta`, `source`) are ignored. An AS number may be a
  JSON number, a numeric string, or `"AS"` followed by digits, as
  `ReadJSON` reads `asn`.
- Records go through `NewASPAs`; one bad record fails the whole read, with
  its index.
- No `"aspas"` member is an error (`no "aspas" member: the export has no
  ASPAs; rpki-client writes them unless -A, Routinator only with
  enable-aspa`), not an empty set: an empty set would make every rule
  silently report nothing.
- A top-level `"provider_authorizations"` without `"aspas"` is an error
  naming its cause: rpki-client 8.0–8.4's per-AFI form, superseded in 8.5.

### 3.5 What does not change

`ReadJSON`, `VRPs`, `ApplySLURM`, `Filter` and `WriteRPSL` are unchanged.
IRRd imports no ASPAs and serves no ASPA pseudo-objects, so nothing in
`irrdq`, `rpsld` or `rpslq` reads them. The package comment gains a
paragraph: `ASPAs` is the RPKI data the consistency checks read; IRRd's
RPKI-aware mode has no use for it.

## 4. The cross-check (`resolve/consist`)

### 4.1 API

```go
type Checker struct {
	// … existing fields …

	// ASPAs, when set, adds the ASPA rules to Lint (lint/aspa-*): the
	// aut-num's policy and the as-sets it announces compared with the
	// ASPAs. nil: Lint is unchanged.
	ASPAs *rpki.ASPAs
}

const (
	RuleASPAMissingProvider = "lint/aspa-missing-provider" // Warning
	RuleASPAStaleProvider   = "lint/aspa-stale-provider"   // Info
	RuleASPACustomerSet     = "lint/aspa-customer-set"     // Warning
)
```

`Rules()` lists them after the existing rules; `docs/diagnostics.md` gets a
row each. `Check` (the pair comparison) is unchanged.

### 4.2 `lint/aspa-missing-provider` (Warning)

The linted AS C imports a full table from peer X, and C's ASPA does not
list X — or C's ASPA is AS0.

- **Full table.** One of C's decided `import:`/`mp-import:` clauses toward
  X (peval's `Policy.Clauses` for the session C ← X), in ipv4.unicast or
  ipv6.unicast, has a conjunct whose `Prefixes` is the session family's
  whole space (`ANY`), with:
  - any `NotPrefixes` (bogon filters);
  - any *negated* AS-path or community test (`NOT <_AS0_>`);
  - no *positive* AS-path or community test. `accept <^PeerAS+$>`, or
    `accept ANY AND community(65000:1)`, selects a subset of routes: a
    peer's or a customer's, not a provider's full table.
  ASPA has no address family (profile -14 removed it), so a full table in
  either family makes X a provider.
- **Sessions.** Only toward a real peer Lint names: Forward, Reverse, and
  ViaSets with `Checker.SetPeers`. Never the reserved AS-ANY session
  (`AS4294967295`) or a set peering's representative session: a finding
  there would name an AS the policy never named.
- **Silent when:** C has no ASPA (decision 2); the clause is undecided
  (peval could not decide it: a router not given, a regexp peering, another
  protocol); X is in C's providers.
- **Issue:** on the import attribute (`Attr`, `Index` of the clause), with
  X in `Peers` and the families in `AFs`; the message names X and says
  whether C's ASPA is AS0 or lists other providers. One issue per attribute
  and X, merged across families as Lint merges.

### 4.3 `lint/aspa-stale-provider` (Info)

C's ASPA lists provider P, and none of C's peerings names P.

- **Named** means in `PeerList.Forward` or `PeerList.ViaSets` (Peers lists
  ViaSets whether or not `SetPeers` is set). Reverse does not count: it is
  P's policy naming C, not C's.
- **Silent when:** C has no ASPA, or an AS0 one; `PeerList.Skipped` is not
  empty (a peering through AS-ANY, a regexp or a set template could name
  P); peer listing hit a limit.
- **Issue:** object-level (`Attr ""`, `Index -1`), P in `Peers`, one issue
  per P.

### 4.4 `lint/aspa-customer-set` (Warning)

C announces an as-set S, and a direct member AS M of S has an ASPA that
does not name C — or an AS0 ASPA.

- **Announces.** S is named *positively* in one of C's `export:`/
  `mp-export:` filters, found by a static walk of the filter tree (the walk
  the missing-set check already does): not under a `NOT`, not a set
  template. AS-path regexps are not walked: a set inside `<…>` is a path
  test, not an announcement. Only as-sets; a route-set lists routes, not
  customers.
- **Direct members** of S: the ASNs `object.DirectMembers(S)` lists
  (`src-members:` honoured), and the aut-nums `Source.MembersByRef(S)`
  returns that pass `resolve.ClaimAllowed`. Nested sets are not followed:
  their members are customers of that set's owner, not of C. Range
  operators on a member are ignored (an ASN is an ASN).
- **Silent when:** M = C; M has no ASPA; C is among M's providers; S is
  missing (already `lint/missing-set`).
- **Issue:** on the export attribute (`Attr`, `Index`), with M in `Peers` —
  the one rule whose `Peers` is not a session peer, and its doc comment
  says so — and a message naming S and M. One issue per attribute, S and M.
- **Cost.** One `GetSet` and one `MembersByRef` per announced set, each set
  once per Lint call, under the Checker's Expander limits.

### 4.5 What Lint already gives

Severity, merging across sessions, spans, sorting and the sweep's per-rule
totals come from the existing `linter`; the new rules add issues through it.
Nothing here evaluates an AS path: the rules read normalized filters'
structure (which tests a conjunct has, not what they match), set members
and ASPA provider lists.

## 5. The CLI (`rpslcheck`)

- New flag: `-rpki FILE`, the validator's JSON export. It is read with
  `ReadASPAs` and set as `Checker.ASPAs`; without it nothing changes. A
  read error exits 3 ("could not complete"), as an unreadable `-dump` does.
- All three modes (one AS, a pair, `-sweep`) report the new rules like any
  other lint rule, in text and JSON; a sweep's per-rule totals include them.
- `docs/rpslcheck.md` documents the flag and the three rules, with one
  measured sweep's totals (§7.4).
- New goldens in `resolve/testdata/rpslcheck/` for one AS and one sweep
  with `-rpki`, over a fixture holding each rule's case.

## 6. NRTMv4 signature algorithms (`resolve/nrtm4`)

### 6.1 Accepted and refused

| `alg` | Key | Note |
|---|---|---|
| `ES256` | ECDSA P-256 | the one a client MUST support |
| `ES384` | ECDSA P-384 | |
| `ES512` | ECDSA P-521 | |
| `Ed25519` | Ed25519 | RFC 9864 |
| `RS256` | RSA ≥ 2048 bits | Recommended in the registry |
| `PS256` | RSA ≥ 2048 bits | |

Refused, with the algorithm named: `none`, every MAC (`HS*`), `EdDSA`
(Deprecated by RFC 9864; a server must use `Ed25519` instead), `Ed448` (no
standard-library implementation), RSA under 2048 bits, and anything else.
`crit` stays refused, as now.

### 6.2 The key decides the algorithm

The header's `alg` must be the one the key's type allows: a P-256 key
verifies only `ES256`, P-384 only `ES384`, P-521 only `ES512`, an Ed25519
key only `Ed25519`, an RSA key `RS256` or `PS256`. A mismatch is refused,
so a header cannot pick a different check than the key was issued for.
A rotation (`next_signing_key`) may change the key type; the new key is
parsed by its own type, and the rule that the old key is never used again
(§9.6) is unchanged.

### 6.3 API

```go
// ParsePublicKey parses a PEM public key (SubjectPublicKeyInfo) of a type
// NRTMv4 verification accepts: *ecdsa.PublicKey on P-256, P-384 or P-521,
// ed25519.PublicKey, or *rsa.PublicKey of at least 2048 bits.
func ParsePublicKey(text string) (crypto.PublicKey, error)
```

This is a breaking change (it returned `*ecdsa.PublicKey`), listed in the
CHANGELOG's migration table. `Client.PublicKey` (a PEM string),
`Status.CurrentKey` and rpsld's `-source NAME=nrtm4:URL,key=PEM` are
unchanged. The ES256 path is byte-for-byte the current one.

## 7. Tests

### 7.1 `resolve/rpki`

- Table tests for every §3.2 rule and the §3.3 merge (union, AS0 dropped,
  AS0-only kept, the cap before and after merging).
- `ReadASPAs` over fixtures copied verbatim: rpki-client's live entries
  (customers 43, 80 and 174 above), Routinator's `json` and `jsonext`
  shapes from src/output.rs, the 8.0–8.4 `provider_authorizations` form,
  an export without `"aspas"`, and each malformed-record case.
- `FuzzReadASPAs`: no panic; whatever is accepted holds §3.2, and its
  `All()` given back to `NewASPAs` is equal to it.
- Real data (opt-in, `RPSL_REALDATA`): `ReadASPAs` over NTT's export
  (`.data/rpki/vrps.json`): every record read, and the count compared with
  the file's `metadata.uniquevaps` (3,269 on 2026-09-27, beside `aspas`
  3,273 and `vaps` 3,271). The plan settles which of these the array's
  length is before the test asserts it. A few customers are checked by hand
  against the file.

### 7.2 `resolve/consist`

- Table tests for each rule's edges: `ANY`, `ANY AND NOT {bogons}`,
  `NOT <AS0>`, a positive regexp and a positive community test (no
  finding), an undecided clause, an AS0 ASPA, no ASPA, a non-empty
  `Skipped`, a set peering's representative session, a nested set, a
  `member-of:` claimant allowed and refused, a set under `NOT`, a set
  inside a regexp, M = C.
- **The consistency model** (`TestModelConsist`, `TestModelConsistBackends`)
  draws random ASPAs for the generated ASes (none, AS0, providers including
  and excluding the peer) and random customer as-sets named in exports.
  An oracle decides each rule from the generator's own model — its filter
  trees, peerings and sets — without `NormalizeFilter`, `Peers` or the
  Source, and Lint's ASPA issues must equal the oracle's exactly, over every
  backend the model already runs (MemSource, Corpus with KeepPolicy and
  IndexPeers, irrd and whois against irrtest and against rpsld).
- `Rules()` and `docs/diagnostics.md` agree (`TestDiagnosticRulesAreDocumented`).

### 7.3 `resolve/nrtm4`

- A sign-and-verify round trip for each accepted algorithm; a refusal for
  each refused one and for every mismatched pair of key type and `alg`.
- `internal/nrtmtest` signs with any accepted key type; one random history
  rotates from ES256 to Ed25519 within a session, and the mirror must equal
  the server's database after it.
- `FuzzVerifyJWS`: no panic over any key type, and only a well-formed,
  correctly signed file with the key's own algorithm verifies.
- `TestLiveRIPE` (opt-in) still verifies RIPE's real ES256 file.

### 7.4 Real data (opt-in)

`TestRealDataConsist` gains a run with NTT's ASPAs: a RIPE sweep (or a
sample, `RPSL_CONSIST_SAMPLE`) reporting each new rule's count, and a
sample of each rule's findings checked by hand against the aut-num and the
export. The measured totals go into `docs/rpslcheck.md`. Run alone, under
the memory guard, like every real-data test.

## 8. Docs and invariants

- Design doc: §8.7 gains `ASPAs`; §8.8 the algorithms; §8.12 the three
  rules; §11 the new tests and fuzz targets; §12 the status line.
- CLAUDE.md: the fuzz list (45 targets), the engine-purity check including
  `./rpki`, and one line for the rules' exactness (§4.5).
- README status table; `docs/rpslcheck.md`; `docs/diagnostics.md`;
  CHANGELOG `[0.25.0]` with the `ParsePublicKey` migration.

## 9. Out of scope

- ASPA SLURM (decision 4).
- ASPA path verification (upstream/downstream): it evaluates AS paths.
- A "no ASPA for an AS with providers" rule (decision 2).
- Reading ASPAs over RTR, or from rpki-client's BIRD/OpenBGPD outputs.
- Serving ASPAs from `rpsld`: IRRd does not.
- rpki-client 8.0–8.4's per-AFI ASPA form: refused with a clear error.
- `Ed448` (no standard-library implementation).

## 10. Risks

- **The drafts are still moving.** The profile is at WG consensus, not an
  RFC. Comments and docs pin draft-ietf-sidrops-aspa-profile-29 and
  draft-ietf-grow-nrtm-v4-11, as the NRTMv4 client already pins its draft.
- **"Full table" is an inference.** A customer may import ANY from a peer
  that is not its transit provider (a full-table peering). The rule then
  says so as a Warning that the operator can judge; the definition is
  written in the issue's documentation, and the real-data sample (§7.4)
  measures how often it fires.
- **ASPA data churns daily.** Findings are a snapshot of one export;
  `rpslcheck` prints nothing about freshness. The export's
  `metadata.buildtime` is not read in this release.
