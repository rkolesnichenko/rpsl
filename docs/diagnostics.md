# Diagnostic rules

Every `Diagnostic` carries a `Rule`: a stable, machine-filterable ID. Rules are
part of the public API — a rule is never renamed or reused for a different
condition within a major version — and `Severity` follows one convention:

- **Error** — a line or value could not be interpreted, so it is *missing* from
  the typed result (and from any expansion built on it). Filtering on
  `d.Severity >= rpsl.Error` finds everything Decode dropped.
- **Warning** — the value was used, but it is suspect or not what RPSL allows.
- **Info** — advisory only (none are emitted today).

`<class>` stands for an RPSL class (`route`, `as-set`, …) and `<attr>` for an
attribute of it.

## `lexer/` and `rpsl/` — reading text (`rpsl.Parse`, `rpsl.ParseObject`)

| Rule | Severity | Meaning |
| --- | --- | --- |
| `lexer/malformed-line` | Error | A line that is not an attribute, continuation, comment or blank. |
| `lexer/invalid-attribute-name` | Error | An attribute name that is not a letter followed by letters, digits, `-` or `_` (including non-ASCII bytes and a leading BOM). |
| `lexer/too-many-errors` | Error | More than 100 of the above in one object; the rest are counted here. |
| `rpsl/multiple-objects` | Warning | `ParseObject` text holding more than one object. |
| `rpsl/object-too-large` | Error | An object over `MaxObjectBytes` or `MaxObjectLines`, skipped to the next blank line (yielded as an empty object). |
| `rpsl/trivia-too-large` | Warning | Blank/comment lines before an object over a cap, or an over-long line outside any object, discarded. |
| `rpsl/read-error` | Error | The reader failed; the stream ends here. |

## `object/` — typed decoding (`rpsl.Decode`)

| Rule | Severity | Meaning |
| --- | --- | --- |
| `object/empty-key` | Error | The class attribute (the key) has no value. |
| `object/<class>-<attr>` | Error | A value of `<attr>` could not be parsed and is missing from the struct, e.g. `object/route-origin`, `object/aut-num-member-of`, `object/as-set-members`, `object/route-ping-hdl`. |
| `object/<class>-name`, `object/route-prefix`, `object/route6-prefix`, `object/aut-num-as` | Error | The class key — a set name, a route prefix, an AS number — could not be parsed; the key field is left empty. |
| `object/inetnum-range`, `object/as-block-range` | Error | A range that is not `lo - hi`, is reversed, or (inetnum) is not two IPv4 addresses. |
| `object/inet6num-prefix` | Error | An inet6num key that is not an IPv6 prefix. |
| `object/<class>-members`, `-mp-members` | Warning | A nested set of a class the container may not list (an `RS-` set in an as-set). |
| `object/<class>-members-host-bits`, `-mp-members-host-bits` | Warning | A prefix member with host bits set; it is read with them cleared. |
| `object/route-set-members-afi` | Warning | An IPv6 prefix in a route-set's `members:`, which RFC 4012 §4.2 keeps IPv4-only (IPv6 belongs in `mp-members:`). |
| `object/<class>-member-of-class` | Warning | A `member-of:` naming a set of a class the object cannot join: an aut-num joins as-sets, a route or route6 route-sets, an inet-rtr rtr-sets. |
| `object/list-empty-item` | Warning | An empty item in a comma-separated list (`AS1,,AS2`). |
| `object/<class>-name-class` | Warning | A set named like another class (`route-set: AS-FOO`). |
| `object/route-afi`, `object/route6-afi` | Warning | An IPv6 `route` or IPv4 `route6`. |
| `object/<class>-host-bits` | Warning | A route, route6 or inet6num prefix with host bits set. |
| `object/<class>-holes-host-bits` | Warning | A `holes:` prefix with host bits set; it is read with them cleared. |
| `object/<class>-leading-zeros` | Warning | An IPv4 address or prefix with zero-padded octets (`064.006.160.000/19`), in any attribute; the octets are read as decimal, as RPSL writes addresses and IRRd reads them. |
| `object/<class>-holes-outside` | Warning | A `holes:` prefix outside the route. |
| `object/<class>-auth` | Warning | An `auth:` line naming a scheme this library does not know, or carrying no credential; it is kept whole and nothing is dropped. |
| `object/<class>-changed`, `object/<class>-created`, `object/<class>-last-modified` | Warning | A `created:`/`last-modified:` that is not RFC 3339, or a `changed:` date that is not `YYYYMMDD`; the text is kept as written. |

## `policy/` — routing policy (`import`, `export`, `default`, `filter`, `peering`, and `mp-` forms)

| Rule | Severity | Meaning |
| --- | --- | --- |
| `policy/empty` | Error or Warning | An empty policy value (Error); an empty `{ }` expression, which has no effect (Warning). |
| `policy/expect-peering`, `policy/expect-filter` | Error | A factor without its `from`/`to` or `accept`/`announce` part. A filter term after `EXCEPT` (`accept ANY EXCEPT FLTR-BOGONS`) gets a hint: `EXCEPT` joins two policies, and `AND NOT` leaves a term out of a filter. |
| `policy/via` | Error | An `import-via:` or `export-via:` clause with no via peering before its `from`/`to`; the clause is dropped. |
| `policy/peering`, `policy/as-expr` | Error | A malformed peering or AS expression, including `NOT`, which is not an AS-expression operator (write `EXCEPT`). |
| `policy/router` | Warning or Error | A router expression term that is not a router: a single-label name (Warning — real policies use labels such as `PEERING`), or an invalid term, `NOT`, a dangling or missing operator (Error). |
| `policy/protocol` | Error | `protocol` or `into` without a protocol name. |
| `policy/action` | Error | An action that is not `attr = value`, `attr .= value` or `attr.method(args)` (the other RFC 2622 Figure 25 assignments, such as `+=`, are read as operator methods): two actions without `;`, a comparison such as `pref == 10`, a bare word, or a missing value. It is left out. |
| `policy/filter` | Error | An unexpected token or invalid term in a filter, or a malformed `community == {…}`. |
| `policy/filter-method` | Error | A method that is not a filter (`aspath.prepend(…)` is an action), or an unknown one. |
| `policy/filter-paren` | Error | An unbalanced `(` or `)` in a filter or method call. |
| `policy/prefix-list` | Error or Warning | A malformed `{…}` prefix list or member, or two members without a `,` between them (Error; the second is left out); an empty item, as in `{a,,b}` (Warning). |
| `policy/host-bits` | Warning | A prefix-list member with host bits set; it is read with them cleared. |
| `policy/leading-zeros` | Warning | An IPv4 address or prefix in a policy value with zero-padded octets; they are read as decimal. |
| `policy/unicode-space` | Warning | A space other than an ASCII space, tab or newline — a no-break space (U+00A0) or another Unicode space, a vertical tab or a form feed — between the tokens of a policy value; it is read as a space, as IRRd reads it. Reported once per value, at the first. |
| `policy/range-op` | Error | An invalid range operator. |
| `policy/as-path-regexp` | Error or Warning | A malformed or empty AS-path regexp, one whose `<` is never closed, a `>` that closes nothing, or a term other than an AS number, as-set or `PeerAS` (Error, at the offending token); an AS number written without `AS`, as in `<3333>` (Warning). |
| `policy/inject` | Error | A malformed `inject:` condition: a test that is not `STATIC`, `HAVE-COMPONENTS` or `EXCLUDE`, a missing `{` or `)`. |
| `policy/aggr-mtd` | Error | An `aggr-mtd:` that is neither `inbound` nor `outbound`. |
| `policy/ifaddr` | Error | A malformed `ifaddr:`: a bad address, a missing or over-long `masklen`. |
| `policy/interface` | Error | A malformed RFC 4012 `interface:`: a bad address family, or a `tunnel` without its `,<encapsulation>`. |
| `policy/peer` | Error or Warning | A malformed `peer:`/`mp-peer:` — a missing protocol, an unterminated `(` in an option (Error); an empty item in the option list (Warning). |
| `policy/mnt-routes` | Error | A malformed `mnt-routes:`: no maintainer name, or a scope that is neither `ANY` nor a prefix list. |
| `policy/typedef` | Error | A dictionary `typedef:` with no type definition after its name. |
| `policy/rp-attribute` | Error or Warning | A malformed `rp-attribute:` declaration, or one declaring no method (Error); an action naming an attribute the dictionary does not declare (Warning, only when one is supplied). |
| `policy/rp-method` | Warning | An action naming a method the dictionary's attribute does not declare. Only when a dictionary is supplied. |
| `policy/rp-protocol` | Error or Warning | A malformed `protocol:` declaration, or an option group without `MANDATORY`/`OPTIONAL` (Error); a protocol name the dictionary does not declare (Warning, only when one is supplied). |
| `policy/afi` | Error | An empty or invalid `afi` list, or an `afi` clause in a legacy `import:`, `export:` or `default:`, where RFC 4012 does not allow one (it is ignored). |
| `policy/default-to` | Error | A `default` without its `to` peering. |
| `policy/expr-brace`, `policy/missing-semicolon` | Error, Warning | A structured policy's `{…}` unbalanced, or two factors with no `;` between them. |
| `policy/trailing` | Error | Input left after a complete value. |
| `policy/nesting` | Error | Nesting (parentheses, braces, `NOT`, operator chains, regexp quantifiers) deeper than 1,000; the value is abandoned. |
| `policy/too-long` | Error | A value (or AS-path regexp) of more than 1,048,576 tokens; not parsed. |
| `policy/too-many-errors` | Error | More than 100 diagnostics in one value; the rest is not checked. |

## `dict/` — profile validation (`rpsl.Validate`)

| Rule | Severity | Meaning |
| --- | --- | --- |
| `dict/unknown-class` | Error | The profile does not define the class. |
| `dict/unknown-attr` | Warning | An attribute the class does not allow (both built-in profiles reject unknown attributes; a custom one may allow them). |
| `dict/missing-required` | Error | A required attribute, or one of a required group (`filter`/`mp-filter`), is missing or has no value. |
| `dict/cardinality` | Error | A single-valued attribute appears more than once. |
