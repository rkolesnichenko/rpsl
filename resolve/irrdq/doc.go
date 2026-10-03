// Package irrdq answers IRRd's query protocol, and RIPE-style whois queries,
// over registries held in memory, as IRRd 4.5.3 answers them — the
// semantics an IRRd client (bgpq4, IRRToolSet, resolve/irrd, resolve/whois)
// expects, including where IRRd and RFC 2622 differ (a member with a range
// operator is dropped from a recursive expansion, an as-set follows a
// route-set listed in it from a route-set root, AS-ANY is a missing set).
// SnapshotOptions.RFC answers "!i…,1" and "!a" by resolve.Expander instead.
//
// It is pure, like resolve: no sockets, no goroutines; resolve/irrdserver
// puts a Session on a connection. A Snapshot is immutable: a Session reads
// the current one once per command, so one answer comes from one snapshot.
//
// A registry holds the routing classes only — as-set, route-set, rtr-set,
// filter-set, peering-set, aut-num, inet-rtr, route and route6 — and a
// query for any other class is refused, never answered as not found: a
// mirror that holds part of a registry does not pass the rest off as missing.
//
// resolve/testdata/rpsld/divergences.md lists where it differs from IRRd.
package irrdq
