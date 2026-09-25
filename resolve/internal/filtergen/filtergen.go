// Package filtergen writes prefix lists, route filters, as-path filters and AS
// lists in the formats router configuration takes, as bgpq4 1.16 writes them:
// the same text, so a generated filter can replace bgpq4's line for line. Its
// Tree is bgpq4's prefix tree, with bgpq4's aggregation (-A) and
// more-specifics (-R, -r). It does no I/O of its own and no expansion;
// cmd/rpslq feeds it the engine's results.
package filtergen
