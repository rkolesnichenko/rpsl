package resolve

// modelSeeds returns how many seeds a randomized model or property test draws
// from n, and whether that is all n. Under the race detector, which slows these
// CPU-bound loops about fourfold, it is a quarter of n: the detector needs each
// concurrent path run, not thousands of random IRRs, and scripts/check.sh runs
// every test again without -race (its coverage pass), where all n are drawn.
// A floor calibrated to n seeds — a count of findings, of suppressed routes —
// is checked only when full is true.
func modelSeeds(n uint64) (seeds uint64, full bool) {
	if raceEnabled {
		return max(n/4, 1), false
	}
	return n, true
}
