package resolve

import (
	"context"

	"github.com/rkolesnichenko/rpsl/policy"
)

// NormalizePeak is NormalizeFilter that also returns the largest disjunction
// it built, for the test that MaxConjuncts holds exactly there.
func NormalizePeak(e *Expander, ctx context.Context, f policy.Filter) (NormalFilter, int, error) {
	return e.normalize(ctx, f)
}
