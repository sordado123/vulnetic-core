package db

import (
	"math"
	"testing"
)

// costEur is the #15 pricing arithmetic: it charges fresh input (input minus the
// cached subset, so the cache is not double-charged), output, and the two cache
// buckets, each at EUR per 1M tokens. Pure, so it runs without a database.
func TestProfilePriceCostEur(t *testing.T) {
	p := profilePrice{in: 3, outp: 15, cr: 0.3, cw: 3.75}

	// 2M input of which 1M was cache reads → 1M fresh @3, 0.5M output @15,
	// 1M cache read @0.3, no cache write. 3 + 7.5 + 0.3 = 10.8.
	if got := p.costEur(2_000_000, 500_000, 1_000_000, 0); math.Abs(got-10.8) > 1e-9 {
		t.Fatalf("cost = %v, want 10.8", got)
	}

	// Cache reads exceeding input (disjoint reporting) clamp fresh at zero rather
	// than charging a negative amount.
	if got := p.costEur(100, 0, 1_000, 0); got < 0 {
		t.Fatalf("negative cost %v: fresh not clamped", got)
	}

	// A profile with no prices set contributes nothing and reads as zero().
	var unset profilePrice
	if !unset.zero() {
		t.Fatal("empty price should be zero()")
	}
	if got := unset.costEur(1_000_000, 1_000_000, 0, 0); got != 0 {
		t.Fatalf("unpriced cost = %v, want 0", got)
	}
}
