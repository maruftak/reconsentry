package report

// Spike detection flags a run that added an abnormal burst of new hosts
// relative to the scope's own recent history — the moment a target is actively
// shipping surface, which is exactly when a hunter wants to look.

const (
	// spikeFloor is the minimum number of new hosts in a single run for a spike
	// to be possible at all. Below this, a "burst" is just normal churn.
	spikeFloor = 3
	// spikeMultiple is how many times the recent average a run must exceed to
	// count as a spike once the floor is met.
	spikeMultiple = 3.0
)

// isSpike reports whether current (the new-host count for a run) is an abnormal
// burst given history (new-host counts of the preceding non-baseline runs,
// chronological). The baseline run has no history and is never a spike.
func isSpike(current int, history []int) bool {
	if current < spikeFloor || len(history) == 0 {
		return false
	}
	mean := mean(history)
	// When the surface is normally static (mean ~0), any burst at/above the
	// floor is notable. Otherwise require a multiple of the recent average.
	if mean < 1 {
		return current >= spikeFloor
	}
	return float64(current) >= spikeMultiple*mean
}

func mean(xs []int) float64 {
	if len(xs) == 0 {
		return 0
	}
	sum := 0
	for _, x := range xs {
		sum += x
	}
	return float64(sum) / float64(len(xs))
}
