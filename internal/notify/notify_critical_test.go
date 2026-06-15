package notify

import (
	"testing"

	"github.com/maruftak/reconsentry/internal/diff"
)

func TestCriticalPriorityBucketsFirst(t *testing.T) {
	changes := []diff.Change{
		{Kind: diff.NewHost, Host: "a", Priority: diff.High},
		{Kind: diff.TakeoverRisk, Host: "b", Priority: diff.Critical},
		{Kind: diff.NewTech, Host: "c", Priority: diff.Low},
	}
	groups := groupByPriority(changes)
	if len(groups) != 3 {
		t.Fatalf("want 3 priority groups, got %d", len(groups))
	}
	if groups[0].priority != diff.Critical {
		t.Errorf("critical group should sort first, got priority %d", groups[0].priority)
	}
	if len(groups[0].changes) != 1 || groups[0].changes[0].Kind != diff.TakeoverRisk {
		t.Errorf("critical bucket should hold the takeover change, got %+v", groups[0].changes)
	}
}

func TestCriticalPriorityLabels(t *testing.T) {
	if got := priorityName(diff.Critical); got != "critical" {
		t.Errorf("priorityName(Critical) = %q, want critical", got)
	}
	if got := priorityEmoji(diff.Critical); got != "🚨" {
		t.Errorf("priorityEmoji(Critical) = %q, want 🚨", got)
	}
	// An unknown high value must not silently drop into the low bucket.
	if got := normalizePriority(diff.Critical); got != diff.Critical {
		t.Errorf("normalizePriority(Critical) = %d, want %d", got, diff.Critical)
	}
}
