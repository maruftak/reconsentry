package prioritize

import (
	"strings"
	"testing"

	"github.com/maruftak/reconsentry/internal/diff"
)

func TestMarkInteresting(t *testing.T) {
	in := []diff.Change{
		{Kind: diff.NewHost, Host: "admin.example.com", Priority: diff.Low, Detail: "new host discovered"},
		{Kind: diff.NewHost, Host: "www.example.com", Priority: diff.High, Detail: "new live host"},
		{Kind: diff.HostLive, Host: "staging.example.com", Priority: diff.Low},
		{Kind: diff.StatusChange, Host: "admin.other.com", Priority: diff.Medium}, // not a new host: untouched
	}
	out := MarkInteresting(in, nil) // nil -> defaults

	// admin.* promoted to High and tagged.
	if out[0].Priority != diff.High {
		t.Errorf("admin host should be promoted to High, got %d", out[0].Priority)
	}
	if !strings.Contains(out[0].Detail, "⭐ interesting: admin") {
		t.Errorf("admin host should be tagged, got %q", out[0].Detail)
	}
	// Already-High new host stays High; tagged but not lowered.
	if out[1].Priority != diff.High {
		t.Errorf("www should remain High, got %d", out[1].Priority)
	}
	// HostLive matches too.
	if out[2].Priority != diff.High || !strings.Contains(out[2].Detail, "staging") {
		t.Errorf("staging HostLive should be promoted+tagged, got %+v", out[2])
	}
	// Non-new-host change untouched even if its host matches a keyword.
	if out[3].Priority != diff.Medium || strings.Contains(out[3].Detail, "interesting") {
		t.Errorf("status change must not be promoted, got %+v", out[3])
	}
}

func TestMarkInterestingDoesNotMutateInput(t *testing.T) {
	in := []diff.Change{{Kind: diff.NewHost, Host: "admin.example.com", Priority: diff.Low, Detail: "x"}}
	MarkInteresting(in, nil)
	if in[0].Priority != diff.Low || in[0].Detail != "x" {
		t.Errorf("input was mutated: %+v", in[0])
	}
}

func TestMarkInterestingCustomKeywords(t *testing.T) {
	in := []diff.Change{
		{Kind: diff.NewHost, Host: "admin.example.com", Priority: diff.Low}, // default keyword, but custom list given
		{Kind: diff.NewHost, Host: "payments.example.com", Priority: diff.Low},
	}
	out := MarkInteresting(in, []string{"payments"})
	if out[0].Priority != diff.Low {
		t.Error("admin should NOT match when a custom keyword list excludes it")
	}
	if out[1].Priority != diff.High {
		t.Error("payments should match the custom keyword")
	}
}

func TestMarkInterestingNoMatch(t *testing.T) {
	in := []diff.Change{{Kind: diff.NewHost, Host: "shop.example.com", Priority: diff.Low}}
	out := MarkInteresting(in, []string{"zzz-no-match"})
	if out[0].Priority != diff.Low || strings.Contains(out[0].Detail, "interesting") {
		t.Errorf("non-matching host should be untouched, got %+v", out[0])
	}
}
