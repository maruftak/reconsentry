package runner

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/maruftak/reconsentry/internal/config"
	"github.com/maruftak/reconsentry/internal/diff"
	"github.com/maruftak/reconsentry/internal/model"
	"github.com/maruftak/reconsentry/internal/store"
)

func newContentPipeline(t *testing.T, content ContentFunc) (*Pipeline, *config.Config) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	discover := func(_ context.Context, _ []string) ([]string, error) { return []string{"a.example.com"}, nil }
	probe := func(_ context.Context, h []string) ([]model.Asset, error) {
		out := make([]model.Asset, 0, len(h))
		for _, x := range h {
			out = append(out, model.Asset{Host: x, Alive: true, Status: 200})
		}
		return out, nil
	}
	p := &Pipeline{Store: st, Discover: discover, Probe: probe, Content: content}
	cfg := &config.Config{Name: "prog", Targets: []string{"example.com"}, MinPriority: "low"}
	return p, cfg
}

func TestPipelineReportsContentChange(t *testing.T) {
	const baseSim uint64 = 0xA5A5_A5A5_A5A5_A5A5
	const movedSim uint64 = 0x5A5A_5A5A_A5A5_A5A5 // 32 bits flipped from base

	sim := baseSim
	content := func(_ context.Context, _ []string) ([]model.ContentFingerprint, error) {
		return []model.ContentFingerprint{{Host: "a.example.com", Status: 200, SimHash: sim}}, nil
	}
	p, cfg := newContentPipeline(t, content)

	// Run 1: baseline — fingerprint saved, no CONTENT_CHANGE.
	r1, err := p.Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range r1.Changes {
		if c.Kind == diff.ContentChange {
			t.Fatalf("baseline run must not emit CONTENT_CHANGE, got %+v", c)
		}
	}

	// Run 2: the page's body content moved.
	sim = movedSim
	r2, err := p.Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	var found *diff.Change
	for i := range r2.Changes {
		if r2.Changes[i].Kind == diff.ContentChange {
			found = &r2.Changes[i]
		}
	}
	if found == nil {
		t.Fatalf("expected a CONTENT_CHANGE on run 2, got %+v", r2.Changes)
	}
	if found.Priority != diff.Medium {
		t.Errorf("a body move (not a come-online) should be Medium, got %d", found.Priority)
	}
	if found.Target != "example.com" {
		t.Errorf("target should resolve to in-scope root, got %q", found.Target)
	}
}

func TestPipelineSkipsContentForPassiveScope(t *testing.T) {
	called := false
	content := func(_ context.Context, _ []string) ([]model.ContentFingerprint, error) {
		called = true
		return nil, nil
	}
	p, cfg := newContentPipeline(t, content)
	cfg.Passive = true // content fetching is active traffic, so it must be skipped

	if _, err := p.Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Error("content fingerprinting must be skipped for passive scopes")
	}
}

func TestPipelineContentErrorDoesNotFailRun(t *testing.T) {
	content := func(_ context.Context, _ []string) ([]model.ContentFingerprint, error) {
		return nil, errors.New("httpx exploded")
	}
	p, cfg := newContentPipeline(t, content)

	res, err := p.Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("a content collector error must not fail the run: %v", err)
	}
	if res.ContentErr == nil {
		t.Error("content collector error should be recorded on the result")
	}
}

// A transient outage on run 2 (host fails to serve) must not fire a change and
// must not clobber the baseline, so run 3 still diffs against run 1's content.
func TestPipelineContentTransientOutageDoesNotClobber(t *testing.T) {
	const baseSim uint64 = 0xA5A5_A5A5_A5A5_A5A5
	const movedSim uint64 = 0x5A5A_5A5A_A5A5_A5A5

	step := 0
	content := func(_ context.Context, _ []string) ([]model.ContentFingerprint, error) {
		step++
		switch step {
		case 1: // baseline
			return []model.ContentFingerprint{{Host: "a.example.com", Status: 200, SimHash: baseSim}}, nil
		case 2: // transient: failed fetch (zero-value)
			return []model.ContentFingerprint{{Host: "a.example.com"}}, nil
		default: // genuine move
			return []model.ContentFingerprint{{Host: "a.example.com", Status: 200, SimHash: movedSim}}, nil
		}
	}
	p, cfg := newContentPipeline(t, content)

	if _, err := p.Run(context.Background(), cfg); err != nil { // baseline
		t.Fatal(err)
	}
	r2, err := p.Run(context.Background(), cfg) // transient outage
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range r2.Changes {
		if c.Kind == diff.ContentChange {
			t.Fatalf("a transient outage must not fire CONTENT_CHANGE, got %+v", c)
		}
	}
	r3, err := p.Run(context.Background(), cfg) // genuine move vs the preserved baseline
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, c := range r3.Changes {
		if c.Kind == diff.ContentChange {
			found = true
		}
	}
	if !found {
		t.Fatalf("run 3 should diff against the preserved baseline and report a CONTENT_CHANGE, got %+v", r3.Changes)
	}
}
