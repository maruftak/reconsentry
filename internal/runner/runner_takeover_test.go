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

func newTakeoverPipeline(t *testing.T, takeover TakeoverFunc) (*Pipeline, *config.Config) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	discover := func(_ context.Context, _ []string) ([]string, error) {
		return []string{"app.example.com"}, nil
	}
	probe := func(_ context.Context, h []string) ([]model.Asset, error) {
		out := make([]model.Asset, 0, len(h))
		for _, x := range h {
			out = append(out, model.Asset{Host: x, Alive: true, Status: 404})
		}
		return out, nil
	}
	p := &Pipeline{Store: st, Discover: discover, Probe: probe, Takeover: takeover}
	// min_priority high proves a Critical takeover survives an aggressive filter.
	cfg := &config.Config{Name: "prog", Targets: []string{"example.com"}, MinPriority: "high"}
	return p, cfg
}

func TestPipelineReportsTakeoverRisk(t *testing.T) {
	takeover := func(_ context.Context, hosts []string) ([]model.HostProbe, error) {
		return []model.HostProbe{
			{Host: "app.example.com", CNAMEs: []string{"acme.ghost.io"}, Body: "Site unavailable"},
		}, nil
	}
	p, cfg := newTakeoverPipeline(t, takeover)

	res, err := p.Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res.TakeoverErr != nil {
		t.Fatalf("unexpected takeover error: %v", res.TakeoverErr)
	}

	var found *diff.Change
	for i := range res.Changes {
		if res.Changes[i].Kind == diff.TakeoverRisk {
			found = &res.Changes[i]
		}
	}
	if found == nil {
		t.Fatalf("expected a TAKEOVER_RISK change, got %+v", res.Changes)
	}
	if found.Priority != diff.Critical {
		t.Errorf("claimable high-confidence takeover should be Critical, got %d", found.Priority)
	}
	if found.Host != "app.example.com" {
		t.Errorf("host: got %q", found.Host)
	}
	if found.Target != "example.com" {
		t.Errorf("target should resolve to in-scope root, got %q", found.Target)
	}
}

func TestPipelineTakeoverErrorDoesNotFailRun(t *testing.T) {
	takeover := func(_ context.Context, _ []string) ([]model.HostProbe, error) {
		return nil, errors.New("httpx exploded")
	}
	p, cfg := newTakeoverPipeline(t, takeover)

	res, err := p.Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("a takeover collector error must not fail the run: %v", err)
	}
	if res.TakeoverErr == nil {
		t.Error("takeover collector error should be recorded on the result")
	}
}

func TestPipelineSkipsTakeoverForPassiveScope(t *testing.T) {
	called := false
	takeover := func(_ context.Context, _ []string) ([]model.HostProbe, error) {
		called = true
		return nil, nil
	}
	p, cfg := newTakeoverPipeline(t, takeover)
	cfg.Passive = true

	if _, err := p.Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Error("takeover detection must be skipped for passive scopes")
	}
}
