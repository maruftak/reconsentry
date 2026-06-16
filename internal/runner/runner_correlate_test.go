package runner

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/maruftak/reconsentry/internal/config"
	"github.com/maruftak/reconsentry/internal/diff"
	"github.com/maruftak/reconsentry/internal/model"
	"github.com/maruftak/reconsentry/internal/store"
)

// hotTarget returns the HOT_TARGET change for host, if any.
func hotTarget(changes []diff.Change, host string) (diff.Change, bool) {
	for _, c := range changes {
		if c.Kind == diff.HotTarget && c.Host == host {
			return c, true
		}
	}
	return diff.Change{}, false
}

// TestPipelineCorrelateWiring drives two runs so an existing host accumulates
// two distinct co-occurring change kinds (STATUS_CHANGE + NEW_TECH). On an
// "interesting" hostname the +2 booster carries it over the threshold. With
// --correlate off, no HOT_TARGET is produced; with it on, exactly one is, and
// the originals still flow through.
func TestPipelineCorrelateWiring(t *testing.T) {
	run := func(correlate bool) []diff.Change {
		st, err := store.Open(filepath.Join(t.TempDir(), "p.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()

		cfg := &config.Config{Name: "prog", Targets: []string{"example.com"}, MinPriority: "low"}

		host := "staging.example.com"
		status := 200
		tech := []string{"nginx"}
		discover := func(_ context.Context, _ []string) ([]string, error) { return []string{host}, nil }
		probe := func(_ context.Context, h []string) ([]model.Asset, error) {
			out := make([]model.Asset, 0, len(h))
			for _, x := range h {
				out = append(out, model.Asset{Host: x, Alive: true, Status: status, Tech: tech})
			}
			return out, nil
		}
		p := &Pipeline{Store: st, Discover: discover, Probe: probe, Correlate: correlate}

		// Run 1: baseline (no diff).
		if _, err := p.Run(context.Background(), cfg); err != nil {
			t.Fatal(err)
		}
		// Run 2: same host, status flips AND a new tech appears.
		status = 302
		tech = []string{"nginx", "Jenkins"}
		r2, err := p.Run(context.Background(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		return r2.Changes
	}

	t.Run("off by default", func(t *testing.T) {
		changes := run(false)
		if _, ok := hotTarget(changes, "staging.example.com"); ok {
			t.Errorf("HOT_TARGET must not appear when --correlate is off: %+v", changes)
		}
	})

	t.Run("on emits one HOT_TARGET and keeps originals", func(t *testing.T) {
		changes := run(true)
		ht, ok := hotTarget(changes, "staging.example.com")
		if !ok {
			t.Fatalf("expected a HOT_TARGET for staging.example.com, got %+v", changes)
		}
		// STATUS_CHANGE + NEW_TECH = 2 + interesting boost(2) = 4, no critical -> high.
		if ht.Priority != diff.High {
			t.Errorf("HOT_TARGET priority = %d, want High", ht.Priority)
		}
		if ht.Target != "example.com" {
			t.Errorf("HOT_TARGET target = %q, want example.com (inherited from contributing changes)", ht.Target)
		}
		// The originals must still be present (correlation appends, never replaces).
		var sawStatus, sawTech bool
		for _, c := range changes {
			switch c.Kind {
			case diff.StatusChange:
				sawStatus = true
			case diff.NewTech:
				sawTech = true
			}
		}
		if !sawStatus || !sawTech {
			t.Errorf("contributing changes must survive alongside HOT_TARGET, got %+v", changes)
		}
	})
}
