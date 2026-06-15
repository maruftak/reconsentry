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

func newDNSPipeline(t *testing.T, dns DNSFunc) (*Pipeline, *config.Config) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "d.db"))
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
	p := &Pipeline{Store: st, Discover: discover, Probe: probe, DNS: dns}
	cfg := &config.Config{Name: "prog", Targets: []string{"example.com"}, MinPriority: "low"}
	return p, cfg
}

func TestPipelineReportsDNSChange(t *testing.T) {
	records := []model.DNSRecord{{Host: "a.example.com", Type: "CNAME", Value: "old.svc"}}
	dns := func(_ context.Context, _ []string) ([]model.DNSRecord, error) { return records, nil }
	p, cfg := newDNSPipeline(t, dns)

	// Run 1: baseline — records saved, no DNS_CHANGE.
	r1, err := p.Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range r1.Changes {
		if c.Kind == diff.DNSChange {
			t.Fatalf("baseline run must not emit DNS_CHANGE, got %+v", c)
		}
	}

	// Run 2: the CNAME target moved.
	records = []model.DNSRecord{{Host: "a.example.com", Type: "CNAME", Value: "new.svc"}}
	r2, err := p.Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	var found *diff.Change
	for i := range r2.Changes {
		if r2.Changes[i].Kind == diff.DNSChange {
			found = &r2.Changes[i]
		}
	}
	if found == nil {
		t.Fatalf("expected a DNS_CHANGE on run 2, got %+v", r2.Changes)
	}
	if found.Detail != "CNAME old.svc → new.svc" {
		t.Errorf("detail: got %q", found.Detail)
	}
	if found.Target != "example.com" {
		t.Errorf("target should resolve to in-scope root, got %q", found.Target)
	}
}

func TestPipelineRunsDNSEvenForPassiveScope(t *testing.T) {
	called := false
	dns := func(_ context.Context, _ []string) ([]model.DNSRecord, error) {
		called = true
		return nil, nil
	}
	p, cfg := newDNSPipeline(t, dns)
	cfg.Passive = true // DNS resolution is benign recon, so it should still run

	if _, err := p.Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Error("DNS monitoring should run even for passive scopes")
	}
}

func TestPipelineDNSErrorDoesNotFailRun(t *testing.T) {
	dns := func(_ context.Context, _ []string) ([]model.DNSRecord, error) {
		return nil, errors.New("resolver down")
	}
	p, cfg := newDNSPipeline(t, dns)

	res, err := p.Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("a DNS collector error must not fail the run: %v", err)
	}
	if res.DNSErr == nil {
		t.Error("DNS collector error should be recorded on the result")
	}
}
