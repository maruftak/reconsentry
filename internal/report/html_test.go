package report

import (
	"strings"
	"testing"
	"time"

	"github.com/maruftak/reconsentry/internal/model"
)

func asset(host string, alive bool, status int, tech ...string) model.Asset {
	return model.Asset{Target: "example.com", Host: host, Alive: alive, Status: status, Tech: tech}
}

func TestHTMLEmpty(t *testing.T) {
	out, err := HTML(SurfaceReport{Scope: "empty-scope", GeneratedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "<!DOCTYPE html>") {
		t.Error("want a full HTML document")
	}
	if !strings.Contains(s, "No snapshots recorded yet") {
		t.Error("empty report should explain there is no data")
	}
	if !strings.Contains(s, "empty-scope") {
		t.Error("report should name the scope")
	}
}

func TestHTMLRendersSurfaceAndTimeline(t *testing.T) {
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	r := SurfaceReport{
		Scope:       "acme",
		GeneratedAt: base,
		ToolVersion: "reconsentry test",
		Snapshots: []RunSnapshot{
			{ID: 1, At: base, Assets: []model.Asset{asset("a.acme.com", true, 200, "nginx")}},
			{ID: 2, At: base.Add(time.Hour), Assets: []model.Asset{
				asset("a.acme.com", true, 200, "nginx"),
				asset("new.acme.com", true, 200, "Next.js"), // appears in run 2 -> NEW + NEW_HOST
			}},
		},
	}
	out, err := HTML(r)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)

	for _, want := range []string{
		"acme",              // scope
		"a.acme.com",        // surface host
		"new.acme.com",      // new host
		"NEW_HOST",          // changelog tag from the diff engine
		"Baseline recorded", // run 1 marked as baseline
		"NEW",               // badge on the freshly-seen host
		"Surface changelog",
		"Current surface",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("rendered report missing %q", want)
		}
	}

	// KPIs: 2 hosts, both live, 2 technologies, 2 runs.
	if !strings.Contains(s, ">2<") {
		t.Error("expected KPI counts in the output")
	}
}

func TestHTMLEscapesHostileInput(t *testing.T) {
	r := SurfaceReport{
		Scope:       "xss",
		GeneratedAt: time.Now(),
		Snapshots: []RunSnapshot{
			{ID: 1, At: time.Now(), Assets: []model.Asset{
				asset("<script>alert(1)</script>", true, 200, "<img src=x onerror=alert(1)>"),
			}},
		},
	}
	out, err := HTML(r)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "<script>alert(1)</script>") {
		t.Error("hostile host must be HTML-escaped, not emitted raw")
	}
	if strings.Contains(s, "<img src=x onerror=alert(1)>") {
		t.Error("hostile tech must be HTML-escaped, not emitted raw")
	}
	if !strings.Contains(s, "&lt;script&gt;") {
		t.Error("expected escaped entities in output")
	}
}

func TestHTMLMarksSurfaceSpike(t *testing.T) {
	base := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	// Three quiet runs (0-1 new host each), then a burst of 6 -> spike.
	mk := func(hosts ...string) []model.Asset {
		out := make([]model.Asset, 0, len(hosts))
		for _, h := range hosts {
			out = append(out, asset(h, true, 200))
		}
		return out
	}
	r := SurfaceReport{
		Scope:       "spiky",
		GeneratedAt: base,
		Snapshots: []RunSnapshot{
			{ID: 1, At: base, Assets: mk("a.com")},
			{ID: 2, At: base.Add(time.Hour), Assets: mk("a.com", "b.com")},
			{ID: 3, At: base.Add(2 * time.Hour), Assets: mk("a.com", "b.com")},
			{ID: 4, At: base.Add(3 * time.Hour), Assets: mk(
				"a.com", "b.com", "c.com", "d.com", "e.com", "f.com", "g.com", "h.com")},
		},
	}
	out, err := HTML(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "SURFACE SPIKE") {
		t.Error("expected the burst run to be flagged as a surface spike")
	}
}

func TestHTMLNoSpikeOnSteadySurface(t *testing.T) {
	base := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	r := SurfaceReport{
		Scope:       "steady",
		GeneratedAt: base,
		Snapshots: []RunSnapshot{
			{ID: 1, At: base, Assets: []model.Asset{asset("a.com", true, 200)}},
			{ID: 2, At: base.Add(time.Hour), Assets: []model.Asset{asset("a.com", true, 200), asset("b.com", true, 200)}},
		},
	}
	out, _ := HTML(r)
	if strings.Contains(string(out), "SURFACE SPIKE") {
		t.Error("a single new host should not be flagged as a spike")
	}
}

func TestHTMLTimelineNewestFirst(t *testing.T) {
	base := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	r := SurfaceReport{
		Scope:       "order",
		GeneratedAt: base,
		Snapshots: []RunSnapshot{
			{ID: 1, At: base, Assets: []model.Asset{asset("a.com", true, 200)}},
			{ID: 2, At: base.Add(time.Hour), Assets: []model.Asset{asset("a.com", true, 200), asset("b.com", true, 200)}},
		},
	}
	out, _ := HTML(r)
	s := string(out)
	i2 := strings.Index(s, "run #2")
	i1 := strings.Index(s, "run #1")
	if i2 < 0 || i1 < 0 || i2 > i1 {
		t.Errorf("timeline should list newest run first: idx run#2=%d run#1=%d", i2, i1)
	}
}
