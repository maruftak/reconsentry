package mcpserver

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/maruftak/reconsentry/internal/diff"
	"github.com/maruftak/reconsentry/internal/model"
	"github.com/maruftak/reconsentry/internal/store"
)

// seed builds a temp store with one scope ("acme") carrying two runs so the
// diff-backed tools have a "latest vs previous" to compute, plus a second
// single-run scope ("beta") to exercise scope selection. It returns a read-only
// handle, matching how the MCP server opens the database in production.
func seed(t *testing.T) *store.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "seed.db")

	rw, err := store.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// acme run #1 (baseline).
	if _, err := rw.SaveRun("acme", t0, []model.Asset{
		{Target: "acme.com", Host: "www.acme.com", IP: "1.1.1.1", Alive: true, Status: 200, Tech: []string{"nginx"}},
		{Target: "acme.com", Host: "old.acme.com", Alive: true, Status: 200},
	}); err != nil {
		t.Fatalf("save acme run1: %v", err)
	}
	// acme run #2: new host appears, old host gone, www gains tech.
	if _, err := rw.SaveRun("acme", t0.Add(time.Hour), []model.Asset{
		{Target: "acme.com", Host: "www.acme.com", IP: "1.1.1.1", Alive: true, Status: 200, Tech: []string{"nginx", "php"}},
		{Target: "acme.com", Host: "admin.acme.com", IP: "2.2.2.2", Alive: true, Status: 200},
	}); err != nil {
		t.Fatalf("save acme run2: %v", err)
	}
	// beta: a single run only (no previous snapshot to diff against).
	if _, err := rw.SaveRun("beta", t0, []model.Asset{
		{Target: "beta.io", Host: "beta.io", Alive: false},
	}); err != nil {
		t.Fatalf("save beta: %v", err)
	}
	if err := rw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	ro, err := store.OpenReadOnly(path)
	if err != nil {
		t.Fatalf("open read-only: %v", err)
	}
	t.Cleanup(func() { _ = ro.Close() })
	return ro
}

func TestListScopes(t *testing.T) {
	st := seed(t)
	got, err := ListScopes(st)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "acme" || got[1] != "beta" {
		t.Fatalf("want [acme beta], got %v", got)
	}
}

func TestResolveScope(t *testing.T) {
	st := seed(t)
	// Explicit, present.
	if s, err := resolveScope(st, "acme"); err != nil || s != "acme" {
		t.Fatalf("explicit acme: got %q, %v", s, err)
	}
	// Explicit, absent -> error.
	if _, err := resolveScope(st, "ghost"); err == nil {
		t.Fatal("absent scope should error")
	}
	// Empty with multiple scopes -> error that lists them.
	if _, err := resolveScope(st, ""); err == nil {
		t.Fatal("empty scope with >1 scope should error")
	} else if !strings.Contains(err.Error(), "acme") {
		t.Errorf("error should name available scopes, got %q", err.Error())
	}
}

func TestResolveScopeSingle(t *testing.T) {
	// A single-scope DB lets the scope arg be omitted.
	path := filepath.Join(t.TempDir(), "one.db")
	rw, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rw.SaveRun("only", time.Now(), []model.Asset{{Host: "h.only.com"}}); err != nil {
		t.Fatal(err)
	}
	_ = rw.Close()
	st, err := store.OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if s, err := resolveScope(st, ""); err != nil || s != "only" {
		t.Fatalf("single-scope empty arg: got %q, %v", s, err)
	}
}

func TestListAssets(t *testing.T) {
	st := seed(t)

	got, err := ListAssets(st, "acme", "")
	if err != nil {
		t.Fatal(err)
	}
	// Latest snapshot of acme = www + admin (old is gone).
	if len(got.Assets) != 2 {
		t.Fatalf("want 2 latest assets, got %d (%+v)", len(got.Assets), got.Assets)
	}
	byHost := map[string]AssetView{}
	for _, a := range got.Assets {
		byHost[a.Host] = a
	}
	if _, ok := byHost["old.acme.com"]; ok {
		t.Error("old.acme.com should not be in the latest snapshot")
	}
	www := byHost["www.acme.com"]
	if !www.Alive || www.Status != 200 || www.IP != "1.1.1.1" || len(www.Technologies) != 2 {
		t.Errorf("www view wrong: %+v", www)
	}

	// Filter is a case-insensitive substring over the host.
	f, err := ListAssets(st, "acme", "ADMIN")
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Assets) != 1 || f.Assets[0].Host != "admin.acme.com" {
		t.Fatalf("filter ADMIN: want [admin.acme.com], got %+v", f.Assets)
	}

	// Absent scope -> error, not a panic.
	if _, err := ListAssets(st, "ghost", ""); err == nil {
		t.Error("ListAssets on absent scope should error")
	}
}

func TestListHistory(t *testing.T) {
	st := seed(t)

	got, err := ListHistory(st, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Runs) != 2 {
		t.Fatalf("want 2 runs, got %d", len(got.Runs))
	}
	// Most-recent first.
	if got.Runs[0].RunID <= got.Runs[1].RunID {
		t.Errorf("runs should be newest-first, got %d then %d", got.Runs[0].RunID, got.Runs[1].RunID)
	}
	// Newest run has 2 assets (www + admin).
	if got.Runs[0].AssetCount != 2 {
		t.Errorf("newest run asset count = %d, want 2", got.Runs[0].AssetCount)
	}

	if _, err := ListHistory(st, "ghost"); err == nil {
		t.Error("ListHistory on absent scope should error")
	}
}

func TestGetChangesDefault(t *testing.T) {
	st := seed(t)

	// Default: latest vs previous for acme.
	got, err := GetChanges(st, "acme", 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got.FromRunID >= got.ToRunID {
		t.Errorf("from should be older than to, got from=%d to=%d", got.FromRunID, got.ToRunID)
	}
	kinds := map[diff.Kind]bool{}
	for _, c := range got.Changes {
		kinds[c.Kind] = true
	}
	// admin.acme.com is new; old.acme.com is gone; www gains php tech.
	if !kinds[diff.NewHost] {
		t.Errorf("expected a NEW_HOST change, got kinds %v", kinds)
	}
	if !kinds[diff.HostGone] {
		t.Errorf("expected a HOST_GONE change, got kinds %v", kinds)
	}
	if !kinds[diff.NewTech] {
		t.Errorf("expected a NEW_TECH change, got kinds %v", kinds)
	}
}

func TestGetChangesMinPriority(t *testing.T) {
	st := seed(t)

	// min_priority=high must drop the low-priority NEW_TECH / HOST_GONE changes
	// but keep the High NEW_HOST.
	got, err := GetChanges(st, "acme", 0, 0, diff.High)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Changes) == 0 {
		t.Fatal("expected at least the NEW_HOST change at high priority")
	}
	for _, c := range got.Changes {
		if c.Priority < diff.High {
			t.Errorf("min_priority=high leaked a low change: %+v", c)
		}
	}
}

func TestGetChangesExplicitRuns(t *testing.T) {
	st := seed(t)

	hist, err := ListHistory(st, "acme")
	if err != nil {
		t.Fatal(err)
	}
	older := hist.Runs[1].RunID // baseline
	newer := hist.Runs[0].RunID // latest

	got, err := GetChanges(st, "acme", older, newer, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got.FromRunID != older || got.ToRunID != newer {
		t.Fatalf("explicit run ids not honoured: got from=%d to=%d", got.FromRunID, got.ToRunID)
	}

	// An unknown run id for the scope must error, not panic or silently empty.
	if _, err := GetChanges(st, "acme", 999999, newer, 0); err == nil {
		t.Error("unknown from run id should error")
	}
	if _, err := GetChanges(st, "acme", older, 999999, 0); err == nil {
		t.Error("unknown to run id should error")
	}
}

func TestGetChangesNeedsTwoRuns(t *testing.T) {
	st := seed(t)

	// beta has a single run, so a default diff cannot be computed.
	if _, err := GetChanges(st, "beta", 0, 0, 0); err == nil {
		t.Error("GetChanges with only one run should error clearly")
	}
}
