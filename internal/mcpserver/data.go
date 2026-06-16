// Package mcpserver exposes an already-collected snapshot database over the
// Model Context Protocol (MCP) so an AI agent can query a target's attack
// surface conversationally. It is strictly read-only: it never scans, probes,
// resolves, mutates, or writes — every tool is a pure read over the store,
// reusing the same store/diff logic as the CLI reporting commands.
//
// The data-fetch functions in this file are deliberately decoupled from the MCP
// SDK: each takes a *store.Store plus plain typed arguments and returns a
// structured result, so they are unit-testable without any protocol plumbing.
// server.go is the thin adapter that parses tool arguments and calls them.
package mcpserver

import (
	"fmt"
	"sort"
	"strings"

	"github.com/maruftak/reconsentry/internal/diff"
	"github.com/maruftak/reconsentry/internal/prioritize"
	"github.com/maruftak/reconsentry/internal/store"
)

// AssetView is the slim, stable JSON projection of a host in a snapshot. It
// drops the noisy embedded asset detail that diff.Change carries and exposes
// only the fields a hunter asks for conversationally.
type AssetView struct {
	Host         string   `json:"host"`
	Alive        bool     `json:"alive"`
	Status       int      `json:"status,omitempty"`
	IP           string   `json:"ip,omitempty"`
	Technologies []string `json:"technologies,omitempty"`
}

// AssetList is the result of list_assets.
type AssetList struct {
	Scope  string      `json:"scope"`
	Count  int         `json:"count"`
	Filter string      `json:"filter,omitempty"`
	Assets []AssetView `json:"assets"`
}

// RunView summarizes one recorded run for list_history.
type RunView struct {
	RunID      int64  `json:"run_id"`
	Timestamp  string `json:"timestamp"` // RFC3339, UTC
	AssetCount int    `json:"asset_count"`
}

// HistoryList is the result of list_history.
type HistoryList struct {
	Scope string    `json:"scope"`
	Count int       `json:"count"`
	Runs  []RunView `json:"runs"`
}

// ChangeView is the slim JSON projection of a single classified change.
type ChangeView struct {
	Kind     diff.Kind `json:"kind"`
	Host     string    `json:"host,omitempty"`
	Target   string    `json:"target,omitempty"`
	Priority int       `json:"priority"`
	Detail   string    `json:"detail"`
}

// ChangeSet is the result of get_changes.
type ChangeSet struct {
	Scope       string       `json:"scope"`
	FromRunID   int64        `json:"from_run_id"`
	ToRunID     int64        `json:"to_run_id"`
	MinPriority int          `json:"min_priority"`
	Count       int          `json:"count"`
	Changes     []ChangeView `json:"changes"`
}

// ListScopes returns the scope names present in the database, sorted.
func ListScopes(st *store.Store) ([]string, error) {
	scopes, err := st.Scopes()
	if err != nil {
		return nil, err
	}
	return scopes, nil
}

// resolveScope validates a requested scope against what the database actually
// holds. An explicit name must exist; an empty name is allowed only when the
// database contains exactly one scope (then it is selected automatically),
// otherwise the caller is told which scopes are available. This mirrors the
// CLI's pickScope behaviour but resolves against stored data, not a config.
func resolveScope(st *store.Store, name string) (string, error) {
	scopes, err := st.Scopes()
	if err != nil {
		return "", err
	}
	if len(scopes) == 0 {
		return "", fmt.Errorf("no scopes recorded in the database yet")
	}
	if name != "" {
		for _, s := range scopes {
			if s == name {
				return s, nil
			}
		}
		return "", fmt.Errorf("scope %q not found; available: %s", name, strings.Join(scopes, ", "))
	}
	if len(scopes) == 1 {
		return scopes[0], nil
	}
	return "", fmt.Errorf("database has %d scopes (%s); pass the scope argument to choose", len(scopes), strings.Join(scopes, ", "))
}

// ListAssets returns the latest-snapshot hosts for scope. filter, when
// non-empty, keeps only hosts whose name contains it (case-insensitive).
func ListAssets(st *store.Store, scope, filter string) (AssetList, error) {
	scope, err := resolveScope(st, scope)
	if err != nil {
		return AssetList{}, err
	}
	assets, err := st.LatestAssets(scope)
	if err != nil {
		return AssetList{}, err
	}
	needle := strings.ToLower(strings.TrimSpace(filter))
	views := make([]AssetView, 0, len(assets))
	for _, a := range assets {
		if needle != "" && !strings.Contains(strings.ToLower(a.Host), needle) {
			continue
		}
		views = append(views, AssetView{
			Host:         a.Host,
			Alive:        a.Alive,
			Status:       a.Status,
			IP:           a.IP,
			Technologies: a.Tech,
		})
	}
	sort.Slice(views, func(i, j int) bool { return views[i].Host < views[j].Host })
	return AssetList{Scope: scope, Count: len(views), Filter: filter, Assets: views}, nil
}

// ListHistory returns the recorded runs for scope, most recent first.
func ListHistory(st *store.Store, scope string) (HistoryList, error) {
	scope, err := resolveScope(st, scope)
	if err != nil {
		return HistoryList{}, err
	}
	runs, err := st.Runs(scope) // already newest-first
	if err != nil {
		return HistoryList{}, err
	}
	views := make([]RunView, 0, len(runs))
	for _, r := range runs {
		views = append(views, RunView{
			RunID:      r.ID,
			Timestamp:  r.StartedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
			AssetCount: r.Assets,
		})
	}
	return HistoryList{Scope: scope, Count: len(views), Runs: views}, nil
}

// GetChanges computes the classified changes for scope using the existing diff
// engine. With from==0 and to==0 it diffs the latest run against the previous
// one; otherwise both run ids must be supplied and must belong to scope. When
// minPriority > 0, only changes at or above that priority are returned (reusing
// prioritize.Filter, the same filter the monitor applies to alerts).
func GetChanges(st *store.Store, scope string, from, to int64, minPriority int) (ChangeSet, error) {
	scope, err := resolveScope(st, scope)
	if err != nil {
		return ChangeSet{}, err
	}
	runs, err := st.Runs(scope) // newest-first
	if err != nil {
		return ChangeSet{}, err
	}

	fromID, toID, err := resolveRunPair(scope, runs, from, to)
	if err != nil {
		return ChangeSet{}, err
	}

	fromAssets, err := st.AssetsForRun(fromID)
	if err != nil {
		return ChangeSet{}, err
	}
	toAssets, err := st.AssetsForRun(toID)
	if err != nil {
		return ChangeSet{}, err
	}

	changes := diff.Diff(fromAssets, toAssets)
	if minPriority > 0 {
		changes = prioritize.Filter(changes, minPriority)
	}

	views := make([]ChangeView, 0, len(changes))
	for _, c := range changes {
		views = append(views, ChangeView{
			Kind:     c.Kind,
			Host:     c.Host,
			Target:   c.Target,
			Priority: c.Priority,
			Detail:   c.Detail,
		})
	}
	return ChangeSet{
		Scope:       scope,
		FromRunID:   fromID,
		ToRunID:     toID,
		MinPriority: minPriority,
		Count:       len(views),
		Changes:     views,
	}, nil
}

// resolveRunPair picks the (from, to) run ids to diff. With both zero it uses
// the latest run as "to" and the previous as "from"; that requires at least two
// runs. When ids are given, both must exist for the scope.
func resolveRunPair(scope string, runs []store.RunInfo, from, to int64) (int64, int64, error) {
	if from == 0 && to == 0 {
		if len(runs) < 2 {
			return 0, 0, fmt.Errorf("scope %q has %d run(s); need at least 2 to compute changes (or run more snapshots)", scope, len(runs))
		}
		return runs[1].ID, runs[0].ID, nil // previous, latest
	}
	if from == 0 || to == 0 {
		return 0, 0, fmt.Errorf("provide both from and to run ids, or neither (to diff the latest two)")
	}
	valid := make(map[int64]bool, len(runs))
	for _, r := range runs {
		valid[r.ID] = true
	}
	if !valid[from] {
		return 0, 0, fmt.Errorf("from run id %d not found for scope %q", from, scope)
	}
	if !valid[to] {
		return 0, 0, fmt.Errorf("to run id %d not found for scope %q", to, scope)
	}
	return from, to, nil
}
