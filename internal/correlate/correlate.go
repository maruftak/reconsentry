// Package correlate fuses a run's individual change events into composite
// "hot target" findings. Each change kind (NEW_HOST, NEW_TECH, DNS_CHANGE, …)
// already alerts on its own, but the signal a human can't eyeball across many
// hosts is when SEVERAL distinct kinds co-occur on the SAME host in one run —
// that means the target is actively moving (a migration, a launch, a soft
// target). Correlate detects that and emits one high-confidence HOT_TARGET
// change per qualifying host.
//
// It is pure post-processing of changes already computed in a run: no network,
// no scanning, no I/O, fully deterministic. It never removes or mutates the
// originals — it only appends.
package correlate

import (
	"fmt"
	"sort"
	"strings"

	"github.com/maruftak/reconsentry/internal/diff"
	"github.com/maruftak/reconsentry/internal/prioritize"
)

// Per-kind correlation weights. Higher = a stronger indication on its own that
// the host is in motion. A claimable takeover dominates; routine churn (a new
// tech fingerprint, a status flip) contributes little.
const (
	weightTakeoverRisk  = 4
	weightDNSChange     = 3
	weightContentChange = 3
	weightNewHost       = 2
	weightHostLive      = 2
	weightMXChange      = 2
	weightTXTChange     = 2
	weightNewTech       = 1
	weightStatusChange  = 1
	weightCertExpiring  = 1
	weightIPChange      = 1
	weightHostGone      = 1
)

// interestingBoost is added to a host's score when its name matches the
// interesting-keyword heuristic (admin/staging/api/vpn/jenkins/…). A
// bounty-likely asset in motion is worth surfacing on weaker evidence.
const interestingBoost = 2

// Defaults for Options.
const (
	defaultThreshold   = 4 // minimum weighted score to fuse
	defaultMinDistinct = 2 // genuinely correlated: never fuse a single loud signal
)

// weights maps each change kind to its correlation weight. A kind absent from
// the map (e.g. HOT_TARGET itself, VULN_FOUND, NEW_ENDPOINT) contributes 0 and
// is ignored as a contributing signal.
var weights = map[diff.Kind]int{
	diff.TakeoverRisk:  weightTakeoverRisk,
	diff.DNSChange:     weightDNSChange,
	diff.ContentChange: weightContentChange,
	diff.NewHost:       weightNewHost,
	diff.HostLive:      weightHostLive,
	diff.MXChange:      weightMXChange,
	diff.TXTChange:     weightTXTChange,
	diff.NewTech:       weightNewTech,
	diff.StatusChange:  weightStatusChange,
	diff.CertExpiring:  weightCertExpiring,
	diff.IPChange:      weightIPChange,
	diff.HostGone:      weightHostGone,
}

// Options tunes the correlation. The zero value uses the documented defaults.
type Options struct {
	// Threshold is the minimum weighted score (including any interesting boost)
	// for a host to be fused into a HOT_TARGET. <= 0 uses defaultThreshold.
	Threshold int
	// MinDistinctKinds is the minimum number of distinct contributing change
	// kinds required. <= 0 uses defaultMinDistinct (2). The >= 2 rule is what
	// makes a finding genuinely correlated rather than one loud signal that
	// already alerts on its own.
	MinDistinctKinds int
	// Interesting is the keyword list for the interesting-host booster. Empty
	// falls back to prioritize.DefaultInteresting, the same set the monitor
	// uses to highlight bounty-likely hosts.
	Interesting []string
}

func (o Options) threshold() int {
	if o.Threshold <= 0 {
		return defaultThreshold
	}
	return o.Threshold
}

func (o Options) minDistinct() int {
	if o.MinDistinctKinds <= 0 {
		return defaultMinDistinct
	}
	return o.MinDistinctKinds
}

// Correlate returns ADDITIONAL composite findings — one HOT_TARGET per host on
// which two or more distinct contributing change kinds co-occur and whose
// weighted score meets the threshold. It does not return or modify the input
// changes; the caller appends the result to its change set. Output is
// deterministic and sorted (priority desc, then host) so alerts are stable.
func Correlate(changes []diff.Change, opts Options) []diff.Change {
	byHost := groupByHost(changes)

	hosts := make([]string, 0, len(byHost))
	for h := range byHost {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	out := make([]diff.Change, 0, len(hosts))
	for _, host := range hosts {
		if finding, ok := correlateHost(host, byHost[host], opts); ok {
			out = append(out, finding)
		}
	}
	sortFindings(out)
	return out
}

// hostChanges accumulates one host's contributing changes during grouping.
type hostChanges struct {
	target  string
	changes []diff.Change
}

// groupByHost buckets changes by host, ignoring hostless changes (they cannot
// be correlated to a single asset) and kinds with no correlation weight.
func groupByHost(changes []diff.Change) map[string]hostChanges {
	m := map[string]hostChanges{}
	for _, c := range changes {
		if c.Host == "" {
			continue
		}
		if _, weighted := weights[c.Kind]; !weighted {
			continue
		}
		hc := m[c.Host]
		if hc.target == "" {
			hc.target = c.Target
		}
		hc.changes = append(hc.changes, c)
		m[c.Host] = hc
	}
	return m
}

// correlateHost evaluates one host's changes and, if they qualify, returns its
// HOT_TARGET finding. The bool is false when the host does not cross both the
// distinct-kind and score thresholds.
func correlateHost(host string, hc hostChanges, opts Options) (diff.Change, bool) {
	kinds := distinctKinds(hc.changes)
	score := 0
	for _, k := range kinds {
		score += weights[k]
	}

	hit := prioritize.InterestingMatch(host, opts.Interesting)
	if hit != "" {
		score += interestingBoost
	}

	if len(kinds) < opts.minDistinct() || score < opts.threshold() {
		return diff.Change{}, false
	}

	return diff.Change{
		Kind:     diff.HotTarget,
		Target:   hc.target,
		Host:     host,
		Detail:   detail(kinds, hc.changes, hit),
		Priority: fusedPriority(hc.changes),
	}, true
}

// distinctKinds returns the sorted set of contributing change kinds on a host.
// Sorting makes the score, count, and detail string deterministic regardless of
// input order.
func distinctKinds(changes []diff.Change) []diff.Kind {
	seen := map[diff.Kind]bool{}
	var out []diff.Kind
	for _, c := range changes {
		if seen[c.Kind] {
			continue
		}
		seen[c.Kind] = true
		out = append(out, c.Kind)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// fusedPriority is Critical when any contributing change is already critical
// (e.g. a high-confidence takeover), else High. A correlated host is never
// below High — that is the point of fusing it.
func fusedPriority(changes []diff.Change) int {
	for _, c := range changes {
		if c.Priority >= diff.Critical {
			return diff.Critical
		}
	}
	return diff.High
}

// detail renders the recommendation string, e.g.
//
//	3 correlated signals: NEW_HOST · NEW_TECH (Jenkins) · interesting:staging — target likely shipping, prioritize
//
// The signal list is built from the sorted distinct kinds (so it is stable),
// annotating NEW_TECH with the technology it introduced when available, and the
// interesting hit (if any) is appended as a final pseudo-signal.
func detail(kinds []diff.Kind, changes []diff.Change, interestingHit string) string {
	parts := make([]string, 0, len(kinds)+1)
	for _, k := range kinds {
		parts = append(parts, signalLabel(k, changes))
	}
	if interestingHit != "" {
		parts = append(parts, "interesting:"+interestingHit)
	}
	n := len(kinds)
	if interestingHit != "" {
		n++
	}
	return fmt.Sprintf("%d correlated signals: %s — target likely shipping, prioritize",
		n, strings.Join(parts, " · "))
}

// signalLabel renders one contributing kind, annotating NEW_TECH with the
// technology names it introduced (parsed from the diff's "new tech: [...]"
// detail) so the alert says *what* showed up, not just that something did.
func signalLabel(k diff.Kind, changes []diff.Change) string {
	label := string(k)
	if k == diff.NewTech {
		if tech := techNames(changes); tech != "" {
			label += " (" + tech + ")"
		}
	}
	return label
}

// techNames extracts a readable technology list from the NEW_TECH change detail
// (formatted by diff.Diff as "new tech: [Foo Bar]"). Returns "" when no tech can
// be parsed, so the label degrades gracefully.
func techNames(changes []diff.Change) string {
	for _, c := range changes {
		if c.Kind != diff.NewTech {
			continue
		}
		open := strings.Index(c.Detail, "[")
		closeIdx := strings.LastIndex(c.Detail, "]")
		if open >= 0 && closeIdx > open {
			inner := strings.TrimSpace(c.Detail[open+1 : closeIdx])
			if inner != "" {
				return inner
			}
		}
	}
	return ""
}

// sortFindings orders findings deterministically: priority desc, then host.
func sortFindings(c []diff.Change) {
	sort.SliceStable(c, func(i, j int) bool {
		if c[i].Priority != c[j].Priority {
			return c[i].Priority > c[j].Priority
		}
		return c[i].Host < c[j].Host
	})
}
