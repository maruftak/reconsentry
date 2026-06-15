// Package prioritize filters and orders changes so alerts carry signal, not noise.
package prioritize

import (
	"strings"

	"github.com/maruftak/reconsentry/internal/diff"
)

// Level converts a config priority string to a numeric threshold.
func Level(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "high":
		return diff.High
	case "medium":
		return diff.Medium
	default:
		return diff.Low
	}
}

// Filter keeps only changes at or above the minimum priority. The input order
// (set by diff.Diff: priority desc, then host) is preserved.
func Filter(changes []diff.Change, min int) []diff.Change {
	out := make([]diff.Change, 0, len(changes))
	for _, c := range changes {
		if c.Priority >= min {
			out = append(out, c)
		}
	}
	return out
}

// DefaultInteresting is the built-in set of hostname substrings that tend to
// flag a high-value, lightly-guarded asset to a hunter — admin panels, non-prod
// environments, internal tooling, and exposed infra. Used when a scope sets no
// `interesting:` list of its own.
var DefaultInteresting = []string{
	"admin", "staging", "stage", "dev", "test", "qa", "uat", "demo", "beta",
	"internal", "intranet", "corp", "vpn", "api", "dashboard", "portal", "console",
	"jenkins", "gitlab", "git", "jira", "grafana", "kibana", "prometheus", "phpmyadmin",
	"backup", "db", "sql", "ftp", "smtp", "mail", "ssh", "k8s", "kube", "ci", "build",
}

// MarkInteresting returns a copy of changes where any newly-discovered host
// (NEW_HOST / HOST_LIVE) whose name contains one of the keywords is promoted to
// high priority and tagged in its detail, so the bounty-likely asset surfaces
// above routine churn. It never lowers a priority. An empty keyword list falls
// back to DefaultInteresting.
func MarkInteresting(changes []diff.Change, keywords []string) []diff.Change {
	if len(keywords) == 0 {
		keywords = DefaultInteresting
	}
	out := make([]diff.Change, len(changes))
	copy(out, changes)
	for i := range out {
		c := &out[i]
		if c.Kind != diff.NewHost && c.Kind != diff.HostLive {
			continue
		}
		hit := matchKeyword(c.Host, keywords)
		if hit == "" {
			continue
		}
		if c.Priority < diff.High {
			c.Priority = diff.High
		}
		c.Detail = appendTag(c.Detail, "⭐ interesting: "+hit)
	}
	return out
}

func matchKeyword(host string, keywords []string) string {
	h := strings.ToLower(host)
	for _, k := range keywords {
		if k == "" {
			continue
		}
		if strings.Contains(h, k) {
			return k
		}
	}
	return ""
}

func appendTag(detail, tag string) string {
	if detail == "" {
		return tag
	}
	return detail + " — " + tag
}
