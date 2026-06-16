package diff

import (
	"fmt"
	"math/bits"

	"github.com/maruftak/reconsentry/internal/model"
)

// simhashHammingThreshold is the minimum number of differing bits between two
// 64-bit body simhashes for the body to count as *materially* changed. Below
// it, the difference is cosmetic noise (a rotated CSRF token, a timestamp, a
// nonce) that survived normalization; above it, the page content genuinely
// moved. 12/64 is a conservative cut — high enough that template churn does not
// trip it, low enough that a real re-platform or a new login form does.
const simhashHammingThreshold = 12

// DiffContent compares previous and current content fingerprints (same scope)
// and returns a CONTENT_CHANGE per host whose served page materially changed.
// Pure function.
//
// Only hosts present in BOTH snapshots are considered: a host new this run is a
// NEW_HOST (handled by Diff), and a host that vanished is HOST_GONE — neither is
// a content change. A current fingerprint that is a failed/empty fetch is
// skipped so a transient outage never alerts (and never clobbers the baseline).
//
// A change fires on any of:
//   - faviconFlipped — both favicon hashes present and different (a re-skin
//     often swaps the favicon first)
//   - bodyMoved — the body simhash moved more than simhashHammingThreshold bits
//   - cameOnline — the page crossed from a non-2xx status into 2xx (an app, a
//     login, or an admin panel appeared where an error page used to be)
//
// A title flip is only a corroborator: it is mentioned in the detail when it
// accompanies a real trigger, but never fires a change on its own (titles change
// for cosmetic reasons constantly). Priority is High when the page came online,
// else Medium. Output is deterministically ordered via sortChanges.
func DiffContent(prev, curr []model.ContentFingerprint) []Change {
	prevByHost := indexContent(prev)

	var changes []Change
	for _, c := range curr {
		p, existed := prevByHost[c.Host]
		if !existed {
			continue // new host this run -> NEW_HOST, not a content change
		}
		if isFailedFingerprint(c) {
			continue // transient outage / empty fetch: do not alert or clobber
		}

		faviconFlipped := c.FaviconHash != "" && p.FaviconHash != "" && c.FaviconHash != p.FaviconHash
		bodyMoved := p.SimHash != 0 && c.SimHash != 0 && hamming(p.SimHash, c.SimHash) > simhashHammingThreshold
		titleFlipped := c.TitleHash != "" && p.TitleHash != "" && c.TitleHash != p.TitleHash
		cameOnline := !in2xx(p.Status) && in2xx(c.Status)

		if !faviconFlipped && !bodyMoved && !cameOnline {
			continue // a lone title flip never triggers
		}

		prio := Medium
		if cameOnline {
			prio = High
		}
		changes = append(changes, Change{
			Kind:     ContentChange,
			Target:   c.Target,
			Host:     c.Host,
			Detail:   contentDetail(p, c, cameOnline, faviconFlipped, bodyMoved, titleFlipped),
			Priority: prio,
		})
	}
	sortChanges(changes)
	return changes
}

// contentDetail builds the human-readable reason a content change fired, in a
// fixed order so the alert is deterministic. Triggers come first (online,
// favicon, body), then the title corroborator is appended when present.
func contentDetail(prev, curr model.ContentFingerprint, cameOnline, faviconFlipped, bodyMoved, titleFlipped bool) string {
	var parts []string
	if cameOnline {
		parts = append(parts, fmt.Sprintf("page came online [%d → %d]", prev.Status, curr.Status))
	}
	if faviconFlipped {
		parts = append(parts, "favicon changed (re-platform)")
	}
	if bodyMoved {
		parts = append(parts, fmt.Sprintf("body content changed (simhash Δ%d/64)", hamming(prev.SimHash, curr.SimHash)))
	}
	detail := joinDetail(parts)
	if titleFlipped {
		detail += " + title changed"
	}
	return detail
}

// joinDetail joins the trigger parts with ", " (always at least one part, since
// DiffContent only calls it when a trigger fired).
func joinDetail(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ", "
		}
		out += p
	}
	return out
}

// isFailedFingerprint reports whether a fingerprint is an empty/failed fetch:
// no status, no body simhash, and no favicon. Such a current value is ignored
// so a transient outage does not fire a change or overwrite the baseline.
func isFailedFingerprint(c model.ContentFingerprint) bool {
	return c.Status == 0 && c.SimHash == 0 && c.FaviconHash == ""
}

// hamming returns the number of differing bits between two 64-bit simhashes.
func hamming(a, b uint64) int {
	return bits.OnesCount64(a ^ b)
}

// in2xx reports whether status is a 2xx success code.
func in2xx(status int) bool {
	return status >= 200 && status < 300
}

// indexContent maps fingerprints by host (last one wins on a dup host).
func indexContent(fps []model.ContentFingerprint) map[string]model.ContentFingerprint {
	m := make(map[string]model.ContentFingerprint, len(fps))
	for _, f := range fps {
		m[f.Host] = f
	}
	return m
}
