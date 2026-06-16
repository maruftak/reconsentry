// Package diff compares two attack-surface snapshots and classifies the
// changes between them. Diff is a pure function (no I/O) so it can be
// exhaustively unit-tested.
package diff

import (
	"fmt"
	"sort"

	"github.com/maruftak/reconsentry/internal/model"
)

// Kind identifies a category of change.
type Kind string

const (
	NewHost      Kind = "NEW_HOST"
	HostLive     Kind = "HOST_LIVE"
	StatusChange Kind = "STATUS_CHANGE"
	IPChange     Kind = "IP_CHANGE"
	NewTech      Kind = "NEW_TECH"
	HostGone     Kind = "HOST_GONE"
	VulnFound    Kind = "VULN_FOUND"    // a finding from scanning a newly-discovered host
	NewEndpoint  Kind = "NEW_ENDPOINT"  // a URL/param seen for the first time
	CertExpiring Kind = "CERT_EXPIRING" // a host's TLS certificate is near expiry
	TakeoverRisk Kind = "TAKEOVER_RISK" // a host's dangling DNS record may be claimable (subdomain takeover)
	DNSChange    Kind = "DNS_CHANGE"    // a host's CNAME or NS record set changed
	MXChange     Kind = "MX_CHANGE"     // a host's MX (mail-flow) record set changed
	TXTChange    Kind = "TXT_CHANGE"    // a host's TXT record set changed (SPF/DMARC/SaaS-verification)
	HotTarget    Kind = "HOT_TARGET"    // multiple distinct change kinds co-occurred on one host (opt-in via --correlate)
)

// Priority levels (higher = more interesting to a hunter). Critical is reserved
// for findings that are exploitable right now — a claimable subdomain takeover —
// so they sort above and survive any min_priority filter.
const (
	Low      = 1
	Medium   = 2
	High     = 3
	Critical = 4
)

var defaultPriority = map[Kind]int{
	NewHost:      High,
	HostLive:     High,
	StatusChange: Medium,
	IPChange:     Low,
	NewTech:      Low,
	HostGone:     Low,
	VulnFound:    High, // fallback; runner sets priority per finding severity
	NewEndpoint:  Medium,
	CertExpiring: High,
	TakeoverRisk: Critical, // fallback; runner sets priority per finding confidence
	DNSChange:    Medium,   // fallback; DiffDNS sets High for NS (delegation) changes
	MXChange:     Medium,   // a mail-flow change
	TXTChange:    Low,      // fallback; DiffDNS sets High when SPF/DMARC posture weakens
	HotTarget:    High,     // fallback; correlate sets Critical when a contributing signal is critical
}

// Change is a single classified difference between snapshots.
type Change struct {
	Kind     Kind        `json:"kind"`
	Target   string      `json:"target"`
	Host     string      `json:"host"`
	Detail   string      `json:"detail"`
	Priority int         `json:"priority"`
	Asset    model.Asset `json:"asset"`
}

// Diff compares a previous and current asset set for the same scope and
// returns classified changes, deterministically ordered (priority desc,
// then host, then kind).
func Diff(prev, curr []model.Asset) []Change {
	prevByHost := indexByHost(prev)
	currByHost := indexByHost(curr)

	var changes []Change

	for host, c := range currByHost {
		p, existed := prevByHost[host]
		if !existed {
			detail := "new host discovered"
			if c.Alive {
				detail = fmt.Sprintf("new live host [%d %s]", c.Status, c.TechString())
			}
			changes = append(changes, newChange(NewHost, c, detail))
			continue
		}
		if !p.Alive && c.Alive {
			changes = append(changes, newChange(HostLive, c,
				fmt.Sprintf("host came alive [%d %s]", c.Status, c.TechString())))
		}
		if p.Status != 0 && c.Status != 0 && p.Status != c.Status {
			changes = append(changes, newChange(StatusChange, c,
				fmt.Sprintf("status %d -> %d", p.Status, c.Status)))
		}
		if p.IP != "" && c.IP != "" && p.IP != c.IP {
			changes = append(changes, newChange(IPChange, c,
				fmt.Sprintf("ip %s -> %s", p.IP, c.IP)))
		}
		if added := addedTech(p.Tech, c.Tech); len(added) > 0 {
			changes = append(changes, newChange(NewTech, c,
				fmt.Sprintf("new tech: %v", added)))
		}
	}

	for host, p := range prevByHost {
		if _, ok := currByHost[host]; !ok {
			changes = append(changes, newChange(HostGone, p, "host no longer resolves/responds"))
		}
	}

	sortChanges(changes)
	return changes
}

func newChange(k Kind, a model.Asset, detail string) Change {
	return Change{
		Kind:     k,
		Target:   a.Target,
		Host:     a.Host,
		Detail:   detail,
		Priority: defaultPriority[k],
		Asset:    a,
	}
}

func indexByHost(assets []model.Asset) map[string]model.Asset {
	m := make(map[string]model.Asset, len(assets))
	for _, a := range assets {
		m[a.Host] = a
	}
	return m
}

// addedTech returns tech present in curr but not prev, sorted.
func addedTech(prev, curr []string) []string {
	seen := make(map[string]bool, len(prev))
	for _, t := range prev {
		seen[t] = true
	}
	var added []string
	for _, t := range curr {
		if !seen[t] {
			added = append(added, t)
		}
	}
	sort.Strings(added)
	return added
}

func sortChanges(c []Change) {
	sort.SliceStable(c, func(i, j int) bool {
		if c[i].Priority != c[j].Priority {
			return c[i].Priority > c[j].Priority
		}
		if c[i].Host != c[j].Host {
			return c[i].Host < c[j].Host
		}
		return c[i].Kind < c[j].Kind
	})
}

// dnsKey identifies a per-host, per-type record set being diffed.
type dnsKey struct{ host, typ string }

// DiffDNS compares previous and current DNS record sets (same scope) and returns
// a change per host+type whose value set changed. Pure function.
//
//   - CNAME/NS → DNS_CHANGE. NS (a zone-delegation change — a hijack/takeover
//     signal) is High; CNAME (an infra move that can precede a takeover) is Medium.
//   - MX → MX_CHANGE (Medium): a mail-flow change.
//   - TXT → TXT_CHANGE (Low), escalated to High when the change weakens email
//     authentication — an SPF record removed or its `all` qualifier softened, or
//     (for the _dmarc.<host> name) the DMARC record removed or its `p=` policy
//     softened. See dns_posture.go.
func DiffDNS(prev, curr []model.DNSRecord) []Change {
	index := func(recs []model.DNSRecord) map[dnsKey]map[string]bool {
		m := map[dnsKey]map[string]bool{}
		for _, r := range recs {
			k := dnsKey{r.Host, r.Type}
			if m[k] == nil {
				m[k] = map[string]bool{}
			}
			m[k][r.Value] = true
		}
		return m
	}
	prevIdx, currIdx := index(prev), index(curr)

	seen := map[dnsKey]bool{}
	var keys []dnsKey
	for k := range prevIdx {
		seen[k] = true
		keys = append(keys, k)
	}
	for k := range currIdx {
		if !seen[k] {
			keys = append(keys, k)
		}
	}

	var changes []Change
	for _, k := range keys {
		added := setDiff(currIdx[k], prevIdx[k])
		removed := setDiff(prevIdx[k], currIdx[k])
		if len(added) == 0 && len(removed) == 0 {
			continue
		}
		changes = append(changes, dnsChange(k, added, removed, prevIdx[k], currIdx[k]))
	}
	sortChanges(changes)
	return changes
}

// dnsChange builds the Change for one changed record set, selecting the kind,
// priority, and detail by record type. prevVals/currVals are the full value
// sets (not just the delta) so TXT posture can be evaluated.
func dnsChange(k dnsKey, added, removed []string, prevVals, currVals map[string]bool) Change {
	switch k.typ {
	case "MX":
		return Change{Kind: MXChange, Host: k.host, Detail: dnsDetail(k.typ, added, removed), Priority: Medium}
	case "TXT":
		prio, note := txtPosture(k.host, prevVals, currVals)
		detail := dnsDetail(k.typ, added, removed)
		if note != "" {
			detail += " — " + note
		}
		return Change{Kind: TXTChange, Host: k.host, Detail: detail, Priority: prio}
	default: // CNAME, NS
		return Change{Kind: DNSChange, Host: k.host, Detail: dnsDetail(k.typ, added, removed), Priority: dnsPriority(k.typ)}
	}
}

// setDiff returns the sorted members of a that are absent from b.
func setDiff(a, b map[string]bool) []string {
	var out []string
	for v := range a {
		if !b[v] {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

func dnsDetail(typ string, added, removed []string) string {
	// A clean one-for-one swap (typical for CNAME) reads as "old → new".
	if len(added) == 1 && len(removed) == 1 {
		return fmt.Sprintf("%s %s → %s", typ, removed[0], added[0])
	}
	parts := typ
	for _, v := range added {
		parts += " +" + v
	}
	for _, v := range removed {
		parts += " -" + v
	}
	return parts
}

func dnsPriority(typ string) int {
	if typ == "NS" {
		return High
	}
	return Medium
}

// DiffEndpoints compares previous and current endpoint sets (same scope) and
// returns a NEW_ENDPOINT change for each URL not seen before. Pure function.
func DiffEndpoints(prev, curr []model.Endpoint) []Change {
	seen := make(map[string]bool, len(prev))
	for _, e := range prev {
		seen[e.URL] = true
	}
	var changes []Change
	for _, e := range curr {
		if seen[e.URL] {
			continue
		}
		seen[e.URL] = true // also de-dupes within curr
		changes = append(changes, Change{
			Kind:     NewEndpoint,
			Target:   e.Target,
			Host:     e.Host,
			Detail:   e.URL,
			Priority: defaultPriority[NewEndpoint],
		})
	}
	sortChanges(changes)
	return changes
}
