// Package runner wires the pipeline: discover -> probe -> store -> diff ->
// prioritize -> notify. Collectors are injected so the pipeline is testable
// without the external recon tools.
package runner

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/maruftak/reconsentry/internal/config"
	"github.com/maruftak/reconsentry/internal/diff"
	"github.com/maruftak/reconsentry/internal/model"
	"github.com/maruftak/reconsentry/internal/notify"
	"github.com/maruftak/reconsentry/internal/prioritize"
	"github.com/maruftak/reconsentry/internal/store"
	"github.com/maruftak/reconsentry/internal/takeover"
)

// DiscoverFunc finds hosts for the given root targets.
type DiscoverFunc func(ctx context.Context, targets []string) ([]string, error)

// ProbeFunc enriches hosts with liveness and metadata.
type ProbeFunc func(ctx context.Context, hosts []string) ([]model.Asset, error)

// ScanFunc scans newly-found hosts for vulnerabilities/exposures.
type ScanFunc func(ctx context.Context, hosts []string) ([]model.Finding, error)

// CrawlFunc crawls live hosts and returns the endpoints (URLs/params) found.
type CrawlFunc func(ctx context.Context, hosts []string) ([]model.Endpoint, error)

// CertFunc fetches TLS certificate expiry for the given hosts.
type CertFunc func(ctx context.Context, hosts []string) ([]model.CertInfo, error)

// TakeoverFunc probes hosts for subdomain-takeover signals (CNAME chain + body).
type TakeoverFunc func(ctx context.Context, hosts []string) ([]model.HostProbe, error)

// DNSFunc resolves CNAME/NS records for the given hosts.
type DNSFunc func(ctx context.Context, hosts []string) ([]model.DNSRecord, error)

// defaultCertDays is the expiry window used when CertDays is unset.
const defaultCertDays = 30

// Pipeline runs one monitoring cycle.
type Pipeline struct {
	Store     *store.Store
	Discover  DiscoverFunc
	Probe     ProbeFunc
	Scanner   ScanFunc          // optional; when set, newly-found hosts are scanned (run --scan-new)
	Crawler   CrawlFunc         // optional; when set, live hosts are crawled for endpoint changes (run --crawl)
	CertCheck CertFunc          // optional; when set, live hosts' TLS certs are checked for near expiry (run --cert-check)
	CertDays  int               // expiry window in days for CertCheck; <= 0 uses defaultCertDays
	Takeover  TakeoverFunc      // optional; when set, hosts are checked for subdomain-takeover risk (run --takeover)
	Resolver  takeover.Resolver // optional DNS resolver for takeover NXDOMAIN checks; nil uses the system resolver
	DNS       DNSFunc           // optional; when set, CNAME/NS records are tracked and changes reported (run --dns)
	Notifiers []notify.Notifier
	Keep      int              // if > 0, retain only the most recent Keep snapshots per scope
	MaxHosts  int              // if > 0, probe at most this many hosts per run (safety bound for huge scopes)
	Now       func() time.Time // injectable clock; defaults to time.Now
}

// Result summarizes one run.
type Result struct {
	RunID       int64
	Assets      []model.Asset
	Changes     []diff.Change
	Findings    []model.Finding
	Endpoints   []model.Endpoint
	FirstRun    bool
	Truncated   int // hosts dropped before probing by MaxHosts (0 = none)
	NotifyErrs  []error
	ScanErr     error
	CrawlErr    error
	CertErr     error
	TakeoverErr error
	DNSErr      error
	DNSRecords  []model.DNSRecord
}

// Run executes a single monitoring cycle for cfg.
func (p *Pipeline) Run(ctx context.Context, cfg *config.Config) (*Result, error) {
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}

	discovered, err := p.Discover(ctx, cfg.Targets)
	if err != nil {
		return nil, fmt.Errorf("discover: %w", err)
	}
	hosts := filterExcluded(dedupHosts(cfg.Targets, discovered), cfg)
	hosts, truncated := capHosts(cfg.Targets, hosts, p.MaxHosts)

	// Passive scopes (scan-forbidding programs) are monitored on discovery
	// alone: no httpx probe, so hosts are recorded not-alive and the diff is
	// limited to NEW_HOST / HOST_GONE. Active scanning and crawling are skipped
	// below for the same reason.
	var probed []model.Asset
	if !cfg.Passive {
		probed, err = p.Probe(ctx, hosts)
		if err != nil {
			// A cancelled context or a killed child usually means the probe
			// outran --timeout on a large surface; point the user at the levers.
			if ctx.Err() != nil || strings.Contains(err.Error(), "killed") {
				return nil, fmt.Errorf("probe: probing %d hosts failed, likely exceeding --timeout; raise --timeout or set --max-hosts to bound very large scopes: %w", len(hosts), err)
			}
			return nil, fmt.Errorf("probe: %w", err)
		}
	}
	assets := reconcile(hosts, probed, cfg.Targets)

	prev, err := p.Store.LatestAssets(cfg.Name)
	if err != nil {
		return nil, err
	}
	firstRun := len(prev) == 0

	runID, err := p.Store.SaveRun(cfg.Name, now(), assets)
	if err != nil {
		return nil, err
	}
	if p.Keep > 0 {
		if err := p.Store.Prune(cfg.Name, p.Keep); err != nil {
			return nil, err
		}
	}

	res := &Result{RunID: runID, Assets: assets, FirstRun: firstRun, Truncated: truncated}

	var changes []diff.Change
	if !firstRun {
		changes = diff.Diff(prev, assets)
		if !cfg.TrackIP {
			changes = dropKind(changes, diff.IPChange)
		}
		if p.Scanner != nil && !cfg.Passive {
			if hosts := newlyFoundHosts(changes); len(hosts) > 0 {
				findings, err := p.Scanner(ctx, hosts)
				if err != nil {
					res.ScanErr = err
				} else {
					res.Findings = findings
					changes = append(changes, findingChanges(findings)...)
				}
			}
		}
	}

	// Crawling runs independently of the host-level firstRun: the first crawl is
	// a baseline (no endpoint diff), later crawls report NEW_ENDPOINT changes.
	// Skipped for passive scopes — crawling is active traffic.
	if p.Crawler != nil && !cfg.Passive {
		changes = append(changes, p.crawl(ctx, cfg, runID, assets, res)...)
	}

	// Cert checking is active TLS traffic, so it is skipped for passive scopes.
	// Expiry is evaluated against the live cert each run, independent of the
	// snapshot diff.
	if p.CertCheck != nil && !cfg.Passive {
		changes = append(changes, p.certCheck(ctx, cfg, assets, res, now())...)
	}

	// Takeover detection probes CNAME + body, so it is active traffic and
	// skipped for passive scopes. Evaluated against the live response each run.
	if p.Takeover != nil && !cfg.Passive {
		changes = append(changes, p.takeoverCheck(ctx, cfg, assets, res)...)
	}

	// DNS-record monitoring queries resolvers, not the target, so it is benign
	// passive recon and runs even for passive scopes. The first collection is a
	// baseline (no diff); later runs report DNS_CHANGE.
	if p.DNS != nil {
		changes = append(changes, p.dnsCheck(ctx, cfg, runID, assets, res)...)
	}

	// Promote bounty-likely new hosts (admin/staging/api/…) before filtering so
	// they survive a high min_priority and stand out in the alert.
	changes = prioritize.MarkInteresting(changes, cfg.Interesting)
	res.Changes = prioritize.Filter(changes, prioritize.Level(cfg.MinPriority))

	for _, n := range p.Notifiers {
		if err := n.Notify(ctx, cfg.Name, res.Changes); err != nil {
			res.NotifyErrs = append(res.NotifyErrs, err)
		}
	}
	return res, nil
}

// capHosts bounds the host list to max as a safety valve for pathologically
// large discoveries (where probing every host would outrun --timeout). Seed
// targets are always kept; the discovered remainder is capped deterministically
// (lowest hostnames first) so the same hosts are probed each run and the diff
// stays stable. Returns the capped list and how many hosts were dropped.
func capHosts(targets, hosts []string, max int) ([]string, int) {
	if max <= 0 || len(hosts) <= max {
		return hosts, 0
	}
	isSeed := make(map[string]bool, len(targets))
	for _, t := range targets {
		isSeed[t] = true
	}
	var seeds, extra []string
	for _, h := range hosts {
		if isSeed[h] {
			seeds = append(seeds, h)
		} else {
			extra = append(extra, h)
		}
	}
	sort.Strings(extra)
	room := max - len(seeds)
	if room < 0 {
		room = 0
	}
	dropped := 0
	if room < len(extra) {
		dropped = len(extra) - room
		extra = extra[:room]
	}
	return append(seeds, extra...), dropped
}

func filterExcluded(hosts []string, cfg *config.Config) []string {
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if !cfg.Excluded(h) {
			out = append(out, h)
		}
	}
	return out
}

// dropKind removes all changes of the given kind.
func dropKind(changes []diff.Change, k diff.Kind) []diff.Change {
	out := make([]diff.Change, 0, len(changes))
	for _, c := range changes {
		if c.Kind != k {
			out = append(out, c)
		}
	}
	return out
}

// newlyFoundHosts returns the hosts from NEW_HOST / HOST_LIVE changes — the
// hosts worth scanning when --scan-new is set.
func newlyFoundHosts(changes []diff.Change) []string {
	seen := make(map[string]bool)
	var hosts []string
	for _, c := range changes {
		if c.Kind != diff.NewHost && c.Kind != diff.HostLive {
			continue
		}
		if c.Host != "" && !seen[c.Host] {
			seen[c.Host] = true
			hosts = append(hosts, c.Host)
		}
	}
	return hosts
}

// findingChanges turns scanner findings into VULN_FOUND changes so they flow
// through prioritization and notification like any other change.
func findingChanges(findings []model.Finding) []diff.Change {
	out := make([]diff.Change, 0, len(findings))
	for _, f := range findings {
		out = append(out, diff.Change{
			Kind:     diff.VulnFound,
			Host:     f.Host,
			Detail:   fmt.Sprintf("%s: %s (%s)", strings.ToUpper(f.Severity), f.Name, f.TemplateID),
			Priority: severityPriority(f.Severity),
		})
	}
	return out
}

// severityPriority maps a nuclei severity to a change priority.
func severityPriority(sev string) int {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical", "high":
		return diff.High
	case "medium":
		return diff.Medium
	default: // low, info, unknown
		return diff.Low
	}
}

// dedupHosts merges seed targets with discovered hosts (targets are always
// monitored, even when discovery returns nothing) and removes duplicates.
func dedupHosts(targets, discovered []string) []string {
	all := append(append([]string{}, targets...), discovered...)
	seen := make(map[string]bool, len(all))
	out := make([]string, 0, len(all))
	for _, h := range all {
		h = strings.ToLower(model.TrimInvisible(h))
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	return out
}

// reconcile merges discovered hosts with probe results. Probed hosts are
// alive; discovered-but-unprobed hosts are recorded as not-alive so they can
// later transition to HOST_LIVE.
func reconcile(hosts []string, probed []model.Asset, targets []string) []model.Asset {
	byHost := make(map[string]model.Asset, len(probed)+len(hosts))
	for _, a := range probed {
		a.Target = matchTarget(a.Host, targets)
		byHost[a.Host] = a
	}
	for _, h := range hosts {
		if _, ok := byHost[h]; !ok {
			byHost[h] = model.Asset{Host: h, Target: matchTarget(h, targets)}
		}
	}
	out := make([]model.Asset, 0, len(byHost))
	for _, a := range byHost {
		out = append(out, a)
	}
	return out
}

// matchTarget returns the most specific in-scope root that host belongs to.
func matchTarget(host string, targets []string) string {
	best := ""
	for _, t := range targets {
		if host == t || strings.HasSuffix(host, "."+t) {
			if len(t) > len(best) {
				best = t
			}
		}
	}
	return best
}

// liveHosts returns the hostnames of assets that responded, as crawl targets.
func liveHosts(assets []model.Asset) []string {
	var hosts []string
	for _, a := range assets {
		if a.Alive {
			hosts = append(hosts, a.Host)
		}
	}
	return hosts
}

// crawl walks the live hosts, stores the endpoints, and returns NEW_ENDPOINT
// changes against the previous crawl (none on the first crawl). Errors are
// recorded on res rather than failing the whole run.
func (p *Pipeline) crawl(ctx context.Context, cfg *config.Config, runID int64, assets []model.Asset, res *Result) []diff.Change {
	prevEndpoints, err := p.Store.LatestEndpoints(cfg.Name)
	if err != nil {
		res.CrawlErr = err
		return nil
	}
	eps, err := p.Crawler(ctx, liveHosts(assets))
	if err != nil {
		res.CrawlErr = err
		return nil
	}
	for i := range eps {
		eps[i].Target = matchTarget(eps[i].Host, cfg.Targets)
	}
	res.Endpoints = eps
	if err := p.Store.SaveEndpoints(runID, cfg.Name, eps); err != nil {
		res.CrawlErr = err
		return nil
	}
	if len(prevEndpoints) == 0 {
		return nil // first crawl is a baseline
	}
	return diff.DiffEndpoints(prevEndpoints, eps)
}

// certCheck fetches TLS cert expiry for the live hosts and returns
// CERT_EXPIRING changes for any cert within the configured window. Errors are
// recorded on res rather than failing the run.
func (p *Pipeline) certCheck(ctx context.Context, cfg *config.Config, assets []model.Asset, res *Result, now time.Time) []diff.Change {
	infos, err := p.CertCheck(ctx, liveHosts(assets))
	if err != nil {
		res.CertErr = err
		return nil
	}
	days := p.CertDays
	if days <= 0 {
		days = defaultCertDays
	}
	changes := certExpiringChanges(infos, days, now)
	for i := range changes {
		changes[i].Target = matchTarget(changes[i].Host, cfg.Targets)
	}
	return changes
}

// takeoverCheck probes every host (alive or not — a dangling pointer is often
// "dead") for subdomain-takeover signals and returns a TAKEOVER_RISK change per
// finding. Errors are recorded on res rather than failing the whole run.
func (p *Pipeline) takeoverCheck(ctx context.Context, cfg *config.Config, assets []model.Asset, res *Result) []diff.Change {
	probes, err := p.Takeover(ctx, allHosts(assets))
	if err != nil {
		res.TakeoverErr = err
		return nil
	}
	resolver := p.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	findings := takeover.Detect(ctx, probes, resolver)
	changes := make([]diff.Change, 0, len(findings))
	for _, f := range findings {
		changes = append(changes, diff.Change{
			Kind:     diff.TakeoverRisk,
			Target:   matchTarget(f.Host, cfg.Targets),
			Host:     f.Host,
			Detail:   f.Detail,
			Priority: takeoverPriority(f),
		})
	}
	return changes
}

// dnsCheck collects CNAME/NS records for every host, persists them, and returns
// DNS_CHANGE changes against the previous DNS collection (none on the first).
// Errors are recorded on res rather than failing the run.
func (p *Pipeline) dnsCheck(ctx context.Context, cfg *config.Config, runID int64, assets []model.Asset, res *Result) []diff.Change {
	prev, err := p.Store.LatestDNSRecords(cfg.Name)
	if err != nil {
		res.DNSErr = err
		return nil
	}
	recs, err := p.DNS(ctx, allHosts(assets))
	if err != nil {
		res.DNSErr = err
		return nil
	}
	res.DNSRecords = recs
	if err := p.Store.SaveDNSRecords(runID, cfg.Name, recs); err != nil {
		res.DNSErr = err
		return nil
	}
	if len(prev) == 0 {
		return nil // first collection is a baseline
	}
	changes := diff.DiffDNS(prev, recs)
	for i := range changes {
		changes[i].Target = matchTarget(changes[i].Host, cfg.Targets)
	}
	return changes
}

// takeoverPriority maps a finding to a change priority: a claimable service at
// high confidence is Critical; a claimable low-confidence (fingerprint-only)
// match is High pending manual confirmation; a merely-parked pointer is Low
// (informational).
func takeoverPriority(f model.TakeoverFinding) int {
	if !f.Vulnerable {
		return diff.Low
	}
	if f.Confidence == "high" {
		return diff.Critical
	}
	return diff.High
}

// allHosts returns every asset's host, deduplicated, so takeover detection can
// inspect hosts that are not currently alive.
func allHosts(assets []model.Asset) []string {
	seen := make(map[string]bool, len(assets))
	out := make([]string, 0, len(assets))
	for _, a := range assets {
		if a.Host == "" || seen[a.Host] {
			continue
		}
		seen[a.Host] = true
		out = append(out, a.Host)
	}
	return out
}

// certExpiringChanges returns a CERT_EXPIRING change for each cert that is
// already expired or expires within `days`. Pure so it can be unit-tested.
func certExpiringChanges(infos []model.CertInfo, days int, now time.Time) []diff.Change {
	cutoff := now.AddDate(0, 0, days)
	var changes []diff.Change
	for _, info := range infos {
		if info.Expiry.After(cutoff) {
			continue
		}
		var detail string
		if info.Expiry.Before(now) {
			detail = fmt.Sprintf("TLS certificate expired on %s", info.Expiry.Format("2006-01-02"))
		} else {
			remaining := int(info.Expiry.Sub(now).Hours()/24 + 0.5)
			detail = fmt.Sprintf("TLS certificate expires in %d day(s) on %s", remaining, info.Expiry.Format("2006-01-02"))
		}
		changes = append(changes, diff.Change{
			Kind:     diff.CertExpiring,
			Host:     info.Host,
			Detail:   detail,
			Priority: diff.High,
		})
	}
	return changes
}
