// Package takeover detects subdomain-takeover risk: a host whose dangling DNS
// record points at an unclaimed third-party service. Detection is a pure
// function over collected HostProbes plus an injected DNS resolver, so the full
// decision tree is exhaustively unit-tested without real network.
//
// It is deliberately conservative — a finding is a RISK INDICATOR requiring
// manual confirmation, never an assertion of compromise. See Fingerprints for
// the embedded service table and how claimable vs. merely-parked services are
// distinguished.
package takeover

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/maruftak/reconsentry/internal/model"
)

// Fingerprint describes a third-party hosting service whose dangling DNS record
// can signal a subdomain takeover.
type Fingerprint struct {
	Service    string   // human label, e.g. "GitHub Pages"
	CNAMEs     []string // CNAME suffixes that point at this service (no leading dot)
	Body       string   // verbatim "unclaimed" HTTP body string ("" => NXDOMAIN-only service)
	NXDOMAIN   bool     // signal is a dead CNAME target, not a body string
	Vulnerable bool     // service is claimable; false => merely parked, report as info
}

// Resolver looks up a host's addresses. It is injected so NXDOMAIN detection is
// testable without real DNS; *net.Resolver (e.g. net.DefaultResolver) satisfies
// it for production use.
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// Detect applies the embedded Fingerprints table to each probe and returns a
// finding per host that shows a takeover signal, ordered by host. It is
// deterministic given resolver.
func Detect(ctx context.Context, probes []model.HostProbe, resolver Resolver) []model.TakeoverFinding {
	return detectWith(ctx, probes, Fingerprints, resolver)
}

func detectWith(ctx context.Context, probes []model.HostProbe, fps []Fingerprint, resolver Resolver) []model.TakeoverFinding {
	var out []model.TakeoverFinding
	for _, p := range probes {
		host := strings.ToLower(strings.TrimSpace(p.Host))
		if host == "" || isIP(host) { // a takeover needs a name with a dangling record
			continue
		}
		if f, ok := bestMatch(ctx, host, p, fps, resolver); ok {
			out = append(out, f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

// bestMatch evaluates every fingerprint against a probe and returns the
// strongest finding (claimable+high-confidence outranks parked or low). It
// returns false when no fingerprint matches.
func bestMatch(ctx context.Context, host string, p model.HostProbe, fps []Fingerprint, resolver Resolver) (model.TakeoverFinding, bool) {
	var best model.TakeoverFinding
	bestRank := -1
	for _, fp := range fps {
		cname, cnameMatch := matchCNAME(host, p.CNAMEs, fp.CNAMEs)
		f, ok := evaluate(ctx, host, p, fp, cname, cnameMatch, resolver)
		if !ok {
			continue
		}
		if r := rank(f); r > bestRank {
			best, bestRank = f, r
		}
	}
	return best, bestRank >= 0
}

// evaluate decides whether one fingerprint matches one probe, returning a fully
// populated finding. The decision tree:
//
//   - NXDOMAIN service: require a CNAME match AND the CNAME target failing to
//     resolve (confirmed via resolver). No body is involved.
//   - HTTP-fingerprint service: require the body fingerprint. A matching CNAME
//     raises confidence from "low" (fingerprint alone) to "high" (both signals).
func evaluate(ctx context.Context, host string, p model.HostProbe, fp Fingerprint, cname string, cnameMatch bool, resolver Resolver) (model.TakeoverFinding, bool) {
	if onProviderApex(host, fp.CNAMEs) { // the service's own name, not a customer's dangling pointer
		return model.TakeoverFinding{}, false
	}
	if fp.NXDOMAIN {
		if !cnameMatch || !isNXDOMAIN(ctx, resolver, cname) {
			return model.TakeoverFinding{}, false
		}
		return finding(host, fp, cname, "high"), true
	}
	if fp.Body == "" || !strings.Contains(p.Body, fp.Body) {
		return model.TakeoverFinding{}, false
	}
	confidence := "low"
	if cnameMatch {
		confidence = "high"
	}
	return finding(host, fp, cname, confidence), true
}

func finding(host string, fp Fingerprint, cname, confidence string) model.TakeoverFinding {
	return model.TakeoverFinding{
		Host:       host,
		Service:    fp.Service,
		CNAME:      cname,
		Confidence: confidence,
		Vulnerable: fp.Vulnerable,
		Detail:     detail(fp, cname, confidence),
	}
}

// detail builds responsible, manual-confirmation-first phrasing. A claimable
// service reads as a takeover risk; a parked one as an informational dangling
// pointer that the provider blocks from re-registration.
func detail(fp Fingerprint, cname, confidence string) string {
	via := ""
	if cname != "" {
		via = fmt.Sprintf(" via CNAME → %s", cname)
	}
	if !fp.Vulnerable {
		return fmt.Sprintf("dangling %s pointer%s (provider blocks re-registration; not claimable — informational)", fp.Service, via)
	}
	if fp.NXDOMAIN {
		return fmt.Sprintf("potential %s takeover: dangling CNAME target%s no longer resolves — manual confirmation required", fp.Service, via)
	}
	return fmt.Sprintf("potential %s takeover (%s confidence): unclaimed-resource fingerprint%s — manual confirmation required", fp.Service, confidence, via)
}

// rank orders findings so bestMatch keeps the most actionable one.
func rank(f model.TakeoverFinding) int {
	switch {
	case f.Vulnerable && f.Confidence == "high":
		return 3
	case f.Vulnerable:
		return 2
	default: // parked / not claimable
		return 1
	}
}

// matchCNAME reports whether any of the host's CNAMEs is a DNS suffix of one of
// the fingerprint patterns, returning the matched CNAME. It skips the host's
// own apex on the provider (e.g. it will not flag foo.github.io itself) to
// avoid flagging the service's legitimately-hosted names.
func matchCNAME(host string, cnames, patterns []string) (string, bool) {
	for _, raw := range cnames {
		c := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
		if c == "" {
			continue
		}
		for _, pat := range patterns {
			if suffixMatch(c, pat) {
				return c, true
			}
		}
	}
	return "", false
}

// onProviderApex reports whether host is itself a name on the service (e.g.
// foo.github.io), which is a legitimately-hosted name, not a customer's
// dangling pointer at the service.
func onProviderApex(host string, patterns []string) bool {
	for _, pat := range patterns {
		if suffixMatch(host, pat) {
			return true
		}
	}
	return false
}

func suffixMatch(name, pattern string) bool {
	return name == pattern || strings.HasSuffix(name, "."+pattern)
}

// isNXDOMAIN reports whether host fails to resolve with an authoritative
// "not found" (NXDOMAIN/NODATA). A nil resolver or any non-NXDOMAIN error
// (timeout, SERVFAIL) returns false so transient failures never produce a
// takeover finding.
func isNXDOMAIN(ctx context.Context, resolver Resolver, host string) bool {
	if resolver == nil || host == "" {
		return false
	}
	_, err := resolver.LookupHost(ctx, host)
	if err == nil {
		return false
	}
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

func isIP(host string) bool {
	return net.ParseIP(host) != nil
}
