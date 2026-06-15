package collect

import (
	"context"
	"net"
	"sort"
	"strings"

	"github.com/maruftak/reconsentry/internal/model"
)

// dnsResolver is the subset of *net.Resolver the DNS collector needs; it is a
// package var so tests can substitute a fake without real DNS.
type dnsResolver interface {
	LookupCNAME(ctx context.Context, host string) (string, error)
	LookupNS(ctx context.Context, host string) ([]*net.NS, error)
}

// DNSResolver resolves the records DNSRecords collects. Overridable in tests.
var DNSResolver dnsResolver = net.DefaultResolver

// DNSRecords resolves CNAME and NS records for each host. DNS resolution is
// benign passive recon — it queries resolvers, not the target's servers — so
// unlike the active HTTP probes the runner may invoke it even for passive
// scopes. NS records only exist at zone cuts (the apex and delegated
// subdomains) and CNAMEs only where one is configured, so plain A-record hosts
// yield nothing and the output stays high-signal. A per-host lookup failure is
// skipped rather than failing the batch.
func DNSRecords(ctx context.Context, hosts []string) ([]model.DNSRecord, error) {
	var recs []model.DNSRecord
	for _, h := range hosts {
		h = strings.ToLower(model.TrimInvisible(h))
		if h == "" {
			continue
		}
		if cname, err := DNSResolver.LookupCNAME(ctx, h); err == nil {
			if c := normalizeDNS(cname); c != "" && c != h {
				recs = append(recs, model.DNSRecord{Host: h, Type: "CNAME", Value: c})
			}
		}
		if nss, err := DNSResolver.LookupNS(ctx, h); err == nil {
			for _, ns := range nss {
				if ns == nil {
					continue
				}
				if v := normalizeDNS(ns.Host); v != "" {
					recs = append(recs, model.DNSRecord{Host: h, Type: "NS", Value: v})
				}
			}
		}
	}
	sortDNS(recs)
	return recs, nil
}

func normalizeDNS(s string) string {
	return strings.TrimSuffix(strings.ToLower(model.TrimInvisible(s)), ".")
}

// sortDNS orders records (host, type, value) so storage and diffs are stable.
func sortDNS(recs []model.DNSRecord) {
	sort.Slice(recs, func(i, j int) bool {
		if recs[i].Host != recs[j].Host {
			return recs[i].Host < recs[j].Host
		}
		if recs[i].Type != recs[j].Type {
			return recs[i].Type < recs[j].Type
		}
		return recs[i].Value < recs[j].Value
	})
}
