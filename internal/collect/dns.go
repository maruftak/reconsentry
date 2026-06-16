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
	LookupMX(ctx context.Context, host string) ([]*net.MX, error)
	LookupTXT(ctx context.Context, host string) ([]string, error)
}

// DNSResolver resolves the records DNSRecords collects. Overridable in tests.
var DNSResolver dnsResolver = net.DefaultResolver

// DNSRecords resolves CNAME, NS, MX, and TXT records for each host (plus the
// host's _dmarc TXT record, stored under the "_dmarc.<host>" name so DMARC
// posture can be diffed). DNS resolution is benign passive recon — it queries
// resolvers, not the target's servers — so unlike the active HTTP probes the
// runner may invoke it even for passive scopes. NS records only exist at zone
// cuts, CNAMEs/MX/TXT only where configured, so plain A-record hosts yield
// nothing and the output stays high-signal. A per-host lookup failure is
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
		if mxs, err := DNSResolver.LookupMX(ctx, h); err == nil {
			for _, mx := range mxs {
				if mx == nil {
					continue
				}
				// Preference is dropped: a reorder is not a security change, and
				// dropping it keeps the diff stable. Only the mail-host set matters.
				if v := normalizeDNS(mx.Host); v != "" {
					recs = append(recs, model.DNSRecord{Host: h, Type: "MX", Value: v})
				}
			}
		}
		recs = appendTXT(ctx, recs, h)
		recs = appendTXT(ctx, recs, "_dmarc."+h)
	}
	sortDNS(recs)
	return recs, nil
}

// appendTXT looks up TXT records for name and appends them under that name.
// TXT values are stored verbatim (only outer whitespace trimmed) because SPF
// and DMARC posture are encoded in the literal string. An empty value is
// skipped. A lookup failure (e.g. no record) is silently skipped.
func appendTXT(ctx context.Context, recs []model.DNSRecord, name string) []model.DNSRecord {
	txts, err := DNSResolver.LookupTXT(ctx, name)
	if err != nil {
		return recs
	}
	for _, t := range txts {
		if v := model.TrimInvisible(t); v != "" {
			recs = append(recs, model.DNSRecord{Host: name, Type: "TXT", Value: v})
		}
	}
	return recs
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
