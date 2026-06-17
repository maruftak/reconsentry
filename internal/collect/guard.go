package collect

import (
	"context"
	"net"
	"strings"

	"github.com/maruftak/reconsentry/internal/model"
)

// isInternalIP reports whether ip falls in a range that active probing must
// never touch: RFC1918 / RFC4193 private space, loopback, link-local (which
// includes the cloud metadata address 169.254.169.254 and IPv6 fe80::/10), or
// the unspecified address. This is the SSRF guard for the probe path — a
// discovered name that resolves into one of these ranges (a dangling internal
// CNAME, or a poisoned CT-log / passive-DNS entry pointing at 127.0.0.1 or the
// instance-metadata endpoint) is dropped before httpx is ever asked to connect.
func isInternalIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() ||
		ip.IsPrivate()
}

// internalHost reports whether host must not be probed. A literal internal IP is
// rejected deterministically. A hostname is resolved and rejected when ANY
// resolved address is internal (conservative: a name that points at even one
// private address could lead httpx to connect there). A name that fails to
// resolve is NOT treated as internal — discovery remains the source of truth and
// a flaky resolver must not silently shrink the monitored surface; httpx will
// simply fail to connect to a genuinely dead name.
func internalHost(ctx context.Context, res *net.Resolver, host string) bool {
	h := normalizeProbeHost(host)
	if h == "" {
		return false
	}
	if ip := net.ParseIP(h); ip != nil {
		return isInternalIP(ip)
	}
	ips, err := res.LookupIP(ctx, "ip", h)
	if err != nil || len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		if isInternalIP(ip) {
			return true
		}
	}
	return false
}

// normalizeProbeHost reduces a probe entry to a bare host or IP, correctly
// preserving IPv6 literals (which cleanHost's port-strip would mangle). It drops
// any scheme and path, then peels an optional :port — including the bracketed
// [ipv6]:port form — before unwrapping IPv6 brackets, so net.ParseIP can classify
// the literal.
func normalizeProbeHost(host string) string {
	h := strings.ToLower(model.TrimInvisible(host))
	h = strings.TrimPrefix(h, "http://")
	h = strings.TrimPrefix(h, "https://")
	if i := strings.IndexByte(h, '/'); i >= 0 {
		h = h[:i]
	}
	if hostOnly, _, err := net.SplitHostPort(h); err == nil {
		h = hostOnly
	}
	h = strings.TrimPrefix(strings.TrimSuffix(h, "]"), "[")
	return strings.TrimSpace(h)
}

// publicHosts splits hosts into those safe to probe (kept) and those rejected by
// the internal-IP guard (dropped), preserving input order. The dropped list is
// returned so the caller can surface what was skipped rather than dropping it
// silently. Resolution uses the default system resolver and honours ctx.
func publicHosts(ctx context.Context, hosts []string) (kept, dropped []string) {
	res := net.DefaultResolver
	for _, h := range hosts {
		if internalHost(ctx, res, h) {
			dropped = append(dropped, h)
			continue
		}
		kept = append(kept, h)
	}
	return kept, dropped
}
