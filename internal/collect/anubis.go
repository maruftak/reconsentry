package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/maruftak/reconsentry/internal/model"
)

// anubisURL builds the jldc.me Anubis query for a root domain. The endpoint
// returns a JSON array of hostnames and does not require an API key.
const anubisURL = "https://jldc.me/anubis/subdomains/%s"

// Anubis discovers subdomains from jldc.me's Anubis endpoint for the given
// root targets. It is a pure HTTP collector and safe for passive scopes. A
// failure for one target does not abort the others; an error is returned only
// when every target lookup fails.
func Anubis(ctx context.Context, targets []string) ([]string, error) {
	seen := map[string]bool{}
	var hosts []string
	var errs []error
	for _, t := range targets {
		body, err := httpGet(ctx, fmt.Sprintf(anubisURL, t))
		if err != nil {
			errs = append(errs, fmt.Errorf("anubis %s: %w", t, err))
			continue
		}
		for _, h := range parseAnubis(body, t) {
			if !seen[h] {
				seen[h] = true
				hosts = append(hosts, h)
			}
		}
	}
	// Fail soft: only surface an error if no target produced a result *and* at
	// least one lookup failed, so a single dead query never kills the run.
	if len(hosts) == 0 && len(errs) > 0 {
		return nil, errs[0]
	}
	return hosts, nil
}

// parseAnubis extracts in-scope hostnames from an Anubis JSON response. Names
// are lowercased, de-duplicated, and dropped if outside the target domain.
func parseAnubis(b []byte, target string) []string {
	var names []string
	if err := json.Unmarshal(b, &names); err != nil {
		return nil
	}
	target = strings.ToLower(model.TrimInvisible(target))
	seen := map[string]bool{}
	var hosts []string
	for _, raw := range names {
		h := strings.ToLower(model.TrimInvisible(raw))
		if h == "" || seen[h] || !inScope(h, target) {
			continue
		}
		seen[h] = true
		hosts = append(hosts, h)
	}
	return hosts
}
