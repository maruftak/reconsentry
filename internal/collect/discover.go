package collect

import (
	"context"
	"errors"
)

// source pairs a discovery source with a label for error reporting.
type source struct {
	name string
	fn   func(ctx context.Context, targets []string) ([]string, error)
}

// defaultSources is the discovery fan-out: the subfinder CLI plus passive
// HTTP collectors. Adding a source here is all it takes to widen coverage.
var defaultSources = []source{
	{"subfinder", Subfinder},
	{"crt.sh", CrtSh},
	{"wayback", Wayback},
	{"otx", OTX},
	{"anubis", Anubis},
}

// Discover runs every discovery source for the given root targets and merges
// the results into one de-duplicated host set. Sources fail soft: a missing
// subfinder binary or a dead crt.sh degrades coverage but does not abort the
// run. An error is returned only when every source fails (so the caller still
// learns when discovery is completely broken).
func Discover(ctx context.Context, targets []string) ([]string, error) {
	seen := map[string]bool{}
	var hosts []string
	var errs []error
	ok := false
	for _, s := range defaultSources {
		found, err := s.fn(ctx, targets)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		ok = true
		for _, h := range found {
			if !seen[h] {
				seen[h] = true
				hosts = append(hosts, h)
			}
		}
	}
	if !ok && len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return hosts, nil
}
