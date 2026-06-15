package takeover

import (
	"context"
	"net"
	"testing"

	"github.com/maruftak/reconsentry/internal/model"
)

// fakeResolver returns NXDOMAIN for the hosts in nxdomain and resolves
// everything else to a placeholder address.
type fakeResolver struct{ nxdomain map[string]bool }

func (f fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if f.nxdomain[host] {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return []string{"203.0.113.10"}, nil
}

func TestDetect(t *testing.T) {
	resolver := fakeResolver{nxdomain: map[string]bool{
		"acme.azurewebsites.net":    true,
		"gone.elasticbeanstalk.com": true,
	}}

	tests := []struct {
		name           string
		probe          model.HostProbe
		wantFinding    bool
		wantService    string
		wantConfidence string
		wantVulnerable bool
	}{
		{
			name:           "cname and body -> high confidence claimable",
			probe:          model.HostProbe{Host: "blog.acme.com", CNAMEs: []string{"acme.ghost.io"}, Body: "<html>Site unavailable</html>"},
			wantFinding:    true,
			wantService:    "Ghost",
			wantConfidence: "high",
			wantVulnerable: true,
		},
		{
			name:           "body only (no matching cname) -> low confidence",
			probe:          model.HostProbe{Host: "blog.acme.com", CNAMEs: []string{"acme.cloudfront.net"}, Body: "Site unavailable"},
			wantFinding:    true,
			wantService:    "Ghost",
			wantConfidence: "low",
			wantVulnerable: true,
		},
		{
			name:           "S3 bucket gone",
			probe:          model.HostProbe{Host: "assets.acme.com", CNAMEs: []string{"acme-bucket.s3.amazonaws.com"}, Body: "The specified bucket does not exist"},
			wantFinding:    true,
			wantService:    "AWS/S3",
			wantConfidence: "high",
			wantVulnerable: true,
		},
		{
			name:           "parked github pages -> info, not claimable",
			probe:          model.HostProbe{Host: "docs.acme.com", CNAMEs: []string{"acme.github.io"}, Body: "There isn't a GitHub Pages site here."},
			wantFinding:    true,
			wantService:    "GitHub Pages",
			wantConfidence: "high",
			wantVulnerable: false,
		},
		{
			name:           "nxdomain service with dangling cname target",
			probe:          model.HostProbe{Host: "app.acme.com", CNAMEs: []string{"acme.azurewebsites.net"}, Failed: true},
			wantFinding:    true,
			wantService:    "Microsoft Azure (App Service)",
			wantConfidence: "high",
			wantVulnerable: true,
		},
		{
			name:        "nxdomain service but cname target still resolves -> no finding",
			probe:       model.HostProbe{Host: "app.acme.com", CNAMEs: []string{"live.azurewebsites.net"}},
			wantFinding: false,
		},
		{
			name:        "cname matches http service but no body fingerprint -> no finding",
			probe:       model.HostProbe{Host: "blog.acme.com", CNAMEs: []string{"acme.ghost.io"}, Body: "welcome to my blog"},
			wantFinding: false,
		},
		{
			name:        "no cname, no fingerprint -> no finding",
			probe:       model.HostProbe{Host: "www.acme.com", CNAMEs: []string{"acme.com"}, Body: "<html>home</html>"},
			wantFinding: false,
		},
		{
			name:        "ip host is skipped",
			probe:       model.HostProbe{Host: "203.0.113.5", Body: "The specified bucket does not exist"},
			wantFinding: false,
		},
		{
			name:        "host on provider apex is not flagged",
			probe:       model.HostProbe{Host: "acme.github.io", CNAMEs: []string{"acme.github.io"}, Body: "There isn't a GitHub Pages site here."},
			wantFinding: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Detect(context.Background(), []model.HostProbe{tt.probe}, resolver)
			if !tt.wantFinding {
				if len(got) != 0 {
					t.Fatalf("want no finding, got %+v", got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("want 1 finding, got %d: %+v", len(got), got)
			}
			f := got[0]
			if f.Service != tt.wantService {
				t.Errorf("service: got %q want %q", f.Service, tt.wantService)
			}
			if f.Confidence != tt.wantConfidence {
				t.Errorf("confidence: got %q want %q", f.Confidence, tt.wantConfidence)
			}
			if f.Vulnerable != tt.wantVulnerable {
				t.Errorf("vulnerable: got %v want %v", f.Vulnerable, tt.wantVulnerable)
			}
			if f.Detail == "" {
				t.Error("detail should not be empty")
			}
		})
	}
}

func TestDetectOrdersByHost(t *testing.T) {
	probes := []model.HostProbe{
		{Host: "zeta.acme.com", CNAMEs: []string{"z.ghost.io"}, Body: "Site unavailable"},
		{Host: "alpha.acme.com", CNAMEs: []string{"a.ghost.io"}, Body: "Site unavailable"},
	}
	got := Detect(context.Background(), probes, nil)
	if len(got) != 2 {
		t.Fatalf("want 2 findings, got %d", len(got))
	}
	if got[0].Host != "alpha.acme.com" || got[1].Host != "zeta.acme.com" {
		t.Errorf("findings not ordered by host: %s, %s", got[0].Host, got[1].Host)
	}
}

func TestNilResolverSkipsNXDOMAIN(t *testing.T) {
	// Without a resolver, an NXDOMAIN-only service can't be confirmed, so it
	// must not produce a (false-positive) finding.
	probes := []model.HostProbe{{Host: "app.acme.com", CNAMEs: []string{"acme.azurewebsites.net"}, Failed: true}}
	if got := Detect(context.Background(), probes, nil); len(got) != 0 {
		t.Fatalf("nil resolver should skip NXDOMAIN services, got %+v", got)
	}
}

func TestBestMatchPrefersClaimable(t *testing.T) {
	// A body that matches both a parked and a claimable service should surface
	// the claimable one. (Synthetic: same body string under two fingerprints.)
	fps := []Fingerprint{
		{Service: "ParkedCorp", CNAMEs: []string{"parked.example"}, Body: "gone", Vulnerable: false},
		{Service: "ClaimCorp", CNAMEs: []string{"claim.example"}, Body: "gone", Vulnerable: true},
	}
	probe := model.HostProbe{Host: "x.acme.com", CNAMEs: []string{"x.claim.example"}, Body: "it is gone now"}
	got := detectWith(context.Background(), []model.HostProbe{probe}, fps, nil)
	if len(got) != 1 || got[0].Service != "ClaimCorp" {
		t.Fatalf("want ClaimCorp finding, got %+v", got)
	}
}
