package collect

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"strings"

	"github.com/maruftak/reconsentry/internal/model"
)

// takeoverLine models the subset of `httpx -json` output the takeover detector
// consumes. Field tags match ProjectDiscovery httpx's Result struct: the CNAME
// chain is `cname` (an array despite the singular tag) and the response body is
// `body` (emitted with -include-response). `response` is the full raw response
// (headers + body) httpx emits under the same flag; it is read as a fallback so
// a fingerprint still matches if the body lands there across httpx versions.
type takeoverLine struct {
	Input      string   `json:"input"`
	URL        string   `json:"url"`
	Host       string   `json:"host"`
	StatusCode int      `json:"status_code"`
	CNAMEs     []string `json:"cname"`
	Body       string   `json:"body"`
	Response   string   `json:"response"`
	Failed     bool     `json:"failed"`
}

// Takeover probes hosts for the signals subdomain-takeover detection needs: the
// CNAME chain (-cname) and the response body (-include-response). It runs with
// -probe so every input yields a line — including hosts that fail to serve,
// whose dangling CNAME may itself be the takeover signal. Active HTTP/DNS
// traffic, so the runner only invokes it on non-passive scopes.
func Takeover(ctx context.Context, hosts []string) ([]model.HostProbe, error) {
	if len(hosts) == 0 {
		return nil, nil
	}
	if err := ensure("httpx"); err != nil {
		return nil, err
	}
	args := []string{
		"-json", "-silent", "-no-color", "-probe",
		"-cname", "-include-response", "-status-code",
	}
	out, err := runStdin(ctx, strings.Join(hosts, "\n"), "httpx", args...)
	if err != nil {
		return nil, err
	}
	return parseTakeover(out), nil
}

// parseTakeover converts httpx JSONL output into host probes. Pure, so it is
// unit-tested without invoking httpx.
func parseTakeover(b []byte) []model.HostProbe {
	var probes []model.HostProbe
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var l takeoverLine
		if err := json.Unmarshal([]byte(line), &l); err != nil {
			continue
		}
		name := l.Input
		if name == "" {
			name = l.Host
		}
		if name == "" {
			name = hostFromURL(l.URL)
		}
		name = cleanHost(name)
		if name == "" {
			continue
		}
		body := l.Body
		if body == "" {
			body = l.Response // fall back to the raw response when body isn't a separate field
		}
		probes = append(probes, model.HostProbe{
			Host:   name,
			CNAMEs: cleanCNAMEs(l.CNAMEs),
			Body:   body,
			Status: l.StatusCode,
			Failed: l.Failed,
		})
	}
	return probes
}

func cleanCNAMEs(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, c := range in {
		c = strings.ToLower(strings.TrimSuffix(model.TrimInvisible(c), "."))
		if c != "" {
			out = append(out, c)
		}
	}
	return out
}
