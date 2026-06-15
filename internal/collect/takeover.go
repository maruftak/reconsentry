package collect

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/maruftak/reconsentry/internal/model"
)

// takeoverBodyPreview is how many bytes of each response body httpx returns for
// fingerprint matching. The "unclaimed resource" strings all appear early in
// the body, so a few KB is plenty while keeping output bounded.
const takeoverBodyPreview = 4096

// takeoverLine models the subset of `httpx -json` output the takeover detector
// consumes: the CNAME chain and the body/status used to match a service
// fingerprint.
type takeoverLine struct {
	Input        string   `json:"input"`
	URL          string   `json:"url"`
	Host         string   `json:"host"`
	StatusCode   int      `json:"status_code"`
	CNAMEs       []string `json:"cnames"`
	ResponseBody string   `json:"response_body"`
	Failed       bool     `json:"failed"`
}

// Takeover probes hosts for the signals subdomain-takeover detection needs:
// the CNAME chain (-cname) and a response-body preview (-body-preview). It runs
// with -probe so every input yields a line (including hosts that fail to serve,
// whose dangling CNAME may itself be the takeover signal). Active HTTP traffic,
// so the runner only invokes it on non-passive scopes.
func Takeover(ctx context.Context, hosts []string) ([]model.HostProbe, error) {
	if len(hosts) == 0 {
		return nil, nil
	}
	if err := ensure("httpx"); err != nil {
		return nil, err
	}
	args := []string{
		"-json", "-silent", "-no-color", "-probe", "-cname",
		"-status-code", "-body-preview", strconv.Itoa(takeoverBodyPreview),
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
		probes = append(probes, model.HostProbe{
			Host:   name,
			CNAMEs: cleanCNAMEs(l.CNAMEs),
			Body:   l.ResponseBody,
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
