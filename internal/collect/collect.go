// Package collect gathers attack-surface assets by orchestrating proven
// external recon tools (subfinder, httpx). The thin exec wrappers shell out;
// the parse functions are pure and unit-tested.
package collect

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/maruftak/reconsentry/internal/model"
)

// ensure returns a helpful error when a required external tool is missing.
func ensure(tool string) error {
	if _, err := exec.LookPath(tool); err != nil {
		return fmt.Errorf("%s not found in PATH — install it (see README) to enable this collector", tool)
	}
	return nil
}

// Subfinder discovers subdomains for the given root targets via the subfinder CLI.
func Subfinder(ctx context.Context, targets []string) ([]string, error) {
	if err := ensure("subfinder"); err != nil {
		return nil, err
	}
	args := []string{"-silent"}
	for _, t := range targets {
		args = append(args, "-d", t)
	}
	out, err := runStdin(ctx, "", "subfinder", args...)
	if err != nil {
		return nil, err
	}
	return parseLines(out), nil
}

// parseLines splits newline-delimited output into a lowercased, de-duplicated host list.
func parseLines(b []byte) []string {
	seen := map[string]bool{}
	var hosts []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		h := strings.ToLower(model.TrimInvisible(sc.Text()))
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		hosts = append(hosts, h)
	}
	return hosts
}

// httpxLine models the subset of `httpx -json` output we consume. Field names
// vary slightly across httpx versions, so we accept both tech/technologies.
type httpxLine struct {
	Input        string   `json:"input"`
	URL          string   `json:"url"`
	Host         string   `json:"host"`
	HostIP       string   `json:"host_ip"`
	StatusCode   int      `json:"status_code"`
	Title        string   `json:"title"`
	Webserver    string   `json:"webserver"`
	Tech         []string `json:"tech"`
	Technologies []string `json:"technologies"`
	A            []string `json:"a"`
}

// Httpx probes hosts for liveness and metadata via the httpx CLI. Hosts that
// do not respond are omitted from the result; the caller reconciles liveness.
func Httpx(ctx context.Context, hosts []string) ([]model.Asset, error) {
	if len(hosts) == 0 {
		return nil, nil
	}
	if err := ensure("httpx"); err != nil {
		return nil, err
	}
	hosts = guardProbeTargets(ctx, hosts)
	if len(hosts) == 0 {
		return nil, nil
	}
	args := []string{"-json", "-silent", "-no-color", "-tech-detect", "-title", "-web-server", "-status-code", "-ip"}
	out, err := runStdin(ctx, strings.Join(hosts, "\n"), "httpx", args...)
	if err != nil {
		return nil, err
	}
	return parseHttpx(out), nil
}

// parseHttpx converts httpx JSONL output into assets.
func parseHttpx(b []byte) []model.Asset {
	var assets []model.Asset
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var l httpxLine
		if err := json.Unmarshal([]byte(line), &l); err != nil {
			continue
		}
		name := l.Input
		if name == "" {
			name = hostFromURL(l.URL)
		}
		name = cleanHost(name)
		if name == "" {
			continue
		}
		// Prefer the stable host_ip; fall back to the first sorted A record so
		// DNS round-robin ordering does not produce spurious IP_CHANGE alerts.
		ip := l.HostIP
		if ip == "" && len(l.A) > 0 {
			sorted := append([]string(nil), l.A...)
			sort.Strings(sorted)
			ip = sorted[0]
		}
		assets = append(assets, model.Asset{
			Host:   name,
			Alive:  true,
			Status: l.StatusCode,
			Title:  l.Title,
			Server: l.Webserver,
			Tech:   model.NormalizeTech(mergeTech(l.Tech, l.Technologies)),
			IP:     ip,
		})
	}
	return assets
}

func hostFromURL(raw string) string {
	if raw == "" {
		return ""
	}
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Host
	}
	return raw
}

func cleanHost(h string) string {
	h = strings.ToLower(model.TrimInvisible(h))
	h = strings.TrimPrefix(h, "http://")
	h = strings.TrimPrefix(h, "https://")
	if i := strings.IndexByte(h, '/'); i >= 0 {
		h = h[:i]
	}
	if i := strings.LastIndexByte(h, ':'); i >= 0 && isDigits(h[i+1:]) {
		h = h[:i]
	}
	return h
}

func mergeTech(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range a {
		out = addTech(out, seen, t)
	}
	for _, t := range b {
		out = addTech(out, seen, t)
	}
	return out
}

func addTech(out []string, seen map[string]bool, t string) []string {
	t = strings.TrimSpace(t)
	key := strings.ToLower(t)
	if t == "" || seen[key] {
		return out
	}
	seen[key] = true
	return append(out, t)
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// guardProbeTargets applies the internal-IP SSRF guard to a probe host list,
// returning only the public targets. Dropped hosts are reported once to stderr
// so a skipped target is visible rather than silently swallowed.
func guardProbeTargets(ctx context.Context, hosts []string) []string {
	kept, dropped := publicHosts(ctx, hosts)
	if len(dropped) > 0 {
		fmt.Fprintf(os.Stderr, "reconsentry: skipped %d internal/private probe target(s): %s\n",
			len(dropped), strings.Join(dropped, ", "))
	}
	return kept
}

func runStdin(ctx context.Context, stdin, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}
