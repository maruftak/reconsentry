// Command reconsentry is a continuous attack-surface change monitor: it watches
// authorized targets and alerts when a new subdomain, live host, or technology
// appears.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/maruftak/reconsentry/internal/collect"
	"github.com/maruftak/reconsentry/internal/config"
	"github.com/maruftak/reconsentry/internal/diff"
	"github.com/maruftak/reconsentry/internal/mcpserver"
	"github.com/maruftak/reconsentry/internal/model"
	"github.com/maruftak/reconsentry/internal/notify"
	"github.com/maruftak/reconsentry/internal/report"
	"github.com/maruftak/reconsentry/internal/runner"
	"github.com/maruftak/reconsentry/internal/store"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "0.5.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "run":
		os.Exit(cmdRun(os.Args[2:]))
	case "init":
		os.Exit(cmdInit(os.Args[2:]))
	case "assets":
		os.Exit(cmdAssets(os.Args[2:]))
	case "history":
		os.Exit(cmdHistory(os.Args[2:]))
	case "report":
		os.Exit(cmdReport(os.Args[2:]))
	case "badge":
		os.Exit(cmdBadge(os.Args[2:]))
	case "diff":
		os.Exit(cmdDiff(os.Args[2:]))
	case "mcp":
		os.Exit(cmdMCP(os.Args[2:]))
	case "version", "-v", "--version":
		fmt.Printf("reconsentry %s\n", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `reconsentry — attack-surface change monitor

usage:
  reconsentry init [path]              write a starter scope file (default scope.yaml)
  reconsentry run --config scope.yaml [flags]
  reconsentry assets --config scope.yaml [--scope name] [--json]   show the latest snapshot
  reconsentry history --config scope.yaml [--scope name] [--json]  list past runs
  reconsentry report --config scope.yaml [--scope name] [-o out.html]  self-contained HTML surface report
  reconsentry badge --config scope.yaml [--scope name] [-o badge.svg]   live attack-surface SVG badge
  reconsentry diff --config scope.yaml [--scope name] [--json] [idA idB]  changes between two stored runs
  reconsentry mcp --db reconsentry.db [--config scope.yaml]   read-only MCP server over stdio (for AI agents)
  reconsentry version

A scope file holds one scope, or many under a top-level "scopes:" list.

run flags:
  --config string   path to scope config (required)
  --db string       path to sqlite database (default "reconsentry.db")
  --interval dur    if set (e.g. 6h), monitor continuously on this interval
  --timeout dur     max duration for a single run cycle (default 10m; 0 = no limit)
  --keep int        retain only the most recent N snapshots per scope (0 = keep all)
  --max-hosts int   probe at most N hosts per run; bounds huge scopes (0 = no limit)
  --scan-new        run nuclei against newly-found hosts; findings show as VULN_FOUND
  --crawl           crawl live hosts with katana; new URLs show as NEW_ENDPOINT
  --cert-check      check live hosts' TLS certs; near-expiry shows as CERT_EXPIRING
  --cert-days int   CERT_EXPIRING window in days (default 30; with --cert-check)
  --takeover        check hosts for dangling DNS records; risk shows as TAKEOVER_RISK
  --dns             track CNAME/NS/MX/TXT records; changes show as DNS_CHANGE/MX_CHANGE/TXT_CHANGE (passive-safe)
  --dry-run         print changes; do not send notifications
  --json            emit results as JSON (one object per cycle) for piping
  --sarif string    write each cycle's changes to this SARIF file (CI upload)

Only monitor targets you are authorized to test.
`)
}

func cmdRun(args []string) int {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to scope config (required)")
	dbPath := fs.String("db", "reconsentry.db", "path to sqlite database")
	interval := fs.Duration("interval", 0, "continuous run interval (e.g. 6h); 0 = run once")
	timeout := fs.Duration("timeout", 10*time.Minute, "max duration for a single run cycle (0 = no limit)")
	keep := fs.Int("keep", 0, "retain only the most recent N snapshots per scope (0 = keep all)")
	maxHosts := fs.Int("max-hosts", 0, "probe at most N hosts per run; bounds huge scopes (0 = no limit)")
	scanNew := fs.Bool("scan-new", false, "run nuclei against newly-found hosts; findings show as VULN_FOUND")
	crawl := fs.Bool("crawl", false, "crawl live hosts with katana; new URLs show as NEW_ENDPOINT")
	certCheck := fs.Bool("cert-check", false, "check live hosts' TLS certs; near-expiry shows as CERT_EXPIRING")
	certDays := fs.Int("cert-days", 30, "CERT_EXPIRING window in days (with --cert-check)")
	takeover := fs.Bool("takeover", false, "check hosts for dangling DNS records; risk shows as TAKEOVER_RISK")
	dns := fs.Bool("dns", false, "track CNAME/NS/MX/TXT records; changes show as DNS_CHANGE/MX_CHANGE/TXT_CHANGE")
	dryRun := fs.Bool("dry-run", false, "print changes; do not notify")
	jsonOut := fs.Bool("json", false, "emit run results as JSON (one object per cycle)")
	sarifPath := fs.String("sarif", "", "write each cycle's changes to this SARIF file (for CI code-scanning upload)")
	_ = fs.Parse(args)

	if *cfgPath == "" {
		fmt.Fprintln(os.Stderr, "error: --config is required")
		return 2
	}
	scopes, err := config.LoadAll(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	defer st.Close()

	// Build a pipeline per scope so each carries its own notifiers.
	type job struct {
		cfg  *config.Config
		pipe *runner.Pipeline
	}
	jobs := make([]job, 0, len(scopes))
	for _, cfg := range scopes {
		var notifiers []notify.Notifier
		if !*dryRun {
			add := func(urls []string, format string) {
				for _, u := range urls {
					notifiers = append(notifiers, notify.NewWebhook(u, format))
				}
			}
			add(cfg.Notify.Webhooks, "generic")
			add(cfg.Notify.Slack, "slack")
			add(cfg.Notify.Discord, "discord")
			for _, tg := range cfg.Notify.Telegram {
				notifiers = append(notifiers, notify.NewTelegram(tg.Token, tg.ChatID))
			}
			for _, em := range cfg.Notify.Email {
				notifiers = append(notifiers, notify.NewEmail(em.SMTPHost, em.SMTPPort, em.Username, em.Password, em.From, em.To))
			}
		}
		var scanner runner.ScanFunc
		if *scanNew {
			scanner = collect.Nuclei
		}
		var crawler runner.CrawlFunc
		if *crawl {
			crawler = collect.Katana
		}
		var certChecker runner.CertFunc
		if *certCheck {
			certChecker = collect.CertExpiry
		}
		var takeoverChecker runner.TakeoverFunc
		if *takeover {
			takeoverChecker = collect.Takeover
		}
		var dnsChecker runner.DNSFunc
		if *dns {
			dnsChecker = collect.DNSRecords
		}
		jobs = append(jobs, job{
			cfg: cfg,
			pipe: &runner.Pipeline{
				Store:     st,
				Discover:  collect.Discover,
				Probe:     collect.Httpx,
				Scanner:   scanner,
				Crawler:   crawler,
				CertCheck: certChecker,
				CertDays:  *certDays,
				Takeover:  takeoverChecker,
				DNS:       dnsChecker,
				Notifiers: notifiers,
				Keep:      *keep,
				MaxHosts:  *maxHosts,
			},
		})
	}
	multi := len(jobs) > 1

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// runOnce runs every scope once and reports whether all succeeded.
	runOnce := func() bool {
		ok := true
		var sarifScopes []report.ScopeChanges
		for _, j := range jobs {
			runCtx := ctx
			var cancel context.CancelFunc
			if *timeout > 0 {
				runCtx, cancel = context.WithTimeout(ctx, *timeout)
			}
			res, err := j.pipe.Run(runCtx, j.cfg)
			if cancel != nil {
				cancel()
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "run error [%s]: %v\n", j.cfg.Name, err)
				ok = false
				continue
			}
			if *sarifPath != "" {
				sarifScopes = append(sarifScopes, report.ScopeChanges{Scope: j.cfg.Name, Changes: res.Changes})
			}
			if *jsonOut {
				printJSON(j.cfg.Name, res)
			} else {
				if multi {
					fmt.Printf("== %s ==\n", j.cfg.Name)
				}
				printResult(res)
			}
		}
		if *sarifPath != "" {
			if err := writeSARIF(*sarifPath, sarifScopes); err != nil {
				fmt.Fprintf(os.Stderr, "sarif error: %v\n", err)
				ok = false
			}
		}
		return ok
	}

	if *interval <= 0 {
		if !runOnce() {
			return 1
		}
		return 0
	}

	if !*jsonOut {
		fmt.Printf("reconsentry: monitoring %d scope(s) every %s (ctrl-c to stop)\n", len(jobs), *interval)
	}
	runOnce()
	t := time.NewTicker(*interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			if !*jsonOut {
				fmt.Println("reconsentry: stopped")
			}
			return 0
		case <-t.C:
			runOnce()
		}
	}
}

func cmdInit(args []string) int {
	path := "scope.yaml"
	if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
		path = args[0]
	}
	if _, err := os.Stat(path); err == nil {
		fmt.Fprintf(os.Stderr, "error: %s already exists (refusing to overwrite)\n", path)
		return 1
	}
	if err := os.WriteFile(path, []byte(scopeTemplate), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	fmt.Printf("wrote %s — edit your targets, then run: reconsentry run --config %s\n", path, path)
	return 0
}

// pickScope selects a scope by name, or the only scope when name is empty.
func pickScope(scopes []*config.Config, name string) (*config.Config, error) {
	if name != "" {
		for _, c := range scopes {
			if c.Name == name {
				return c, nil
			}
		}
		return nil, fmt.Errorf("scope %q not found in config", name)
	}
	if len(scopes) == 1 {
		return scopes[0], nil
	}
	names := make([]string, len(scopes))
	for i, c := range scopes {
		names[i] = c.Name
	}
	return nil, fmt.Errorf("config has %d scopes (%s); pass --scope to choose", len(scopes), strings.Join(names, ", "))
}

func cmdAssets(args []string) int {
	fs := flag.NewFlagSet("assets", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to scope config (required)")
	dbPath := fs.String("db", "reconsentry.db", "path to sqlite database")
	scopeName := fs.String("scope", "", "scope name (required if the config has multiple)")
	jsonOut := fs.Bool("json", false, "emit assets as JSON")
	_ = fs.Parse(args)

	if *cfgPath == "" {
		fmt.Fprintln(os.Stderr, "error: --config is required")
		return 2
	}
	scopes, err := config.LoadAll(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	cfg, err := pickScope(scopes, *scopeName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	defer st.Close()

	assets, err := st.LatestAssets(cfg.Name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	sort.Slice(assets, func(i, j int) bool { return assets[i].Host < assets[j].Host })

	if *jsonOut {
		b, err := json.MarshalIndent(assets, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "json error: %v\n", err)
			return 1
		}
		fmt.Println(string(b))
		return 0
	}

	if len(assets) == 0 {
		fmt.Printf("no assets recorded for %q yet — run: reconsentry run --config %s\n", cfg.Name, *cfgPath)
		return 0
	}
	fmt.Printf("%d asset(s) for %s (latest snapshot):\n", len(assets), cfg.Name)
	for _, a := range assets {
		status := "-"
		if a.Status != 0 {
			status = strconv.Itoa(a.Status)
		}
		state := "down"
		if a.Alive {
			state = "live"
		}
		fmt.Printf("  %-40s %-4s %-4s %-15s", a.Host, state, status, a.IP)
		if len(a.Tech) > 0 {
			fmt.Printf("  [%s]", a.TechString())
		}
		fmt.Println()
	}
	return 0
}

func cmdHistory(args []string) int {
	fs := flag.NewFlagSet("history", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to scope config (required)")
	dbPath := fs.String("db", "reconsentry.db", "path to sqlite database")
	scopeName := fs.String("scope", "", "scope name (required if the config has multiple)")
	jsonOut := fs.Bool("json", false, "emit history as JSON")
	_ = fs.Parse(args)

	if *cfgPath == "" {
		fmt.Fprintln(os.Stderr, "error: --config is required")
		return 2
	}
	scopes, err := config.LoadAll(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	cfg, err := pickScope(scopes, *scopeName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	defer st.Close()

	runs, err := st.Runs(cfg.Name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	if *jsonOut {
		b, err := json.MarshalIndent(runs, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "json error: %v\n", err)
			return 1
		}
		fmt.Println(string(b))
		return 0
	}

	if len(runs) == 0 {
		fmt.Printf("no runs recorded for %q yet — run: reconsentry run --config %s\n", cfg.Name, *cfgPath)
		return 0
	}
	fmt.Printf("%d run(s) for %s (most recent first):\n", len(runs), cfg.Name)
	for _, r := range runs {
		fmt.Printf("  #%-5d %s  %d asset(s)\n", r.ID, r.StartedAt.Format("2006-01-02 15:04:05"), r.Assets)
	}
	return 0
}

func cmdReport(args []string) int {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to scope config (required)")
	dbPath := fs.String("db", "reconsentry.db", "path to sqlite database")
	scopeName := fs.String("scope", "", "scope name (required if the config has multiple)")
	out := fs.String("o", "", "output HTML file (default: stdout)")
	_ = fs.Parse(args)

	if *cfgPath == "" {
		fmt.Fprintln(os.Stderr, "error: --config is required")
		return 2
	}
	scopes, err := config.LoadAll(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	cfg, err := pickScope(scopes, *scopeName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	defer st.Close()

	runs, err := st.Runs(cfg.Name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	snaps := make([]report.RunSnapshot, 0, len(runs))
	for _, r := range runs {
		assets, err := st.AssetsForRun(r.ID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		snaps = append(snaps, report.RunSnapshot{ID: r.ID, At: r.StartedAt, Assets: assets})
	}

	html, err := report.HTML(report.SurfaceReport{
		Scope:       cfg.Name,
		GeneratedAt: time.Now(),
		ToolVersion: "reconsentry " + version,
		Snapshots:   snaps,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "render error: %v\n", err)
		return 1
	}

	if *out == "" {
		os.Stdout.Write(html)
		return 0
	}
	if err := os.WriteFile(*out, html, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write error: %v\n", err)
		return 1
	}
	fmt.Printf("wrote %s (%d run(s), %d host(s))\n", *out, len(snaps), latestCount(snaps))
	return 0
}

// latestCount returns the host count of the most recent snapshot, for the
// report-written confirmation line.
func latestCount(snaps []report.RunSnapshot) int {
	if len(snaps) == 0 {
		return 0
	}
	// Runs() is newest-first, so the most recent snapshot is the first element.
	return len(snaps[0].Assets)
}

func cmdBadge(args []string) int {
	fs := flag.NewFlagSet("badge", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to scope config (required)")
	dbPath := fs.String("db", "reconsentry.db", "path to sqlite database")
	scopeName := fs.String("scope", "", "scope name (required if the config has multiple)")
	label := fs.String("label", "attack surface", "left-hand badge label")
	window := fs.Duration("window", 7*24*time.Hour, "change-velocity window (e.g. 7d as 168h)")
	out := fs.String("o", "", "output SVG file (default: stdout)")
	_ = fs.Parse(args)

	if *cfgPath == "" {
		fmt.Fprintln(os.Stderr, "error: --config is required")
		return 2
	}
	scopes, err := config.LoadAll(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	cfg, err := pickScope(scopes, *scopeName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	defer st.Close()

	assets, err := st.LatestAssets(cfg.Name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	total := len(assets)
	live := 0
	for _, a := range assets {
		if a.Alive {
			live++
		}
	}

	runs, err := st.Runs(cfg.Name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	// Runs() is newest-first. Walk to the first run at least `window` old and
	// diff its host count against the current total for the change velocity.
	delta, hasDelta := 0, false
	for _, r := range runs {
		if time.Since(r.StartedAt) >= *window {
			delta = total - r.Assets
			hasDelta = true
			break
		}
	}

	svg := report.Badge(*label, report.SurfaceStats{Total: total, Live: live, Delta: delta, HasDelta: hasDelta})

	if *out == "" {
		os.Stdout.Write(svg)
		return 0
	}
	if err := os.WriteFile(*out, svg, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write error: %v\n", err)
		return 1
	}
	fmt.Printf("wrote %s (%d/%d live)\n", *out, live, total)
	return 0
}

func cmdDiff(args []string) int {
	fs := flag.NewFlagSet("diff", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to scope config (required)")
	dbPath := fs.String("db", "reconsentry.db", "path to sqlite database")
	scopeName := fs.String("scope", "", "scope name (required if the config has multiple)")
	jsonOut := fs.Bool("json", false, "emit changes as JSON")
	_ = fs.Parse(args)

	if *cfgPath == "" {
		fmt.Fprintln(os.Stderr, "error: --config is required")
		return 2
	}
	scopes, err := config.LoadAll(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	cfg, err := pickScope(scopes, *scopeName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	defer st.Close()

	runs, err := st.Runs(cfg.Name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	if len(runs) < 2 {
		fmt.Printf("need at least 2 runs to diff %q (have %d)\n", cfg.Name, len(runs))
		return 0
	}

	// Resolve the run pair: explicit "idA idB", or the two most recent.
	valid := make(map[int64]bool, len(runs))
	for _, r := range runs {
		valid[r.ID] = true
	}
	var fromID, toID int64
	switch rest := fs.Args(); len(rest) {
	case 0:
		toID, fromID = runs[0].ID, runs[1].ID // newest vs previous
	case 2:
		a, errA := strconv.ParseInt(rest[0], 10, 64)
		b, errB := strconv.ParseInt(rest[1], 10, 64)
		if errA != nil || errB != nil {
			fmt.Fprintln(os.Stderr, "error: run ids must be integers")
			return 2
		}
		if !valid[a] || !valid[b] {
			fmt.Fprintf(os.Stderr, "error: run id not found for scope %q\n", cfg.Name)
			return 1
		}
		fromID, toID = a, b
	default:
		fmt.Fprintln(os.Stderr, "error: pass exactly two run ids, or none for the latest two")
		return 2
	}

	from, err := st.AssetsForRun(fromID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	to, err := st.AssetsForRun(toID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	changes := diff.Diff(from, to)

	if *jsonOut {
		b, err := json.MarshalIndent(changes, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "json error: %v\n", err)
			return 1
		}
		fmt.Println(string(b))
		return 0
	}

	fmt.Printf("%d change(s) for %s — run #%d → run #%d:\n", len(changes), cfg.Name, fromID, toID)
	if len(changes) == 0 {
		fmt.Println("  (no changes)")
		return 0
	}
	for _, c := range changes {
		host := c.Host
		if host == "" {
			host = "-"
		}
		fmt.Printf("  [%-13s] %-40s %s\n", c.Kind, host, c.Detail)
	}
	return 0
}

// cmdMCP serves the snapshot database to an AI agent over a read-only MCP
// server on stdio. It never scans, probes, or writes — it only reports data
// already collected by `reconsentry run`. The database is opened read-only so a
// bug cannot mutate it. --config is optional and, when given, is only validated
// (the scope list comes from the database itself), so a stale config path fails
// fast rather than silently.
func cmdMCP(args []string) int {
	fs := flag.NewFlagSet("mcp", flag.ExitOnError)
	dbPath := fs.String("db", "reconsentry.db", "path to sqlite database")
	cfgPath := fs.String("config", "", "optional scope config to validate (scopes are read from the database)")
	_ = fs.Parse(args)

	if *cfgPath != "" {
		if _, err := config.LoadAll(*cfgPath); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
	}

	st, err := store.OpenReadOnly(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		fmt.Fprintf(os.Stderr, "hint: run `reconsentry run --config scope.yaml --db %s` first to collect a snapshot\n", *dbPath)
		return 1
	}
	defer st.Close()

	// Everything human-facing must go to stderr; stdout is the MCP transport.
	fmt.Fprintf(os.Stderr, "reconsentry mcp: serving %s read-only over stdio (ctrl-c to stop)\n", *dbPath)
	if err := mcpserver.Serve(st, version); err != nil {
		fmt.Fprintf(os.Stderr, "mcp error: %v\n", err)
		return 1
	}
	return 0
}

// writeSARIF renders the cycle's changes to a SARIF file, overwriting any
// previous cycle (last write wins on a continuous interval).
func writeSARIF(path string, scopes []report.ScopeChanges) error {
	b, err := report.SARIF(scopes)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func printResult(res *runner.Result) {
	if res.Truncated > 0 {
		fmt.Fprintf(os.Stderr, "warning: --max-hosts dropped %d host(s) before probing; raise --max-hosts or narrow the scope\n", res.Truncated)
	}
	if res.ScanErr != nil {
		fmt.Fprintf(os.Stderr, "scan error: %v\n", res.ScanErr)
	}
	if res.CrawlErr != nil {
		fmt.Fprintf(os.Stderr, "crawl error: %v\n", res.CrawlErr)
	}
	if res.CertErr != nil {
		fmt.Fprintf(os.Stderr, "cert-check error: %v\n", res.CertErr)
	}
	for _, e := range res.NotifyErrs {
		fmt.Fprintf(os.Stderr, "notify error: %v\n", e)
	}
	switch {
	case res.FirstRun:
		fmt.Printf("baseline recorded: %d assets (no diff on first run)\n", len(res.Assets))
	case len(res.Changes) == 0:
		fmt.Printf("no changes (%d assets)\n", len(res.Assets))
	default:
		fmt.Printf("%d change(s):\n", len(res.Changes))
		for _, c := range res.Changes {
			fmt.Printf("  [%s] %s — %s\n", c.Kind, c.Host, c.Detail)
		}
	}
}

// runJSON is the machine-readable view of a run, stable for piping into other
// tooling.
type runJSON struct {
	Scope      string          `json:"scope"`
	RunID      int64           `json:"run_id"`
	FirstRun   bool            `json:"first_run"`
	AssetCount int             `json:"asset_count"`
	Changes    []diff.Change   `json:"changes"`
	Findings   []model.Finding `json:"findings,omitempty"`
}

func printJSON(scope string, res *runner.Result) {
	if res.ScanErr != nil {
		fmt.Fprintf(os.Stderr, "scan error: %v\n", res.ScanErr)
	}
	if res.CrawlErr != nil {
		fmt.Fprintf(os.Stderr, "crawl error: %v\n", res.CrawlErr)
	}
	if res.CertErr != nil {
		fmt.Fprintf(os.Stderr, "cert-check error: %v\n", res.CertErr)
	}
	for _, e := range res.NotifyErrs {
		fmt.Fprintf(os.Stderr, "notify error: %v\n", e)
	}
	out := runJSON{
		Scope:      scope,
		RunID:      res.RunID,
		FirstRun:   res.FirstRun,
		AssetCount: len(res.Assets),
		Changes:    res.Changes,
		Findings:   res.Findings,
	}
	if out.Changes == nil {
		out.Changes = []diff.Change{}
	}
	b, err := json.Marshal(out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "json error: %v\n", err)
		return
	}
	fmt.Println(string(b))
}

// scopeTemplate is written by `reconsentry init`.
const scopeTemplate = `# reconsentry scope.
# Only monitor targets you own or that are explicitly in scope for an
# authorized bug-bounty / vulnerability-disclosure program.

name: my-program

targets:
  - example.com
  # - example.org

# Hosts/subtrees to ignore (exact host or any subdomain of it).
exclude:
  - internal.example.com

# Minimum priority to report: low | medium | high
min_priority: medium

# Alert when a host's resolved IP changes. Off by default: CDN/cloud hosts
# (Vercel, Cloudflare, ...) rotate IPs constantly and would spam false alerts.
track_ip: false

# Passive mode: monitor on discovery alone — no active probing (httpx),
# scanning (--scan-new) or crawling (--crawl). Use for programs that forbid
# active scanning. Only NEW_HOST / HOST_GONE changes are reported.
passive: false

# Substrings that mark a newly-found host as high-value: any new host whose
# name contains one is promoted to high priority and starred in the alert, so
# it survives a high min_priority and stands out. Omit this list to use the
# built-in defaults (admin, staging, api, vpn, jenkins, grafana, .git, ...).
# interesting:
#   - admin
#   - staging
#   - payments

# Each list is a set of destination URLs rendered in that platform's format.
# A scope can fan out to all destinations at once.
#
# Keep secrets out of this file — reference environment variables as ${VAR},
# e.g.  token: ${TG_TOKEN}   or   password: ${SMTP_PASS}
notify:
  webhooks: []   # generic JSON POST
  slack: []      # Slack incoming-webhook URLs
  discord: []    # Discord webhook URLs
  telegram: []   # Telegram Bot API targets
  email: []      # SMTP email targets
`
