# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `badge` command: renders a self-contained shields.io-style SVG of a scope's
  live surface state with change velocity (e.g. `attack surface | 38/42 live
  ▲3`) — amber when the surface is growing, green otherwise. Embeddable in a
  README or servable from GitHub Pages.
- Reusable GitHub Action (`uses: maruftak/reconsentry@v1`) plus a scheduled
  example workflow, so a repo can monitor its surface in CI, persist the SQLite
  history, and upload the HTML report as an artifact — no hosting required.
- Project landing page and a published sample report under `docs/`, deployed to
  GitHub Pages via a `pages` workflow.
- `report` command: renders a scope's full snapshot history into a single
  self-contained HTML file (`reconsentry report --config scope.yaml -o
  surface.html`) — no server or external assets. It replays every run through
  the diff engine to show a priority-coloured timeline of every change since the
  baseline, a live/down surface table with `NEW` badges on freshly-seen hosts,
  and KPIs. A portable artifact you can commit or publish on GitHub Pages as a
  living "surface changelog". A rendered sample lives at `docs/sample-report.html`.
- A fourth passive subdomain-discovery source: [jldc.me Anubis](https://jldc.me).
  It is a pure HTTP collector (no install, no API key), enforces target scope,
  de-duplicates hosts, and fails soft per target like the other sources — a dead
  query degrades coverage instead of aborting the run. Closes #38.

## [0.5.0] - 2026-06-14

### Added
- `run --cert-check` fetches each live host's TLS certificate and reports
  `CERT_EXPIRING` (high priority) for any cert that is already expired or within
  the `--cert-days` window (default 30). Expiry is evaluated against the live
  cert each run; it is active TLS traffic, so it is skipped on passive scopes.
- `run --sarif PATH` writes the cycle's changes as a [SARIF 2.1.0] file (one run
  per scope, each change a result with its kind as the rule and priority mapped
  to a SARIF level), so a scheduled run can upload findings to GitHub code
  scanning or any SARIF-aware dashboard.

### Changed
- CI now runs `govulncheck` on every build, and Dependabot keeps Go modules and
  GitHub Actions up to date. The workflow actions were bumped off the deprecated
  Node 20 runtime (`checkout@v6`, `setup-go@v6`, `goreleaser-action@v7`).

[SARIF 2.1.0]: https://sarifweb.azurewebsites.net/

## [0.4.0] - 2026-06-14

### Added
- Three more passive subdomain-discovery sources alongside `subfinder`:
  [crt.sh](https://crt.sh) certificate-transparency logs, the
  [Wayback Machine](https://web.archive.org) URL index, and
  [AlienVault OTX](https://otx.alienvault.com) passive DNS. All are pure HTTP
  collectors (no extra install, no API key) and are safe on passive scopes. The
  collect layer fans out over every source, merges and de-duplicates the hosts,
  and fails soft per source — a missing `subfinder` binary or a dead endpoint
  degrades coverage instead of aborting the run; discovery only errors when
  every source fails. Closes #27.

### Changed
- Slack and Discord alerts are now grouped by priority (high → medium → low)
  with a severity emoji and per-group headers. Payloads are chunked to stay
  within platform limits (Slack's 3000-char section / 50-block caps, Discord's
  1024-char field / 25-field caps), so a large diff is delivered instead of
  being rejected. Long values are truncated on a rune boundary.

## [0.3.1] - 2026-06-12

### Added
- `run --max-hosts N` caps how many hosts are probed per cycle (seed targets are
  always kept), a safety bound so a target with thousands of discovered
  subdomains can't make `httpx` outrun `--timeout` and fail the whole run. A
  probe killed by the timeout now reports an actionable hint instead of a bare
  `signal: killed`. Default `0` = no limit.

## [0.3.0] - 2026-06-12

### Added
- Passive mode: set `passive: true` on a scope to monitor it on discovery alone.
  reconsentry skips the active `httpx` probe (and `--scan-new`/`--crawl`) for
  that scope and reports only `NEW_HOST` / `HOST_GONE`, so programs that forbid
  active scanning can still be watched. Per-scope, so active and passive scopes
  coexist in one run. Closes #12.
- `run --scan-new` runs [nuclei](https://github.com/projectdiscovery/nuclei)
  against newly-discovered hosts and surfaces results as `VULN_FOUND` changes
  (priority mapped from severity), so a new asset is reported together with what
  is exposed on it. Scanning only targets hosts from `NEW_HOST`/`HOST_LIVE`
  changes, never the whole surface. Closes #11.
- `run --crawl` crawls live hosts with [katana](https://github.com/projectdiscovery/katana)
  and reports first-seen URLs/params as `NEW_ENDPOINT` changes, extending
  monitoring from hosts to endpoints. The first crawl is a baseline; endpoints
  are stored per run and pruned alongside snapshots by `--keep`. Closes #10.

## [0.2.0] - 2026-06-12

### Added
- Email (SMTP) notifier: add `notify.email` entries (`smtp_host`, `from`, `to`,
  optional `smtp_port`/`username`/`password`) to receive alerts by email.
- Telegram notifier: add `notify.telegram` entries (`token` + `chat_id`) to
  alert via the Telegram Bot API. Delivery shares the same retry/backoff as the
  webhook notifiers.
- `run --keep N` prunes old snapshots, retaining only the most recent N per
  scope, so the database stays bounded over months of continuous monitoring
  (default 0 = keep everything).
- Multi-scope configs: a file may declare several scopes under a top-level
  `scopes:` list, and `run` monitors them all in one process (each isolated in
  the database). `assets` / `history` take `--scope <name>` to select one.
  Single-scope files keep working unchanged.
- `reconsentry assets --config scope.yaml [--json]` prints the latest captured
  snapshot (host, liveness, status, IP, tech) straight from the database — no
  re-probing — so the recorded surface is queryable, not a black box.
- `reconsentry history --config scope.yaml [--json]` lists past runs (timestamp
  and asset count, most recent first), making the monitoring cadence and how the
  surface size moved over time visible.
- `reconsentry init [path]` scaffolds a commented starter scope file.
- `--json` flag emits machine-readable run results (one object per cycle) for
  piping into other tooling.
- `--timeout` flag bounds each run cycle so a hung `subfinder`/`httpx` can't
  wedge a continuous monitor (default 10m).
- Webhook delivery now retries transient failures (network errors, HTTP 429/5xx)
  with backoff; permanent 4xx responses fail fast.
- Alert messages include a clickable `https://<host>` URL per change.
- `Makefile`, `.golangci.yml`, `CHANGELOG.md`, issue/PR templates, and a
  golangci-lint CI job.
- `${VAR}` environment-variable expansion in config values, so secrets (bot
  tokens, SMTP passwords, webhook URLs) can be kept out of the scope file and
  supplied via the environment. An unset variable expands to empty and fails
  validation.

### Changed
- **Breaking (config):** `notify.slack` and `notify.discord` are now lists of
  webhook URLs instead of booleans. A single scope can now fan out to a generic
  endpoint, Slack, and Discord simultaneously. Update existing scope files:

  ```yaml
  # before
  notify:
    webhooks: [https://hooks.slack.com/services/XXX]
    slack: true
  # after
  notify:
    slack: [https://hooks.slack.com/services/XXX]
  ```
- Notify endpoint URLs are validated (`http://`/`https://`) at config load.

### Fixed
- Strip a UTF-8 BOM (`U+FEFF`) from config files and host values. A BOM
  survives `strings.TrimSpace`, so a scope file saved by a Windows editor
  (e.g. Notepad) silently corrupted every target — the BOM rode along into
  the Host header and made the upstream return the wrong response. Found by
  running the tool against a live target.

### Removed
- Dead `prioritize.Sort` helper (results are already ordered by `diff.Diff`).

### Security
- Notifier transport errors no longer include the request URL, which can embed a
  secret — a Telegram bot token in the path, or a Slack/Discord webhook URL that
  is itself a credential. These errors surface to stderr/logs on delivery
  failure, so the URL is now stripped.

## [0.1.0]

### Added
- Initial MVP: `subfinder`/`httpx` collectors, SQLite snapshot store, pure
  snapshot diff with change classification (`NEW_HOST`, `HOST_LIVE`,
  `STATUS_CHANGE`, `IP_CHANGE`, `NEW_TECH`, `HOST_GONE`), priority filtering,
  and webhook/Slack/Discord notifications. Single run or continuous `--interval`
  monitoring. CI, Dockerfile, and GoReleaser config.
