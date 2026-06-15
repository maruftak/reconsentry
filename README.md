# ReconSentry

[![CI](https://github.com/maruftak/reconsentry/actions/workflows/ci.yml/badge.svg)](https://github.com/maruftak/reconsentry/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/maruftak/reconsentry)](https://goreportcard.com/report/github.com/maruftak/reconsentry)
[![Go Reference](https://pkg.go.dev/badge/github.com/maruftak/reconsentry.svg)](https://pkg.go.dev/github.com/maruftak/reconsentry)
[![Release](https://img.shields.io/github/v/release/maruftak/reconsentry?sort=semver)](https://github.com/maruftak/reconsentry/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Know the moment your target's attack surface changes.**

`reconsentry` is a continuous attack-surface change monitor for bug-bounty hunters and
security teams. It watches the targets you're authorized to test and alerts you the
instant a **new subdomain, a newly-live host, a status change, an IP change, or new
technology** appears — so you reach fresh assets before everyone else.

Existing recon tools are great at *discovery* but leave you to diff the output by hand.
`reconsentry` closes that gap: it snapshots your surface on a schedule, computes the
difference, prioritizes what matters, and pushes a clean alert to Slack / Discord / any
webhook.

🌐 **[Landing page & live HTML report demo →](https://maruftak.github.io/reconsentry/)**

![reconsentry detecting a new host appearing on a target's attack surface](docs/demo.gif)

> ⚠️ **Authorized use only.** Point `reconsentry` at assets you own or domains that are
> explicitly in scope for a bug-bounty / VDP program. Recon against systems you don't
> have permission to test may be illegal.

## How it works

```
targets ──> discover ──> probe ──> snapshot ──> diff vs last run ──> prioritize ──> alert
            (subfinder)  (httpx)   (SQLite)      (NEW_HOST, …)       (low/med/high) (webhook)
```

`reconsentry` orchestrates battle-tested tools instead of reinventing recon. Its value is
the **diff + prioritization + alerting** layer on top.

## Install

`reconsentry` is a single Go binary. It shells out to [`subfinder`][sf] and [`httpx`][hx]
(from ProjectDiscovery) for discovery and probing — install those too. Subdomain
discovery is also augmented by [crt.sh][crtsh] certificate-transparency logs, the
[Wayback Machine][wb] URL index, and [AlienVault OTX][otx] passive DNS over plain
HTTP, so those sources need no extra install.

```bash
# reconsentry
go install github.com/maruftak/reconsentry/cmd/reconsentry@latest

# required recon tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

> **Note:** ProjectDiscovery's `httpx` can collide on `PATH` with the unrelated Python
> `httpx` CLI. If probing misbehaves, run `httpx -version` and ensure the ProjectDiscovery
> binary resolves first on your `PATH`.

Or build from source:

```bash
git clone https://github.com/maruftak/reconsentry
cd reconsentry
go build -o reconsentry ./cmd/reconsentry
```

## Quick start

1. Scaffold a scope file and edit your targets:

```bash
reconsentry init            # writes a commented scope.yaml
```

```yaml
name: my-program
targets:
  - example.com
exclude:
  - internal.example.com
min_priority: medium          # low | medium | high
# Each list is a set of destination URLs rendered in that platform's format,
# so one scope can alert all three at once.
notify:
  slack:
    - https://hooks.slack.com/services/XXX/YYY/ZZZ
  discord: []
  webhooks: []                # generic JSON POST
  telegram:                   # Telegram Bot API (sendMessage)
    - token: "123456:ABC-DEF"
      chat_id: "987654321"
  email:                      # SMTP
    - smtp_host: smtp.gmail.com
      smtp_port: 587
      username: alerts@example.com
      password: "app-password"
      from: alerts@example.com
      to: [me@example.com]
```

2. Record a baseline, then monitor:

```bash
# first run records a baseline (no diff)
reconsentry run --config scope.yaml

# run again later — only changes are reported
reconsentry run --config scope.yaml

# or monitor continuously every 6 hours
reconsentry run --config scope.yaml --interval 6h
```

### Flags

| Flag         | Default          | Purpose                                           |
| ------------ | ---------------- | ------------------------------------------------- |
| `--config`   | _(required)_     | path to the scope file                            |
| `--db`       | `reconsentry.db` | SQLite snapshot database                          |
| `--interval` | `0` (run once)   | monitor continuously on this interval (e.g. `6h`) |
| `--timeout`  | `10m`            | max duration per run cycle (`0` = no limit)       |
| `--keep`     | `0` (keep all)   | retain only the most recent N snapshots per scope |
| `--max-hosts`| `0` (no limit)   | probe at most N hosts per run; safety bound for huge scopes |
| `--dry-run`  | `false`          | print changes without sending notifications       |
| `--json`     | `false`          | emit results as JSON (one object per cycle)       |
| `--sarif`    | `""`             | write each cycle's changes to a SARIF file        |

`--json` makes runs scriptable, e.g. surface only high-priority changes:

```bash
reconsentry run --config scope.yaml --json \
  | jq '.changes[] | select(.priority >= 3) | "\(.kind) \(.host)"'
```

`--sarif` writes a [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) file (one
run per scope, each change a result) so a scheduled run can upload its findings
to GitHub code scanning or any SARIF-aware dashboard:

```bash
reconsentry run --config scope.yaml --sarif reconsentry.sarif
```

### `git log` for your attack surface

`reconsentry report` turns a scope's snapshot history into a **single,
self-contained HTML file** — no server, no JS framework, no external assets.
Open it locally, commit it next to your scope file, or publish it on GitHub
Pages as a living *surface changelog* your whole team can read:

```bash
reconsentry report --config scope.yaml -o surface.html
# wrote surface.html (3 run(s), 5 host(s))
```

It replays every recorded run through the same diff engine the alerts use, so
the report shows a priority-coloured **timeline of every change since the
baseline** (`NEW_HOST`, `STATUS_CHANGE`, …), a live/down surface table with a
`NEW` badge on freshly-seen hosts, and at-a-glance KPIs. One portable file you
can screenshot, share, or version-control.

It also flags a **🌊 surface spike** — a run that added an abnormal burst of new
hosts versus the scope's own recent history. A spike is the moment a target is
actively shipping surface, which is exactly when you want to be looking.

👉 **[See a rendered sample report](docs/sample-report.html)** (open the raw
file — it's fully offline).

### Run it in CI (GitHub Action)

`reconsentry` ships a reusable composite action, so you can monitor on a schedule
without hosting anything — commit the SQLite db back to persist history and
upload the HTML report as a build artifact:

```yaml
- uses: maruftak/reconsentry@v1
  with:
    config: scope.yaml
    db: reconsentry.db
    args: --max-hosts 1000
    report: surface.html
  env:
    SLACK_WEBHOOK: ${{ secrets.SLACK_WEBHOOK }}
```

A full scheduled example is in [`examples/github-action.yml`](examples/github-action.yml).
Use only on authorized targets, and keep notifier secrets in Actions secrets
(referenced as `${ENV_NAME}` in the scope file).

### Live surface badge

`reconsentry badge` renders a self-contained, embeddable SVG of the scope's live
surface plus its **change velocity** — host count, live count, and the net
change over a window (default 7 days). It turns **amber** when the surface is
growing (a hunter's cue that the target is shipping) and stays green otherwise:

```bash
reconsentry badge --config scope.yaml -o badge.svg
# renders: attack surface | 38/42 live ▲3
```

![example surface badge](docs/surface-badge.svg)

Drop it in a README or serve it from GitHub Pages so the surface state is always
one glance away.

### Inspect the current surface

`run` reports *changes*; `assets` shows the *latest snapshot* straight from the
database, no re-probing — so your recorded surface isn't a black box:

```bash
reconsentry assets --config scope.yaml
# 1 asset(s) for my-program (latest snapshot):
#   app.example.com   live 200  93.184.216.34   [HSTS, Next.js, Vercel]

reconsentry assets --config scope.yaml --json | jq '.[] | select(.alive)'
```

And `history` lists past runs, so you can see the monitoring cadence and how the
surface size moved over time:

```bash
reconsentry history --config scope.yaml
# 2 run(s) for my-program (most recent first):
#   #2     2026-06-11 22:25:16  7 asset(s)
#   #1     2026-06-10 22:25:11  5 asset(s)
```

### Monitor multiple programs

Declare several scopes under a top-level `scopes:` list and `reconsentry run`
monitors them all in one process — each with its own targets, priority, and
notification destinations (see [`examples/multi-scope.yaml`](examples/multi-scope.yaml)):

```yaml
scopes:
  - name: acme-public
    targets: [acme.com]
    notify: { slack: [https://hooks.slack.com/services/XXX] }
  - name: widgets-vdp
    targets: [widgets.example]
    min_priority: high
```

`assets` and `history` then take `--scope <name>` to pick one. Single-scope
files keep working with no changes.

### Interesting-host highlighting

Some new subdomains scream "look here": `admin`, `staging`, `dev`, `api`,
`vpn`, `jenkins`, `grafana`, `gitlab`, … Any newly-discovered host whose name
contains one of these is **promoted to high priority and starred** in the
alert, so the bounty-likely asset survives a high `min_priority` and stands out
from routine churn:

```
🔴 NEW_HOST  admin-beta.acme.com  [200, Django]  ⭐ interesting: admin
```

A built-in default keyword set applies out of the box. Override it per scope:

```yaml
name: acme-public
targets: [acme.com]
interesting:
  - payments
  - admin
  - graphql
```

### Passive mode

Some programs forbid active scanning. Set `passive: true` on a scope to monitor
it on discovery alone — reconsentry skips the `httpx` probe, `--scan-new`, and
`--crawl` for that scope and reports only `NEW_HOST` / `HOST_GONE`. It is
per-scope, so an active scope and a passive one can run in the same process.

```yaml
name: scan-forbidding-vdp
targets: [example.com]
passive: true
```

### Telegram and email notifications

Telegram and email destinations live under the same `notify:` block as Slack,
Discord, and generic webhooks. The scaffold from `reconsentry init` includes the
empty fields, and [`examples/multi-scope.yaml`](examples/multi-scope.yaml) shows
how each scope can choose its own notification destinations.

Keep tokens and SMTP passwords out of checked-in YAML by referencing environment
variables with `${ENV_NAME}`. `reconsentry` expands those values before
validation, so a missing secret fails fast instead of sending a broken alert.

For Telegram:

1. Create a bot with BotFather and copy the bot token.
2. Send a message to the bot from the target chat.
3. Get the chat ID from the Telegram Bot API.

```yaml
notify:
  telegram:
    - token: ${TG_TOKEN}
      chat_id: ${TG_CHAT_ID}
```

For email, configure an SMTP submission server and at least one recipient. When
`smtp_port` is omitted, the notifier defaults to `587`.

```yaml
notify:
  email:
    - smtp_host: smtp.example.com
      smtp_port: 587
      username: ${SMTP_USER}
      password: ${SMTP_PASS}
      from: alerts@example.com
      to:
        - security@example.com
```

## What it detects

| Change          | Priority | Meaning                                   |
| --------------- | -------- | ----------------------------------------- |
| `NEW_HOST`      | high     | a subdomain that wasn't there before      |
| `HOST_LIVE`     | high     | a known host that just started responding |
| `STATUS_CHANGE` | medium   | HTTP status code changed                  |
| `IP_CHANGE`     | low      | resolved IP changed (opt-in via `track_ip`; off by default — noisy on CDNs) |
| `NEW_TECH`      | low      | a new technology fingerprint              |
| `HOST_GONE`     | low      | a host stopped resolving/responding       |
| `CERT_EXPIRING` | high     | a host's TLS cert is near expiry (opt-in via `--cert-check`) |

## Roadmap

The planned roadmap has shipped: multi-scope configs, `history` / `assets`,
`--keep` retention, Telegram + email notifiers, `--crawl` (katana endpoints),
`--scan-new` (nuclei), passive mode, and most recently:

- [x] richer notifier formatting — Slack blocks / Discord embeds, grouped by
      priority with severity emoji and limit-safe chunking
- [x] more passive discovery sources — crt.sh, Wayback, OTX, and Anubis
- [x] `report` — a self-contained HTML surface changelog (no server, one file)

Ideas for what's next are welcome — open an issue.

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Good first issues are
labeled `good-first-issue`.

## License

MIT — see [LICENSE](LICENSE).

[sf]: https://github.com/projectdiscovery/subfinder
[hx]: https://github.com/projectdiscovery/httpx
[crtsh]: https://crt.sh
[wb]: https://web.archive.org
[otx]: https://otx.alienvault.com
