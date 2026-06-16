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

Pick whichever fits — every path ships the same single, dependency-free binary.

### Docker — zero setup (recommended)

The image is **batteries-included**: `reconsentry`, [`subfinder`][sf], and
[`httpx`][hx] are all baked in, so there's nothing else to install and no `PATH`
collision to untangle.

```bash
docker run --rm -v "$PWD:/work" -w /work \
  ghcr.io/maruftak/reconsentry:latest run --config scope.yaml
```

### Homebrew (macOS / Linux)

```bash
brew install maruftak/tap/reconsentry
```

### Prebuilt binary

Download a build for your OS/arch from the [latest release][rel] — no toolchain
required. Unpack it and put `reconsentry` on your `PATH`.

### `go install`

```bash
go install github.com/maruftak/reconsentry/cmd/reconsentry@latest
```

For every non-Docker path, also install the two ProjectDiscovery tools
`reconsentry` shells out to for active discovery and probing (passive sources —
[crt.sh][crtsh], the [Wayback Machine][wb], [AlienVault OTX][otx] — need no
install):

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

> **Note:** ProjectDiscovery's `httpx` can collide on `PATH` with the unrelated Python
> `httpx` CLI. If probing misbehaves, run `httpx -version` and ensure the ProjectDiscovery
> binary resolves first on your `PATH`. The Docker image sidesteps this entirely.

### Build from source

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

`diff` compares any two stored runs without re-probing — pass two run ids (from
`history`), or none to compare the two most recent:

```bash
reconsentry diff --config scope.yaml          # latest run vs the previous one
reconsentry diff --config scope.yaml 1 4      # what changed between run #1 and #4
reconsentry diff --config scope.yaml --json 1 4 | jq '.[] | select(.priority >= 3)'
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

### Subdomain takeover monitoring

A subdomain takeover is one of the highest-payout, lowest-effort findings in
bug bounty: a host whose DNS still points at a third-party service (S3, Azure,
Ghost, GitHub Pages, …) that has been de-provisioned, so an attacker can
re-register the resource and serve content from the victim's domain. Other
tools scan for this once; `reconsentry` watches for the **moment a host slips
into a takeover-able state** and alerts you — exactly when you want to be first.

Enable it with `--takeover`. For every host it resolves the CNAME chain and
matches the response against an embedded fingerprint table (a curated subset of
[can-i-take-over-xyz][citox], cross-checked against subjack and nuclei):

```bash
reconsentry run --config scope.yaml --takeover
```

```
🚨 TAKEOVER_RISK  blog.acme.com  potential Ghost takeover (high confidence):
   unclaimed-resource fingerprint via CNAME → acme.ghost.io — manual confirmation required
```

Detection is deliberately conservative, to keep the signal high:

- **High confidence (critical)** — the CNAME points at a known-claimable
  service *and* the response carries that service's "unclaimed" fingerprint
  (or, for NXDOMAIN-style services like Azure / Elastic Beanstalk, the CNAME
  target no longer resolves).
- **Lower confidence (high)** — only the body fingerprint matched; flagged for
  manual confirmation.
- **Informational (low)** — the host is parked on a service that *recognizes*
  an unclaimed page but **blocks re-registration** (GitHub Pages, Heroku,
  Shopify, Fastly, …). Reported so you know it's dangling, never as a takeover,
  so you aren't sent chasing a dead end.

> ⚠️ A `TAKEOVER_RISK` is a **risk indicator requiring manual confirmation**, never
> proof of compromise. Confirm ownership and claimability yourself before
> reporting, and never register a resource you are not authorized to claim.

`--takeover` is active HTTP/DNS traffic, so it is skipped for `passive: true`
scopes.

### DNS-record monitoring

`--dns` tracks each host's **`CNAME`**, **`NS`**, **`MX`**, and **`TXT`** records
and reports a change when they move between runs:

```bash
reconsentry run --config scope.yaml --dns
```

```
🔴 DNS_CHANGE  acme.com         NS +ns1.new-registrar.com -ns1.old-registrar.com
🟠 DNS_CHANGE  blog.acme.com    CNAME old.hosting.net → new.hosting.net
🟠 MX_CHANGE   acme.com         MX aspmx.l.google.com → mx.sendgrid.net
🔴 TXT_CHANGE  acme.com         TXT v=spf1 ... -all → v=spf1 ... ~all — SPF weakened
🔴 TXT_CHANGE  _dmarc.acme.com  TXT v=DMARC1; p=reject → v=DMARC1; p=none — DMARC weakened
```

Why these record types:

- **`NS` change (high)** — the zone's delegation moved. That can mean a domain
  transfer, a misconfiguration, or a nameserver that's now unclaimed (an NS
  takeover). Worth knowing immediately.
- **`CNAME` change (medium)** — a host now points somewhere new. Often a benign
  infra move, but it's also the first step toward a dangling-record takeover, so
  it pairs naturally with `--takeover`.
- **`MX` change (medium)** — the host's mail flow moved to a different server
  set. Could be a planned migration, or mail being silently rerouted.
- **`TXT` change (low, escalates to high)** — a TXT record set changed. Most are
  routine (a new SaaS-verification token), so the default is low. But a change
  that **weakens email authentication** is escalated to **high**: an `SPF`
  record removed or its terminal `all` qualifier softened (`-all` → `~all` →
  `?all` → `+all`), or — looking up `_dmarc.<host>` — the `DMARC` record removed
  or its `p=` policy softened (`reject` → `quarantine` → `none`). These are the
  changes that newly enable email spoofing of the domain.

`NS` records only exist at zone cuts (the apex and delegated subdomains), and
`CNAME` / `MX` / `TXT` only where configured, so plain A-record hosts produce
nothing — the output stays high-signal. The first `--dns` run is a baseline;
later runs report the diff.

Unlike the active probes, DNS resolution only queries resolvers (not the
target's own servers), so `--dns` is benign passive recon and runs even for
`passive: true` scopes.

### Content-change monitoring (`--content`)

A host you already know about is worth re-checking when the **page it serves**
changes — a re-platform exposes a fresh attack surface, an error page replaced
by a real app is a new target, and a login or admin panel appearing where there
wasn't one is a lead. `--content` fingerprints each **live** host's page and
reports a `CONTENT_CHANGE` when it *materially* moves between runs:

```bash
reconsentry run --config scope.yaml --content
```

```
🔴 CONTENT_CHANGE  api.acme.com    page came online [403 → 200]
🟠 CONTENT_CHANGE  shop.acme.com   favicon changed (re-platform), body content changed (simhash Δ27/64) + title changed
```

The fingerprint is three stable signals, none of which is the raw page:

- **favicon hash** — httpx's mmh3 favicon hash (when available). A re-skin often
  swaps the favicon first, so a flip is a strong re-platform tell.
- **body simhash** — a 64-bit [simhash](https://en.wikipedia.org/wiki/SimHash)
  of the page's *normalized* text. Near-identical pages share most bits, so a
  change is measured as a Hamming distance; only a move past a conservative
  threshold counts as material.
- **title hash** — a cheap corroborator. It is mentioned in the alert alongside
  a real trigger but **never fires a change on its own** (titles churn for
  cosmetic reasons constantly).

A change fires when the favicon flips, the body simhash moves past the
threshold, or the page **comes online** (a non-`2xx` status crossing into
`2xx`). Coming online is `high` priority — an app just appeared; everything else
is `medium`.

The reason it doesn't drown you in false positives is the **normalization**
before the simhash: the body is lowercased, stripped of HTML tags to plain text,
and scrubbed of high-entropy per-render noise — CSRF tokens, nonces, long
hex/base64 runs, ISO timestamps, and epoch seconds — before being shingled into
word 3-grams. So a page that only rotated its anti-CSRF token or its
"generated at" timestamp hashes to (nearly) the same value and stays quiet,
while a genuinely new page moves well past the threshold.

Because it fetches page bodies, `--content` is **active traffic** and is skipped
for `passive: true` scopes. The first `--content` run is a baseline; later runs
report the diff. A host that fails to serve on a given run is ignored rather
than alerted, and its failed fetch never overwrites the stored baseline — so a
transient outage doesn't cost you the comparison point.

### Signal correlation (`--correlate`)

Each change kind above already alerts on its own. But the signal a human can't
eyeball across hundreds of hosts is when **several distinct kinds land on the
*same* host in one run** — a host that just appeared *and* picked up a new
technology *and* had its CNAME flip is not three small events, it's one story:
that target is actively moving (a migration, a launch, a soft target mid-deploy).
`--correlate` fuses those co-occurring changes into a single high-confidence
`HOT_TARGET` finding so the host in motion rises above the per-event churn.

```bash
reconsentry run --config scope.yaml --correlate
```

```
🚨 HOT_TARGET  blog.acme.com    2 correlated signals: DNS_CHANGE · TAKEOVER_RISK — target likely shipping, prioritize
🔴 HOT_TARGET  staging.acme.com 3 correlated signals: NEW_HOST · NEW_TECH (Jenkins) · interesting:staging — target likely shipping, prioritize
```

It is pure post-processing of the changes a run already computed — no extra
network, scanning, or I/O, and fully deterministic. The originals are **kept**;
the `HOT_TARGET` is *added* alongside them.

How a host qualifies. Each contributing change kind on the host carries a weight
(higher = a stronger sign of motion):

| Signal | Weight | | Signal | Weight |
| --- | --- | --- | --- | --- |
| `TAKEOVER_RISK` | 4 | | `MX_CHANGE` | 2 |
| `DNS_CHANGE` | 3 | | `TXT_CHANGE` | 2 |
| `CONTENT_CHANGE` | 3 | | `NEW_TECH` | 1 |
| `NEW_HOST` | 2 | | `STATUS_CHANGE` | 1 |
| `HOST_LIVE` | 2 | | `CERT_EXPIRING` / `IP_CHANGE` / `HOST_GONE` | 1 |

A host is fused into a `HOT_TARGET` when **both**:

- it has **≥ 2 distinct** contributing change kinds — the rule that makes a
  finding genuinely *correlated*, never a single loud signal (a lone
  `TAKEOVER_RISK` scores 4 but already alerts on its own, so it is not re-fused); and
- its **weighted score ≥ 4** (the default threshold).

Booster: if the host name matches the [interesting-host](#interesting-host-highlighting)
keywords (`admin`, `staging`, `api`, `jenkins`, …) it gets **+2**, so a
bounty-likely asset crosses the bar on weaker evidence. The finding's priority is
**critical** when any contributing change is critical (e.g. a claimable
takeover), otherwise **high**; the detail lists the contributing signals in a
stable, sorted order. Because `HOT_TARGET` is just another change kind, it flows
through prioritization, every notifier, the JSON output, and the SARIF export
exactly like the rest. With the flag off, nothing changes.

## MCP server

`reconsentry mcp` runs a **read-only [MCP](https://modelcontextprotocol.io)
server over stdio** that exposes the snapshot database to an AI agent (Claude
Desktop, Claude Code, …), so you can ask about a target's attack surface in
plain language: *"what new hosts appeared in acme since the last run?"*,
*"list the live admin hosts"*, *"show me the high-priority changes."*

It is strictly reporting over **already-collected** data. It never scans,
probes, resolves, or writes — every tool is a pure read, the database is opened
in SQLite read-only mode, and the tools are annotated read-only so the agent
knows they have no side effects. Run `reconsentry run …` to collect; run
`reconsentry mcp` to let an agent explore what was collected.

```bash
# point it at a database a previous run populated
reconsentry mcp --db reconsentry.db

# --config is optional and only validates the file; scopes come from the db
reconsentry mcp --db reconsentry.db --config scope.yaml
```

It speaks MCP on stdout/stdin and prints only diagnostics to stderr, so it is
meant to be launched by an MCP client rather than run interactively.

**Tools exposed**

| Tool           | Arguments                                                              | Returns                                                                                  |
| -------------- | --------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `list_scopes`  | —                                                                     | the scope (program) names present in the database                                        |
| `list_assets`  | `scope` (optional if the db has one scope), `filter` (optional substring) | latest-snapshot hosts: `host`, `alive`, `status`, `ip`, `technologies`                   |
| `list_history` | `scope` (optional if the db has one scope)                            | recorded runs (`run_id`, `timestamp`, `asset_count`), most recent first                  |
| `get_changes`  | `scope`, `from_run_id`/`to_run_id` (optional), `min_priority` (`low`/`medium`/`high`) | classified changes — defaults to latest run vs the previous one — each with `kind`, `host`, `priority`, `detail` |

Unknown scopes or run ids come back as a clear tool error (e.g. `scope "ghost"
not found; available: acme`), never a crash. `get_changes` reuses the same diff
engine and priority filter as the monitor, so the changes match what an alert
would have reported.

**Claude Desktop / Claude Code config**

Add an entry to your MCP client config (Claude Desktop:
`claude_desktop_config.json`; Claude Code: `~/.claude.json` or
`.mcp.json`), pointing `command` at the `reconsentry` binary and giving it the
absolute path to your database:

```json
{
  "mcpServers": {
    "reconsentry": {
      "command": "/usr/local/bin/reconsentry",
      "args": ["mcp", "--db", "/path/to/reconsentry.db"]
    }
  }
}
```

Restart the client and ask it about your scopes. Only expose databases for
targets you are authorized to monitor.

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
| `TAKEOVER_RISK`  | critical | a host's dangling DNS record may be claimable — a subdomain takeover (opt-in via `--takeover`) |
| `DNS_CHANGE`     | high/med | a host's `NS` (high — delegation change) or `CNAME` (medium) record set changed (opt-in via `--dns`) |
| `MX_CHANGE`      | medium   | a host's `MX` (mail-flow) record set changed (opt-in via `--dns`) |
| `TXT_CHANGE`     | low/high | a host's `TXT` record set changed — high when it weakens email auth (SPF `all` softened/removed or DMARC `p=` softened/removed) (opt-in via `--dns`) |
| `CONTENT_CHANGE` | high/med | a known host's served page materially changed — a re-platform, a newly-exposed login/admin page, an app where an error page used to be, or a host coming online; high when the page comes online (non-2xx → 2xx), else medium (opt-in via `--content`) |
| `HOT_TARGET`     | critical/high | several distinct change kinds co-occurred on one host in a single run — a target in motion (opt-in via `--correlate`; critical when a contributing signal is critical, else high) |

## Roadmap

The planned roadmap has shipped: multi-scope configs, `history` / `assets`,
`--keep` retention, Telegram + email notifiers, `--crawl` (katana endpoints),
`--scan-new` (nuclei), passive mode, and most recently:

- [x] richer notifier formatting — Slack blocks / Discord embeds, grouped by
      priority with severity emoji and limit-safe chunking
- [x] more passive discovery sources — crt.sh, Wayback, OTX, and Anubis
- [x] `report` — a self-contained HTML surface changelog (no server, one file)
- [x] **subdomain takeover monitoring** (`--takeover`) — alert the moment a
      host's dangling DNS record becomes claimable
- [x] **DNS-record change monitoring** (`--dns`) — `CNAME` / `NS` flips
      (zone-hijack and takeover-precursor signals)
- [x] **`MX` / `TXT` record monitoring** (`--dns`) — mail-flow changes plus
      email-spoof signals: SPF/DMARC weakening escalates `TXT_CHANGE` to high
- [x] **read-only MCP server** (`reconsentry mcp`) — query a target's stored
      attack surface conversationally from an AI agent (no scanning, no writes)
- [x] **signal correlation** (`--correlate`) — fuse co-occurring change kinds on
      one host into a single `HOT_TARGET` finding (a target in motion)
- [x] **content-change monitoring** (`--content`) — fingerprint each live host's
      page (favicon hash + body simhash + title) and alert when it *materially*
      changes: a re-platform, a newly-exposed login/admin page, an app where an
      error page used to be, or a host coming online. Stable across cosmetic
      noise (CSRF tokens, timestamps, nonces). Unifies the favicon-hash and
      response-body (simhash) diff items.

Ideas for what's next are welcome — open an issue.

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Good first issues are
labeled `good-first-issue`.

## License

MIT — see [LICENSE](LICENSE).

[rel]: https://github.com/maruftak/reconsentry/releases
[sf]: https://github.com/projectdiscovery/subfinder
[hx]: https://github.com/projectdiscovery/httpx
[crtsh]: https://crt.sh
[wb]: https://web.archive.org
[otx]: https://otx.alienvault.com
[citox]: https://github.com/EdOverflow/can-i-take-over-xyz
