# Launch copy

Drafts for announcing ReconSentry. Authorized-use framing leads every post — it
matters for a security audience. Attach a screenshot of the sample report
(`docs/sample-report.html`, captured with the 🌊 spike + `NEW` badges visible) —
that image is the single most important viral asset.

Links:
- Repo: https://github.com/maruftak/reconsentry
- Demo / landing: https://maruftak.github.io/reconsentry/
- Sample report: https://maruftak.github.io/reconsentry/sample-report.html

---

## Show HN

**Title:** `Show HN: ReconSentry – a single Go binary that alerts when your attack surface changes`

I do bug bounties, and the annoying part isn't *finding* subdomains — tools like
subfinder/amass do that fine. It's that I have to re-run them and diff the output
by hand to notice when something *new* appears. The new asset is where the bounty
is, and on a busy program 500 hunters are racing to it.

ReconSentry is the diff+prioritize+alert layer on top of recon. It snapshots your
(authorized) targets on a schedule into SQLite, computes what changed since last
run, ranks it (a new live host is high; a CDN IP shuffle is low), and pushes a
clean alert to Slack/Discord/Telegram/email/webhook.

It's one static Go binary — no Docker, no Postgres, no web server. The closest
tools (reNgine, Osmedeus) are great but need real infra; I wanted something I
could drop on a $5 VPS or a GitHub Action.

Things I think are novel:
- `reconsentry report` renders your whole snapshot history into a single
  self-contained HTML file — a "git log for your attack surface." Commit it or
  publish it on Pages.
- It flags **surface spikes**: a run that adds an abnormal burst of new hosts vs
  the target's own history — i.e. the moment a target is actively shipping.
- New hosts whose names look juicy (admin, staging, api, vpn, jenkins, …) get
  auto-promoted and starred in the alert.

Discovery uses 5 passive sources (subfinder, crt.sh, Wayback, OTX, Anubis) plus
optional httpx probing, nuclei scanning, katana crawling, and TLS cert-expiry
checks. Passive-only mode for programs that forbid active scanning.

MIT. Authorized targets only. Live demo + sample report on the page.

Repo: https://github.com/maruftak/reconsentry
Demo: https://maruftak.github.io/reconsentry/

---

## r/netsec

**Title:** `ReconSentry: continuous attack-surface change monitoring as a single Go binary (diff → prioritize → alert + HTML changelog)`

Built an open-source attack-surface monitor aimed at the "tell me what *changed*"
gap. Most recon tooling is discovery-first; ReconSentry sits on top and does
snapshot → diff → priority → alert, on a schedule, with no infra (one Go binary +
SQLite).

Detects: `NEW_HOST`, `HOST_LIVE`, `STATUS_CHANGE`, `IP_CHANGE`, `NEW_TECH`,
`HOST_GONE`, `CERT_EXPIRING`, `NEW_ENDPOINT`, `VULN_FOUND` (nuclei on new hosts).
Notifiers: Slack/Discord/Telegram/email/generic webhook, per-scope.

A few things worth feedback on:
- **Surface-spike detection** — flags a run where new-host count is an abnormal
  burst vs the scope's recent baseline. A "something's launching, look now"
  signal rather than per-host noise.
- **Self-contained HTML "surface changelog"** — replays snapshot history through
  the diff engine into one portable file (no JS framework, works offline).
- **Interesting-host highlighting** — new hosts matching admin/staging/api/vpn/…
  are auto-promoted and starred.

Multi-scope, passive mode (discovery-only for scan-forbidding programs),
`--max-hosts` bounding, SARIF output for code-scanning dashboards, a `diff`
command to compare any two snapshots, and a reusable GitHub Action for CI
monitoring.

Designed for authorized engagements / VDP scope only — README leads with that.

Repo + live sample report: https://github.com/maruftak/reconsentry

---

## X / Twitter thread

**1/** Bug bounty truth: finding subdomains is solved. Noticing the *new* one
before 500 other hunters is not.

Built ReconSentry — a single Go binary that watches your authorized targets and
pings you the second the attack surface changes. 🧵

**2/** It's the layer recon tools skip: snapshot → diff → prioritize → alert.
New live host = 🔴 high. CDN IP shuffle = low. You only hear what matters, in
Slack/Discord/Telegram/email.

**3/** No infra. No Docker, no Postgres, no web UI to babysit. One static binary +
a SQLite file. Run it on a $5 box or a GitHub Action.

**4/** `reconsentry report` → one self-contained HTML file: a *git log for your
attack surface*. Every change since baseline, on a timeline. Commit it. Publish
it. Screenshot it. 👇 [attach report screenshot]

**5/** It also flags 🌊 **surface spikes** — when a target suddenly adds a burst of
hosts. That's a launch/migration in progress. That's where you go first.

**6/** And juicy new hosts (admin, staging, api, vpn, jenkins…) get auto-starred
so the bounty-likely asset never gets buried.

**7/** MIT. Authorized targets only.
⭐ https://github.com/maruftak/reconsentry
Live demo: https://maruftak.github.io/reconsentry/

---

## Posting notes

- **Screenshot first.** Open the sample report, capture the timeline with the
  spike + NEW badges. Reuse it on HN (as a comment), r/netsec, and X.
- **Timing.** Show HN: weekday morning US-Pacific. r/netsec: any weekday.
- **Engage.** Reply to early comments fast; that drives ranking on HN and Reddit.
- **awesome-lists.** Open PRs to `awesome-hacking`, `awesome-bugbounty-tools` for
  slow-burn organic discovery.
