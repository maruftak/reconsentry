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

r/netsec is strict. Submit as a **link post to the repo** (not a text/self-promo
post), keep the **title factual** (no marketing voice, no emoji), and put the
substance in a **first comment as OP** with an author disclosure. The sub respects
tools that (a) orchestrate existing tooling rather than reinvent it and (b) state
their limits plainly — both are leaned into below. Expected flair: Tool. Reply to
early technical questions fast; that drives ranking.

**Title:** `ReconSentry – a single Go binary that monitors an attack surface for changes (new subdomains, subdomain-takeover risk, DNS record flips) and alerts you`

**Alt title:** `ReconSentry: continuous attack-surface change monitoring (snapshot → diff → prioritize → alert), open source, no infra`

**First comment (post as OP):**

Author here. ReconSentry is an open-source (MIT) attack-surface *change* monitor.
It targets the "tell me what changed" gap rather than discovery: subfinder/amass
already enumerate well; the manual part is re-running them and diffing the output
to catch the one *new* asset — which on a busy program is where everyone races.

How it works: it orchestrates existing tools (subfinder + httpx, plus passive
crt.sh / Wayback / OTX / Anubis) instead of reinventing them, snapshots the result
to SQLite on a schedule, diffs against the previous run, assigns a priority, and
pushes only what crosses a threshold to Slack/Discord/Telegram/email/webhook. One
static binary — no Docker/Postgres/web UI — so it runs on a small VPS or entirely
inside a GitHub Action (SQLite committed back for history).

Change kinds: NEW_HOST, HOST_LIVE, STATUS_CHANGE, IP_CHANGE, NEW_TECH, HOST_GONE,
CERT_EXPIRING, TAKEOVER_RISK, DNS_CHANGE. Optional katana crawl and nuclei scan of
*newly seen* hosts only.

The two parts I'd most want feedback on:

- **Subdomain-takeover monitoring (`--takeover`)** — resolves the CNAME chain and
  matches a fingerprint table (curated subset of can-i-take-over-xyz, cross-checked
  against subjack and nuclei). Deliberately conservative to keep signal high: "high
  confidence" only when the CNAME points at a claimable service *and* the unclaimed
  fingerprint matches (or the target stops resolving, for NXDOMAIN-style services);
  services that show an unclaimed page but block re-registration (GitHub Pages,
  Heroku, Shopify, Fastly…) are reported as informational, never as a takeover.
  Every hit is flagged "requires manual confirmation," never proof.
- **DNS-record monitoring (`--dns`)** — tracks NS (delegation change / possible
  zone hijack) and CNAME (takeover precursor) per host and reports the diff.

Other bits: surface-spike detection (a run that adds an abnormal burst of new hosts
vs the scope's own baseline — a "something's launching" signal, not per-host
noise), a self-contained offline HTML "surface changelog," multi-scope,
passive-only mode for scan-forbidding programs, `--max-hosts` bounding, and SARIF
output for code-scanning dashboards.

Honest limitations: discovery is only as good as subfinder + the passive sources
(no brute-force / permutation engine yet); tech fingerprinting is httpx's; the
takeover fingerprint set is a curated subset, not exhaustive; and it's young, so
the diff/priority heuristics need real-world tuning — false-positive/negative
reports are exactly what I'm after.

Authorized targets only (assets you own or explicitly in a bounty/VDP scope); the
README leads with that.

Repo (with a live sample report): https://github.com/maruftak/reconsentry

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
