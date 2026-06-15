package report

import (
	"bytes"
	"html/template"
	"sort"
	"time"

	"github.com/maruftak/reconsentry/internal/diff"
	"github.com/maruftak/reconsentry/internal/model"
)

// RunSnapshot is one recorded run's surface: the assets observed at a point in
// time. The HTML report replays consecutive snapshots through the diff engine
// to reconstruct the full attack-surface changelog.
type RunSnapshot struct {
	ID     int64
	At     time.Time
	Assets []model.Asset
}

// SurfaceReport is the input to HTML: a scope's full snapshot history.
type SurfaceReport struct {
	Scope       string
	GeneratedAt time.Time
	ToolVersion string
	Snapshots   []RunSnapshot
}

// HTML renders a self-contained attack-surface report: one portable HTML file
// with no external assets, safe to commit to a repo or publish on GitHub Pages
// as a living "surface changelog". It reuses the pure diff engine to turn the
// snapshot history into a visual timeline of every change.
func HTML(r SurfaceReport) ([]byte, error) {
	vm := buildView(r)
	var buf bytes.Buffer
	if err := surfaceTmpl.Execute(&buf, vm); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// --- view model -------------------------------------------------------------

type reportView struct {
	Scope       string
	Generated   string
	ToolVersion string
	KPIs        kpis
	Timeline    []timelineEntry // newest first
	Surface     []surfaceRow    // current snapshot, host-sorted
	Empty       bool
}

type kpis struct {
	Hosts   int
	Live    int
	Tech    int
	Runs    int
	Changes int
}

type timelineEntry struct {
	RunID    int64
	When     string
	Assets   int
	Baseline bool
	Groups   []changeGroup // changes grouped by kind, priority-ordered
	Total    int
	Spike    bool // an abnormal burst of new hosts vs the scope's recent history
	NewHosts int  // new hosts in this run (drives spike detection)
}

type changeGroup struct {
	Kind     string
	Priority int
	Hosts    []string
}

type surfaceRow struct {
	Host   string
	State  string // "live" | "down"
	Status int
	IP     string
	Tech   string
	New    bool // first seen in the latest snapshot
}

func buildView(r SurfaceReport) reportView {
	snaps := append([]RunSnapshot(nil), r.Snapshots...)
	sort.Slice(snaps, func(i, j int) bool { return snaps[i].ID < snaps[j].ID })

	vm := reportView{
		Scope:       r.Scope,
		Generated:   r.GeneratedAt.UTC().Format("2006-01-02 15:04:05 UTC"),
		ToolVersion: r.ToolVersion,
		Empty:       len(snaps) == 0,
	}
	if vm.Empty {
		return vm
	}

	latest := snaps[len(snaps)-1]
	vm.Surface, vm.KPIs = surfaceAndKPIs(snaps, latest)
	vm.Timeline, vm.KPIs.Changes = buildTimeline(snaps)
	vm.KPIs.Runs = len(snaps)
	return vm
}

func surfaceAndKPIs(snaps []RunSnapshot, latest RunSnapshot) ([]surfaceRow, kpis) {
	prevHosts := map[string]bool{}
	if len(snaps) >= 2 {
		for _, a := range snaps[len(snaps)-2].Assets {
			prevHosts[a.Host] = true
		}
	}

	rows := make([]surfaceRow, 0, len(latest.Assets))
	techSeen := map[string]bool{}
	var live int
	for _, a := range latest.Assets {
		state := "down"
		if a.Alive {
			state = "live"
			live++
		}
		for _, t := range a.Tech {
			techSeen[t] = true
		}
		rows = append(rows, surfaceRow{
			Host:   a.Host,
			State:  state,
			Status: a.Status,
			IP:     a.IP,
			Tech:   a.TechString(),
			New:    len(snaps) >= 2 && !prevHosts[a.Host],
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Host < rows[j].Host })

	return rows, kpis{Hosts: len(latest.Assets), Live: live, Tech: len(techSeen)}
}

func buildTimeline(snaps []RunSnapshot) ([]timelineEntry, int) {
	entries := make([]timelineEntry, 0, len(snaps))
	var totalChanges int

	var newHostHistory []int // new-host counts of preceding non-baseline runs
	for i, s := range snaps {
		e := timelineEntry{RunID: s.ID, When: s.At.UTC().Format("2006-01-02 15:04 UTC"), Assets: len(s.Assets)}
		if i == 0 {
			e.Baseline = true
		} else {
			changes := diff.Diff(snaps[i-1].Assets, s.Assets)
			e.Groups = groupChanges(changes)
			e.Total = len(changes)
			totalChanges += len(changes)

			for _, c := range changes {
				if c.Kind == diff.NewHost {
					e.NewHosts++
				}
			}
			e.Spike = isSpike(e.NewHosts, newHostHistory)
			newHostHistory = append(newHostHistory, e.NewHosts)
		}
		entries = append(entries, e)
	}

	// Newest first for display.
	for l, r := 0, len(entries)-1; l < r; l, r = l+1, r-1 {
		entries[l], entries[r] = entries[r], entries[l]
	}
	return entries, totalChanges
}

func groupChanges(changes []diff.Change) []changeGroup {
	byKind := map[diff.Kind]*changeGroup{}
	var order []diff.Kind
	for _, c := range changes {
		g, ok := byKind[c.Kind]
		if !ok {
			g = &changeGroup{Kind: string(c.Kind), Priority: c.Priority}
			byKind[c.Kind] = g
			order = append(order, c.Kind)
		}
		host := c.Host
		if host == "" {
			host = c.Detail
		}
		g.Hosts = append(g.Hosts, host)
	}

	groups := make([]changeGroup, 0, len(order))
	for _, k := range order {
		groups = append(groups, *byKind[k])
	}
	// Highest priority first, then kind name for stable output.
	sort.SliceStable(groups, func(i, j int) bool {
		if groups[i].Priority != groups[j].Priority {
			return groups[i].Priority > groups[j].Priority
		}
		return groups[i].Kind < groups[j].Kind
	})
	return groups
}

// --- template ---------------------------------------------------------------

func priorityName(p int) string {
	switch p {
	case diff.High:
		return "high"
	case diff.Medium:
		return "medium"
	default:
		return "low"
	}
}

var surfaceTmpl = template.Must(template.New("surface").Funcs(template.FuncMap{
	"prio": priorityName,
}).Parse(surfaceHTML))

const surfaceHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Scope}} — attack surface · reconsentry</title>
<style>
:root{
  --bg:#0b0f14; --panel:#121821; --panel2:#0e141c; --line:#1e2935;
  --txt:#e6edf3; --dim:#8b9bb0; --accent:#3ddc97; --accent2:#4aa8ff;
  --high:#ff5c7c; --medium:#ffb454; --low:#5b7089;
  --mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--txt);
  font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;}
a{color:var(--accent2);text-decoration:none}
.wrap{max-width:1080px;margin:0 auto;padding:40px 24px 80px}
header{display:flex;align-items:baseline;justify-content:space-between;
  flex-wrap:wrap;gap:12px;border-bottom:1px solid var(--line);padding-bottom:20px}
.brand{font-weight:700;letter-spacing:.5px}
.brand .dot{color:var(--accent)}
h1{font-size:30px;margin:18px 0 4px;font-weight:680}
.scope{font-family:var(--mono);color:var(--accent)}
.meta{color:var(--dim);font-size:13px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
  gap:14px;margin:28px 0 36px}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:12px;
  padding:16px 18px}
.kpi .n{font-size:28px;font-weight:720;font-family:var(--mono)}
.kpi .l{color:var(--dim);font-size:12px;text-transform:uppercase;letter-spacing:.6px}
.kpi.live .n{color:var(--accent)}
h2{font-size:13px;text-transform:uppercase;letter-spacing:1.2px;color:var(--dim);
  margin:40px 0 16px;font-weight:600}
/* timeline */
.tl{position:relative;margin-left:8px;padding-left:26px;border-left:2px solid var(--line)}
.tl .ev{position:relative;margin-bottom:26px}
.tl .ev::before{content:"";position:absolute;left:-34px;top:4px;width:11px;height:11px;
  border-radius:50%;background:var(--accent);box-shadow:0 0 0 4px var(--bg)}
.tl .ev.base::before{background:var(--low)}
.tl .ev.spike::before{background:var(--high);box-shadow:0 0 0 4px var(--bg),0 0 12px var(--high)}
.spike{display:inline-block;font-family:var(--mono);font-size:12.5px;font-weight:700;
  color:var(--high);background:#1a1014;border:1px solid #3a2630;border-radius:7px;
  padding:4px 10px;margin:2px 0 8px}
.ev .when{font-family:var(--mono);font-size:13px;color:var(--dim)}
.ev .sum{margin:4px 0 8px;font-weight:600}
.ev .sum b{font-family:var(--mono)}
.tag{display:inline-block;font-family:var(--mono);font-size:12px;
  padding:2px 8px;border-radius:6px;margin:3px 6px 3px 0;border:1px solid var(--line)}
.tag .k{font-weight:700}
.tag.high{color:var(--high);border-color:#3a2630;background:#1a1014}
.tag.medium{color:var(--medium);border-color:#3a3326;background:#1a1610}
.tag.low{color:var(--low);border-color:#26303a;background:#0e141c}
.tag .hosts{color:var(--dim);font-weight:400}
.quiet{color:var(--low);font-size:13px}
/* surface table */
.filter{width:100%;max-width:340px;background:var(--panel2);border:1px solid var(--line);
  color:var(--txt);border-radius:8px;padding:9px 12px;font-size:14px;margin-bottom:14px}
table{width:100%;border-collapse:collapse;font-size:14px}
th{text-align:left;color:var(--dim);font-weight:600;font-size:12px;
  text-transform:uppercase;letter-spacing:.5px;padding:8px 10px;border-bottom:1px solid var(--line)}
td{padding:9px 10px;border-bottom:1px solid var(--panel2)}
tr:hover td{background:var(--panel)}
.host{font-family:var(--mono)}
.badge{font-family:var(--mono);font-size:10px;font-weight:700;letter-spacing:.5px;
  background:var(--accent);color:#06231a;border-radius:5px;padding:1px 5px;margin-left:8px;vertical-align:middle}
.state.live{color:var(--accent)}
.state.down{color:var(--low)}
.ip{font-family:var(--mono);color:var(--dim)}
.tech{color:var(--dim);font-size:13px}
.code{font-size:13px;color:var(--medium)}
footer{margin-top:60px;padding-top:20px;border-top:1px solid var(--line);
  color:var(--dim);font-size:13px;display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px}
</style>
</head>
<body>
<div class="wrap">
<header>
  <span class="brand">recon<span class="dot">·</span>sentry</span>
  <span class="meta">generated {{.Generated}}{{if .ToolVersion}} · {{.ToolVersion}}{{end}}</span>
</header>
<h1>Attack surface — <span class="scope">{{.Scope}}</span></h1>
<p class="meta">git log for your attack surface — every change, since the baseline.</p>

{{if .Empty}}
<p class="quiet" style="margin-top:40px">No snapshots recorded yet. Run
<span class="code">reconsentry run --config scope.yaml</span> to record a baseline.</p>
{{else}}

<div class="kpis">
  <div class="kpi"><div class="n">{{.KPIs.Hosts}}</div><div class="l">Hosts</div></div>
  <div class="kpi live"><div class="n">{{.KPIs.Live}}</div><div class="l">Live</div></div>
  <div class="kpi"><div class="n">{{.KPIs.Tech}}</div><div class="l">Technologies</div></div>
  <div class="kpi"><div class="n">{{.KPIs.Runs}}</div><div class="l">Runs tracked</div></div>
  <div class="kpi"><div class="n">{{.KPIs.Changes}}</div><div class="l">Changes seen</div></div>
</div>

<h2>Surface changelog</h2>
<div class="tl">
{{range .Timeline}}
  <div class="ev{{if .Baseline}} base{{end}}{{if .Spike}} spike{{end}}">
    <div class="when">run #{{.RunID}} · {{.When}}</div>
    {{if .Baseline}}
      <div class="sum">Baseline recorded — <b>{{.Assets}}</b> host(s)</div>
    {{else if .Total}}
      {{if .Spike}}<div class="spike">🌊 SURFACE SPIKE — {{.NewHosts}} new host(s) in one run</div>{{end}}
      <div class="sum"><b>{{.Total}}</b> change(s) · {{.Assets}} host(s) total</div>
      {{range .Groups}}
        <span class="tag {{prio .Priority}}"><span class="k">{{.Kind}}</span>
        <span class="hosts">{{range .Hosts}}{{.}} {{end}}</span></span>
      {{end}}
    {{else}}
      <div class="sum quiet">No change · {{.Assets}} host(s)</div>
    {{end}}
  </div>
{{end}}
</div>

<h2>Current surface</h2>
<input class="filter" id="f" placeholder="filter hosts, tech, IP…" oninput="filterRows()">
<table id="surface">
<thead><tr><th>Host</th><th>State</th><th>Status</th><th>IP</th><th>Technology</th></tr></thead>
<tbody>
{{range .Surface}}
  <tr>
    <td class="host">{{.Host}}{{if .New}}<span class="badge">NEW</span>{{end}}</td>
    <td class="state {{.State}}">{{.State}}</td>
    <td class="code">{{if .Status}}{{.Status}}{{else}}—{{end}}</td>
    <td class="ip">{{if .IP}}{{.IP}}{{else}}—{{end}}</td>
    <td class="tech">{{if .Tech}}{{.Tech}}{{else}}—{{end}}</td>
  </tr>
{{end}}
</tbody>
</table>

{{end}}

<footer>
  <span>Generated by <a href="https://github.com/maruftak/reconsentry">reconsentry</a> — continuous attack-surface change monitoring.</span>
  <span class="quiet">Authorized targets only.</span>
</footer>
</div>
<script>
function filterRows(){
  var q=document.getElementById('f').value.toLowerCase();
  var rows=document.querySelectorAll('#surface tbody tr');
  for(var i=0;i<rows.length;i++){
    rows[i].style.display=rows[i].textContent.toLowerCase().indexOf(q)>-1?'':'none';
  }
}
</script>
</body>
</html>
`
