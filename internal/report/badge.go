package report

import (
	"bytes"
	"fmt"
	"html/template"
)

// SurfaceStats is the live state a badge summarizes for one scope.
type SurfaceStats struct {
	Total    int  // hosts in the latest snapshot
	Live     int  // hosts currently responding
	Delta    int  // net change in host count over the window (latest - window-ago)
	HasDelta bool // whether a window-ago baseline existed to compute Delta
}

// badgeColors maps surface state to the right-hand fill. A shrinking or static
// surface is calm green; a growing one is amber — a growing surface is exactly
// what a hunter wants to look at first.
func badgeFill(s SurfaceStats) string {
	if s.HasDelta && s.Delta > 0 {
		return "#fb8500" // amber: surface is expanding
	}
	return "#3fb950" // green
}

// badgeValue renders the right-hand text, e.g. "38/42 live ▲3".
func badgeValue(s SurfaceStats) string {
	v := fmt.Sprintf("%d/%d live", s.Live, s.Total)
	if s.HasDelta && s.Delta != 0 {
		arrow := "▲"
		n := s.Delta
		if n < 0 {
			arrow, n = "▼", -n
		}
		v += fmt.Sprintf(" %s%d", arrow, n)
	}
	return v
}

// textWidth approximates rendered width (px) for the 11px Verdana the badge
// uses. ~6.6px per glyph is close enough for shields-style spacing; arrows are
// wider, so they get a small bump.
func textWidth(s string) int {
	w := 0.0
	for _, r := range s {
		switch r {
		case '▲', '▼':
			w += 9
		case 'i', 'l', 'I', '/', '.', ' ', '1':
			w += 4
		default:
			w += 6.6
		}
	}
	return int(w + 0.5)
}

// Badge renders a shields.io-style SVG for the surface. It is self-contained
// (no fonts, no external assets) so it can be committed, served from GitHub
// Pages, or embedded straight in a README.
func Badge(label string, s SurfaceStats) []byte {
	const pad = 10
	val := badgeValue(s)
	lw := textWidth(label) + pad*2
	vw := textWidth(val) + pad*2
	total := lw + vw

	vm := badgeView{
		Label: label, Value: val, Fill: badgeFill(s),
		LW: lw, VW: vw, Total: total,
		LabelX: lw * 10 / 2, ValueX: (lw + vw/2) * 10,
		LabelLen: textWidth(label) * 10, ValueLen: textWidth(val) * 10,
	}
	var buf bytes.Buffer
	_ = badgeTmpl.Execute(&buf, vm) // template is static; execute cannot fail here
	return buf.Bytes()
}

type badgeView struct {
	Label, Value, Fill string
	LW, VW, Total      int
	LabelX, ValueX     int
	LabelLen, ValueLen int
}

var badgeTmpl = template.Must(template.New("badge").Parse(badgeSVG))

// scale10 — text x/length are expressed in 1/10 px (textLength trick) so the
// shadow + main text line up crisply, matching shields.io output.
const badgeSVG = `<svg xmlns="http://www.w3.org/2000/svg" width="{{.Total}}" height="20" role="img" aria-label="{{.Label}}: {{.Value}}">
<title>{{.Label}}: {{.Value}}</title>
<linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
<clipPath id="r"><rect width="{{.Total}}" height="20" rx="3" fill="#fff"/></clipPath>
<g clip-path="url(#r)">
<rect width="{{.LW}}" height="20" fill="#2b2f36"/>
<rect x="{{.LW}}" width="{{.VW}}" height="20" fill="{{.Fill}}"/>
<rect width="{{.Total}}" height="20" fill="url(#s)"/>
</g>
<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="110">
<text x="{{.LabelX}}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="{{.LabelLen}}">{{.Label}}</text>
<text x="{{.LabelX}}" y="140" transform="scale(.1)" textLength="{{.LabelLen}}">{{.Label}}</text>
<text x="{{.ValueX}}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="{{.ValueLen}}">{{.Value}}</text>
<text x="{{.ValueX}}" y="140" transform="scale(.1)" textLength="{{.ValueLen}}">{{.Value}}</text>
</g>
</svg>`
