package report

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var widthRe = regexp.MustCompile(`<svg[^>]*\bwidth="(\d+)"`)

func svgWidth(t *testing.T, svg string) int {
	t.Helper()
	m := widthRe.FindStringSubmatch(svg)
	if m == nil {
		t.Fatalf("no width attribute in svg: %.80s", svg)
	}
	w, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestBadgeIsWellFormedSVG(t *testing.T) {
	svg := string(Badge("attack surface", SurfaceStats{Total: 42, Live: 38}))
	for _, want := range []string{"<svg", "</svg>", "attack surface", "38/42 live"} {
		if !strings.Contains(svg, want) {
			t.Errorf("badge missing %q", want)
		}
	}
}

func TestBadgeValueFormatting(t *testing.T) {
	tests := []struct {
		name      string
		stats     SurfaceStats
		wantSub   string
		wantNoArr bool
	}{
		{"no delta", SurfaceStats{Total: 42, Live: 38}, "38/42 live", true},
		{"growing", SurfaceStats{Total: 42, Live: 38, Delta: 3, HasDelta: true}, "▲3", false},
		{"shrinking", SurfaceStats{Total: 40, Live: 30, Delta: -2, HasDelta: true}, "▼2", false},
		{"zero delta has no arrow", SurfaceStats{Total: 42, Live: 38, Delta: 0, HasDelta: true}, "38/42 live", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svg := string(Badge("attack surface", tt.stats))
			if !strings.Contains(svg, tt.wantSub) {
				t.Errorf("want %q in %s", tt.wantSub, svg)
			}
			if tt.wantNoArr && (strings.Contains(svg, "▲") || strings.Contains(svg, "▼")) {
				t.Errorf("did not expect an arrow in %s", svg)
			}
		})
	}
}

func TestBadgeFillColor(t *testing.T) {
	growing := string(Badge("s", SurfaceStats{Total: 10, Live: 9, Delta: 2, HasDelta: true}))
	if !strings.Contains(growing, "#fb8500") {
		t.Error("growing surface should use amber fill #fb8500")
	}
	for _, s := range []SurfaceStats{
		{Total: 10, Live: 9},                            // no delta
		{Total: 10, Live: 9, Delta: -1, HasDelta: true}, // shrinking
		{Total: 10, Live: 9, Delta: 0, HasDelta: true},  // static
	} {
		svg := string(Badge("s", s))
		if !strings.Contains(svg, "#3fb950") {
			t.Errorf("non-growing surface %+v should use green fill #3fb950", s)
		}
		if strings.Contains(svg, "#fb8500") {
			t.Errorf("non-growing surface %+v should not use amber", s)
		}
	}
}

func TestBadgeWidthScalesWithText(t *testing.T) {
	short := svgWidth(t, string(Badge("s", SurfaceStats{Total: 1, Live: 1})))
	long := svgWidth(t, string(Badge("a much longer label here", SurfaceStats{Total: 1234, Live: 1200, Delta: 99, HasDelta: true})))
	if long <= short {
		t.Errorf("longer content should yield a wider badge: short=%d long=%d", short, long)
	}
}
