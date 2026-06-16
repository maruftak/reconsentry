package diff

import (
	"math"
	"math/rand"
	"strings"
	"testing"

	"github.com/maruftak/reconsentry/internal/model"
)

func TestHamming(t *testing.T) {
	tests := []struct {
		name string
		a, b uint64
		want int
	}{
		{"identical is zero", 0xDEADBEEF, 0xDEADBEEF, 0},
		{"one bit differs", 0b0000, 0b0001, 1},
		{"all 64 bits differ", 0, math.MaxUint64, 64},
		{"two bits differ", 0b1010, 0b0000, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hamming(tt.a, tt.b); got != tt.want {
				t.Errorf("hamming(%#x, %#x) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestDiffContent(t *testing.T) {
	// base is a realistic nonzero simhash (a normalized non-empty body never
	// hashes to 0). movedSim is far enough from base (> simhashHammingThreshold
	// bits) to read as a genuine body move; closeSim is within the threshold
	// (cosmetic noise that survived normalization).
	const base uint64 = 0xA5A5_A5A5_A5A5_A5A5
	const movedSim uint64 = 0x5A5A_5A5A_A5A5_A5A5 // top 32 bits inverted = 32 bits flipped (> 12)
	const closeSim uint64 = 0xA5A5_A5A5_A5A5_A5FF // low byte differs in 4 bits (<= 12)

	tests := []struct {
		name       string
		prev, curr []model.ContentFingerprint
		wantKinds  int               // number of CONTENT_CHANGE changes expected
		wantPrio   map[string]int    // host -> expected priority (when a change fires)
		wantDetail map[string]string // host -> substring required in Detail
		wantNoFire []string          // hosts that must NOT produce a CONTENT_CHANGE
	}{
		{
			name:       "host present only in curr is NEW_HOST, not content change",
			prev:       nil,
			curr:       []model.ContentFingerprint{{Host: "new.example.com", Status: 200, SimHash: movedSim}},
			wantKinds:  0,
			wantNoFire: []string{"new.example.com"},
		},
		{
			name:       "host gone (only in prev) yields nothing",
			prev:       []model.ContentFingerprint{{Host: "old.example.com", Status: 200, SimHash: base}},
			curr:       nil,
			wantKinds:  0,
			wantNoFire: []string{"old.example.com"},
		},
		{
			name:       "transient empty fetch is skipped (no clobber alert)",
			prev:       []model.ContentFingerprint{{Host: "a.example.com", Status: 200, SimHash: base}},
			curr:       []model.ContentFingerprint{{Host: "a.example.com"}}, // Status 0, SimHash 0, no favicon
			wantKinds:  0,
			wantNoFire: []string{"a.example.com"},
		},
		{
			name: "page came online from a non-2xx is High",
			prev: []model.ContentFingerprint{{Host: "a.example.com", Status: 403, SimHash: base}},
			curr: []model.ContentFingerprint{{Host: "a.example.com", Status: 200, SimHash: base}},
			// status crossed into 2xx even though the body simhash is unchanged.
			wantKinds:  1,
			wantPrio:   map[string]int{"a.example.com": High},
			wantDetail: map[string]string{"a.example.com": "came online"},
		},
		{
			name:       "favicon flip alone fires at Medium",
			prev:       []model.ContentFingerprint{{Host: "a.example.com", Status: 200, SimHash: base, FaviconHash: "111"}},
			curr:       []model.ContentFingerprint{{Host: "a.example.com", Status: 200, SimHash: base, FaviconHash: "222"}},
			wantKinds:  1,
			wantPrio:   map[string]int{"a.example.com": Medium},
			wantDetail: map[string]string{"a.example.com": "favicon changed"},
		},
		{
			name:       "body simhash move fires at Medium",
			prev:       []model.ContentFingerprint{{Host: "a.example.com", Status: 200, SimHash: base}},
			curr:       []model.ContentFingerprint{{Host: "a.example.com", Status: 200, SimHash: movedSim}},
			wantKinds:  1,
			wantPrio:   map[string]int{"a.example.com": Medium},
			wantDetail: map[string]string{"a.example.com": "body content changed"},
		},
		{
			name: "cosmetic token-only change stays below threshold — NO change (keystone)",
			prev: []model.ContentFingerprint{{Host: "a.example.com", Status: 200, SimHash: base, TitleHash: "t1"}},
			// simhash barely moved (within threshold), favicon identical/empty, title same.
			curr:       []model.ContentFingerprint{{Host: "a.example.com", Status: 200, SimHash: closeSim, TitleHash: "t1"}},
			wantKinds:  0,
			wantNoFire: []string{"a.example.com"},
		},
		{
			name: "empty favicon on one side never counts as a flip",
			prev: []model.ContentFingerprint{{Host: "a.example.com", Status: 200, SimHash: base, FaviconHash: ""}},
			curr: []model.ContentFingerprint{{Host: "a.example.com", Status: 200, SimHash: closeSim, FaviconHash: "999"}},
			// favicon went empty -> set, which is NOT a flip; simhash within threshold; title unchanged.
			wantKinds:  0,
			wantNoFire: []string{"a.example.com"},
		},
		{
			name:       "title flip corroborates a body move but is never the sole trigger",
			prev:       []model.ContentFingerprint{{Host: "a.example.com", Status: 200, SimHash: base, TitleHash: "t1"}},
			curr:       []model.ContentFingerprint{{Host: "a.example.com", Status: 200, SimHash: movedSim, TitleHash: "t2"}},
			wantKinds:  1,
			wantPrio:   map[string]int{"a.example.com": Medium},
			wantDetail: map[string]string{"a.example.com": "+ title changed"},
		},
		{
			name:       "title flip ALONE (simhash within threshold) does not fire",
			prev:       []model.ContentFingerprint{{Host: "a.example.com", Status: 200, SimHash: base, TitleHash: "t1"}},
			curr:       []model.ContentFingerprint{{Host: "a.example.com", Status: 200, SimHash: closeSim, TitleHash: "t2"}},
			wantKinds:  0,
			wantNoFire: []string{"a.example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DiffContent(tt.prev, tt.curr)
			content := contentChanges(got)
			if len(content) != tt.wantKinds {
				t.Fatalf("want %d CONTENT_CHANGE, got %d: %+v", tt.wantKinds, len(content), got)
			}
			for _, h := range tt.wantNoFire {
				if _, ok := content[h]; ok {
					t.Errorf("host %q must NOT produce a CONTENT_CHANGE, got %+v", h, content[h])
				}
			}
			for h, wantP := range tt.wantPrio {
				c, ok := content[h]
				if !ok {
					t.Fatalf("host %q expected a CONTENT_CHANGE, got none", h)
				}
				if c.Priority != wantP {
					t.Errorf("host %q priority = %d, want %d (detail %q)", h, c.Priority, wantP, c.Detail)
				}
				if c.Kind != ContentChange {
					t.Errorf("host %q kind = %q, want CONTENT_CHANGE", h, c.Kind)
				}
			}
			for h, sub := range tt.wantDetail {
				c := content[h]
				if !strings.Contains(c.Detail, sub) {
					t.Errorf("host %q detail = %q, want it to contain %q", h, c.Detail, sub)
				}
			}
		})
	}
}

// contentChanges filters down to CONTENT_CHANGE changes keyed by host.
func contentChanges(changes []Change) map[string]Change {
	out := map[string]Change{}
	for _, c := range changes {
		if c.Kind == ContentChange {
			out[c.Host] = c
		}
	}
	return out
}

// DiffContent must be deterministic regardless of input order.
func TestDiffContentDeterministic(t *testing.T) {
	const moved uint64 = 0xFFFF_FFFF_0000_0000
	prev := []model.ContentFingerprint{
		{Host: "a.example.com", Status: 200, SimHash: 0},
		{Host: "b.example.com", Status: 403, SimHash: 0},
		{Host: "c.example.com", Status: 200, SimHash: 0, FaviconHash: "1"},
	}
	curr := []model.ContentFingerprint{
		{Host: "a.example.com", Status: 200, SimHash: moved},
		{Host: "b.example.com", Status: 200, SimHash: 0},
		{Host: "c.example.com", Status: 200, SimHash: 0, FaviconHash: "2"},
	}

	want := renderContent(DiffContent(prev, curr))
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 20; i++ {
		p := append([]model.ContentFingerprint(nil), prev...)
		c := append([]model.ContentFingerprint(nil), curr...)
		r.Shuffle(len(p), func(i, j int) { p[i], p[j] = p[j], p[i] })
		r.Shuffle(len(c), func(i, j int) { c[i], c[j] = c[j], c[i] })
		if got := renderContent(DiffContent(p, c)); got != want {
			t.Fatalf("DiffContent not deterministic under shuffle:\n want %q\n  got %q", want, got)
		}
	}
}

func renderContent(changes []Change) string {
	var b strings.Builder
	for _, c := range changes {
		b.WriteString(string(c.Kind))
		b.WriteByte('|')
		b.WriteString(c.Host)
		b.WriteByte('\n')
	}
	return b.String()
}
