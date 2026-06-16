package correlate

import (
	"strings"
	"testing"

	"github.com/maruftak/reconsentry/internal/diff"
)

// hotTargets filters a change set down to the synthesized HOT_TARGET findings,
// keyed by host, so tests can assert on them without caring about ordering.
func hotTargets(changes []diff.Change) map[string]diff.Change {
	out := map[string]diff.Change{}
	for _, c := range changes {
		if c.Kind == diff.HotTarget {
			out[c.Host] = c
		}
	}
	return out
}

func TestCorrelate(t *testing.T) {
	tests := []struct {
		name string
		in   []diff.Change
		// wantHosts maps a host to the expected HOT_TARGET it should produce.
		// A host absent from the map must NOT produce a HOT_TARGET.
		wantPriority map[string]int // host -> expected HOT_TARGET priority
		// wantSignals is the headline count the detail must lead with
		// ("<n> correlated signals: …"): distinct contributing change kinds
		// PLUS the interesting-host pseudo-signal when the host matched.
		wantSignals map[string]int    // host -> expected headline signal count
		wantDetail  map[string]string // host -> substring that must appear in the detail
		noHotTarget []string          // hosts that must NOT yield a HOT_TARGET
	}{
		{
			name: "single signal on a host yields no hot target",
			in: []diff.Change{
				{Kind: diff.NewHost, Host: "a.example.com", Priority: diff.High, Detail: "new host"},
			},
			noHotTarget: []string{"a.example.com"},
		},
		{
			name: "single high-weight signal still needs >=2 distinct kinds",
			in: []diff.Change{
				// TAKEOVER_RISK alone scores 4 (>= threshold) but is one kind: no fusion.
				{Kind: diff.TakeoverRisk, Host: "solo.example.com", Priority: diff.Critical, Detail: "takeover"},
			},
			noHotTarget: []string{"solo.example.com"},
		},
		{
			name: "two signals crossing threshold yield a high hot target",
			in: []diff.Change{
				{Kind: diff.NewHost, Host: "shop.example.com", Priority: diff.High, Detail: "new host"},
				{Kind: diff.NewTech, Host: "shop.example.com", Priority: diff.Low, Detail: "new tech: [Jenkins]"},
			},
			// NEW_HOST(2) + NEW_TECH(1) = 3, below threshold 4 with no booster: NO hot target.
			noHotTarget: []string{"shop.example.com"},
		},
		{
			name: "three signals cross threshold without a booster",
			in: []diff.Change{
				{Kind: diff.NewHost, Host: "shop.example.com", Priority: diff.High},
				{Kind: diff.NewTech, Host: "shop.example.com", Priority: diff.Low},
				{Kind: diff.StatusChange, Host: "shop.example.com", Priority: diff.Medium},
			},
			// 2 + 1 + 1 = 4 == threshold, 3 distinct kinds: HOT_TARGET, no critical -> high.
			wantPriority: map[string]int{"shop.example.com": diff.High},
			wantSignals:  map[string]int{"shop.example.com": 3},
		},
		{
			name: "a contributing takeover makes the hot target critical",
			in: []diff.Change{
				{Kind: diff.TakeoverRisk, Host: "blog.example.com", Priority: diff.Critical, Detail: "takeover"},
				{Kind: diff.DNSChange, Host: "blog.example.com", Priority: diff.Medium, Detail: "CNAME a -> b"},
			},
			// TAKEOVER_RISK(4) + DNS_CHANGE(3) = 7, 2 kinds, one critical -> critical.
			wantPriority: map[string]int{"blog.example.com": diff.Critical},
			wantSignals:  map[string]int{"blog.example.com": 2},
		},
		{
			name: "interesting-keyword booster pushes a host over threshold",
			in: []diff.Change{
				// NEW_HOST(2) + NEW_TECH(1) = 3 < 4, but host name "staging" adds +2 -> 5.
				{Kind: diff.NewHost, Host: "staging.example.com", Priority: diff.High},
				{Kind: diff.NewTech, Host: "staging.example.com", Priority: diff.Low, Detail: "new tech: [Jenkins]"},
			},
			wantPriority: map[string]int{"staging.example.com": diff.High},
			// 2 change kinds + the interesting pseudo-signal = 3 in the headline.
			wantSignals: map[string]int{"staging.example.com": 3},
			wantDetail:  map[string]string{"staging.example.com": "interesting:staging"},
		},
		{
			name: "non-interesting host with the same two low-weight signals stays quiet",
			in: []diff.Change{
				{Kind: diff.NewTech, Host: "www.example.com", Priority: diff.Low},
				{Kind: diff.IPChange, Host: "www.example.com", Priority: diff.Low},
			},
			// 1 + 1 = 2 < 4, no booster: NO hot target.
			noHotTarget: []string{"www.example.com"},
		},
		{
			name: "duplicate kinds on a host count once toward distinct kinds and score",
			in: []diff.Change{
				{Kind: diff.NewTech, Host: "dup.example.com", Priority: diff.Low},
				{Kind: diff.NewTech, Host: "dup.example.com", Priority: diff.Low},
				{Kind: diff.NewTech, Host: "dup.example.com", Priority: diff.Low},
			},
			// Only one distinct kind: never a hot target regardless of count.
			noHotTarget: []string{"dup.example.com"},
		},
		{
			name: "hostless changes never correlate",
			in: []diff.Change{
				{Kind: diff.NewTech, Host: "", Priority: diff.Low},
				{Kind: diff.StatusChange, Host: "", Priority: diff.Medium},
			},
			noHotTarget: []string{""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Correlate(tt.in, Options{})
			ht := hotTargets(got)

			for _, h := range tt.noHotTarget {
				if _, ok := ht[h]; ok {
					t.Errorf("host %q must NOT yield a HOT_TARGET, got %+v", h, ht[h])
				}
			}
			for h, wantP := range tt.wantPriority {
				c, ok := ht[h]
				if !ok {
					t.Fatalf("host %q expected a HOT_TARGET, got none", h)
				}
				if c.Priority != wantP {
					t.Errorf("host %q HOT_TARGET priority = %d, want %d (detail %q)", h, c.Priority, wantP, c.Detail)
				}
				if c.Kind != diff.HotTarget {
					t.Errorf("host %q finding kind = %q, want HOT_TARGET", h, c.Kind)
				}
			}
			for h, wantN := range tt.wantSignals {
				c := ht[h]
				// The detail leads with "<n> correlated signals".
				prefix := signalPrefix(wantN)
				if !strings.HasPrefix(c.Detail, prefix) {
					t.Errorf("host %q detail = %q, want prefix %q", h, c.Detail, prefix)
				}
			}
			for h, sub := range tt.wantDetail {
				c := ht[h]
				if !strings.Contains(c.Detail, sub) {
					t.Errorf("host %q detail = %q, want it to contain %q", h, c.Detail, sub)
				}
			}
		})
	}
}

// signalPrefix builds the leading text the detail string must start with for n
// contributing signals, e.g. "3 correlated signals: ".
func signalPrefix(n int) string {
	return itoa(n) + " correlated signals: "
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestCorrelateDeterministicDetailOrdering(t *testing.T) {
	// Feed the same host's kinds in two different input orders; the detail's
	// signal list must come out identical (sorted), so alerts are stable.
	a := []diff.Change{
		{Kind: diff.NewTech, Host: "h.example.com", Priority: diff.Low, Detail: "new tech: [Jenkins]"},
		{Kind: diff.StatusChange, Host: "h.example.com", Priority: diff.Medium},
		{Kind: diff.NewHost, Host: "h.example.com", Priority: diff.High},
	}
	b := []diff.Change{
		{Kind: diff.NewHost, Host: "h.example.com", Priority: diff.High},
		{Kind: diff.StatusChange, Host: "h.example.com", Priority: diff.Medium},
		{Kind: diff.NewTech, Host: "h.example.com", Priority: diff.Low, Detail: "new tech: [Jenkins]"},
	}
	da := hotTargets(Correlate(a, Options{}))["h.example.com"].Detail
	db := hotTargets(Correlate(b, Options{}))["h.example.com"].Detail
	if da == "" {
		t.Fatalf("expected a HOT_TARGET detail, got empty")
	}
	if da != db {
		t.Errorf("detail not deterministic:\n  a=%q\n  b=%q", da, db)
	}
	// Kinds are listed in sorted order: NEW_HOST < NEW_TECH < STATUS_CHANGE.
	wantOrder := strings.Index(da, "NEW_HOST") < strings.Index(da, "NEW_TECH") &&
		strings.Index(da, "NEW_TECH") < strings.Index(da, "STATUS_CHANGE")
	if !wantOrder {
		t.Errorf("contributing kinds not sorted in detail: %q", da)
	}
}

func TestCorrelateReturnsOnlyAdditionalFindings(t *testing.T) {
	in := []diff.Change{
		{Kind: diff.NewHost, Host: "api.example.com", Priority: diff.High},
		{Kind: diff.NewTech, Host: "api.example.com", Priority: diff.Low},
	}
	// api is "interesting": 2 + 1 + 2 boost = 5 >= 4 -> one HOT_TARGET.
	extra := Correlate(in, Options{})
	if len(extra) != 1 || extra[0].Kind != diff.HotTarget {
		t.Fatalf("Correlate should return exactly one HOT_TARGET, got %+v", extra)
	}
	// It must NOT echo the originals back — the caller appends.
	for _, c := range extra {
		if c.Kind == diff.NewHost || c.Kind == diff.NewTech {
			t.Errorf("Correlate must return only additional findings, found original %q", c.Kind)
		}
	}
	// Appending preserves every original alongside the new finding (the wiring
	// the runner performs).
	combined := append(append([]diff.Change{}, in...), extra...)
	var kinds []diff.Kind
	for _, c := range combined {
		kinds = append(kinds, c.Kind)
	}
	if !containsKind(kinds, diff.NewHost) || !containsKind(kinds, diff.NewTech) || !containsKind(kinds, diff.HotTarget) {
		t.Errorf("appended set must contain originals + HOT_TARGET, got %v", kinds)
	}
}

func TestCorrelateDoesNotMutateInput(t *testing.T) {
	in := []diff.Change{
		{Kind: diff.NewHost, Host: "staging.example.com", Priority: diff.High, Detail: "x"},
		{Kind: diff.NewTech, Host: "staging.example.com", Priority: diff.Low, Detail: "y"},
	}
	before := len(in)
	_ = Correlate(in, Options{})
	if len(in) != before {
		t.Errorf("Correlate grew its input slice: %d -> %d", before, len(in))
	}
	if in[0].Detail != "x" || in[1].Detail != "y" {
		t.Errorf("Correlate mutated input change details: %+v", in)
	}
}

func TestCorrelateCustomThreshold(t *testing.T) {
	in := []diff.Change{
		{Kind: diff.NewTech, Host: "www.example.com", Priority: diff.Low},
		{Kind: diff.IPChange, Host: "www.example.com", Priority: diff.Low},
	}
	// Default threshold 4: 1+1 = 2 -> nothing.
	if len(hotTargets(Correlate(in, Options{}))) != 0 {
		t.Fatalf("expected no hot target at default threshold")
	}
	// Lowered threshold 2: now it fuses.
	out := hotTargets(Correlate(in, Options{Threshold: 2}))
	if _, ok := out["www.example.com"]; !ok {
		t.Errorf("expected a hot target at threshold 2, got none")
	}
}

func containsKind(ks []diff.Kind, want diff.Kind) bool {
	for _, k := range ks {
		if k == want {
			return true
		}
	}
	return false
}
