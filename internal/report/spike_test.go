package report

import "testing"

func TestIsSpike(t *testing.T) {
	tests := []struct {
		name    string
		current int
		history []int
		want    bool
	}{
		{"below floor is never a spike", 2, []int{0, 0, 0}, false},
		{"no history (baseline) is never a spike", 10, nil, false},
		{"burst on a normally-static surface", 5, []int{0, 0, 1}, true},
		{"static mean, just under floor", 2, []int{0, 0}, false},
		{"big jump over an active average", 12, []int{2, 3, 1}, true},
		{"steady growth is not a spike", 3, []int{3, 4, 3}, false},
		{"exactly the multiple counts", 6, []int{2, 2}, true}, // 6 >= 3*2
		{"just under the multiple does not", 5, []int{2, 2}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isSpike(tt.current, tt.history); got != tt.want {
				t.Errorf("isSpike(%d, %v) = %v, want %v", tt.current, tt.history, got, tt.want)
			}
		})
	}
}

func TestMean(t *testing.T) {
	if got := mean(nil); got != 0 {
		t.Errorf("mean(nil) = %v, want 0", got)
	}
	if got := mean([]int{2, 4, 6}); got != 4 {
		t.Errorf("mean = %v, want 4", got)
	}
}
