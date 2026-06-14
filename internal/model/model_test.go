package model

import (
	"reflect"
	"testing"
)

func TestTrimInvisible(t *testing.T) {
	bom := string([]byte{0xEF, 0xBB, 0xBF}) // UTF-8 BOM, U+FEFF

	cases := map[string]string{
		bom + "example.com": "example.com",
		"  example.com  ":   "example.com",
		bom + " a.com ":     "a.com",
		"a.com" + bom:       "a.com",
		"plain.com":         "plain.com",
	}
	for in, want := range cases {
		if got := TrimInvisible(in); got != want {
			t.Errorf("TrimInvisible(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTechString(t *testing.T) {
	tests := []struct {
		name string
		tech []string
		want string
	}{
		{"empty", nil, ""},
		{"single", []string{"nginx"}, "nginx"},
		{"multiple joined with comma-space", []string{"nginx", "php", "react"}, "nginx, php, react"},
		{"preserves given order", []string{"react", "nginx"}, "react, nginx"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := Asset{Tech: tt.tech}
			if got := a.TechString(); got != tt.want {
				t.Errorf("TechString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNormalizeTech(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"nil yields nil", nil, nil},
		{"empty yields nil", []string{}, nil},
		{"single", []string{"nginx"}, []string{"nginx"}},
		{"sorts for stable output", []string{"react", "nginx", "php"}, []string{"nginx", "php", "react"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeTech(tt.in); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NormalizeTech(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// NormalizeTech must not mutate its input slice (immutability contract).
func TestNormalizeTechDoesNotMutateInput(t *testing.T) {
	in := []string{"react", "nginx", "php"}
	NormalizeTech(in)
	want := []string{"react", "nginx", "php"}
	if !reflect.DeepEqual(in, want) {
		t.Errorf("input mutated: got %v, want %v", in, want)
	}
}
