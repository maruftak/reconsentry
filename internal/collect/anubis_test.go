package collect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
)

func TestParseAnubis(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		target string
		want   []string
	}{
		{
			name:   "happy path extracts hostnames",
			body:   `["a.example.com","b.example.com"]`,
			target: "example.com",
			want:   []string{"a.example.com", "b.example.com"},
		},
		{
			name:   "dedups and lowercases",
			body:   `["A.example.com","a.example.com"]`,
			target: "example.com",
			want:   []string{"a.example.com"},
		},
		{
			name:   "drops out-of-scope hostnames",
			body:   `["a.example.com","cdn.example.net"]`,
			target: "example.com",
			want:   []string{"a.example.com"},
		},
		{
			name:   "matches apex domain",
			body:   `["example.com"]`,
			target: "example.com",
			want:   []string{"example.com"},
		},
		{
			name:   "empty list yields nothing",
			body:   `[]`,
			target: "example.com",
			want:   nil,
		},
		{
			name:   "malformed json yields nothing",
			body:   `not json`,
			target: "example.com",
			want:   nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseAnubis([]byte(tt.body), tt.target)
			sort.Strings(got)
			want := append([]string(nil), tt.want...)
			sort.Strings(want)
			if len(got) != len(want) {
				t.Fatalf("got %v, want %v", got, want)
			}
			for i := range got {
				if got[i] != want[i] {
					t.Fatalf("got %v, want %v", got, want)
				}
			}
		})
	}
}

func TestAnubisMergesAcrossTargets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/subdomains/example.com"):
			w.Write([]byte(`["a.example.com"]`))
		case strings.Contains(r.URL.Path, "/subdomains/example.org"):
			w.Write([]byte(`["b.example.org"]`))
		default:
			w.Write([]byte(`[]`))
		}
	}))
	defer srv.Close()
	defer stubHTTPGetPath(srv.URL)()

	got, err := Anubis(context.Background(), []string{"example.com", "example.org"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sort.Strings(got)
	want := []string{"a.example.com", "b.example.org"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestAnubisFailsSoftOnPartialError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/subdomains/dead.com") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write([]byte(`["a.example.com"]`))
	}))
	defer srv.Close()
	defer stubHTTPGetPath(srv.URL)()

	got, err := Anubis(context.Background(), []string{"dead.com", "example.com"})
	if err != nil {
		t.Fatalf("a dead target should not fail the run: %v", err)
	}
	if len(got) != 1 || got[0] != "a.example.com" {
		t.Fatalf("got %v, want [a.example.com]", got)
	}
}

func TestAnubisErrorsWhenAllTargetsFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	defer stubHTTPGetPath(srv.URL)()

	if _, err := Anubis(context.Background(), []string{"example.com"}); err == nil {
		t.Fatal("want error when every lookup fails, got nil")
	}
}
