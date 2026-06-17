package collect

import (
	"context"
	"net"
	"testing"
)

func TestIsInternalIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.5", true},        // RFC1918
		{"172.16.4.1", true},      // RFC1918
		{"192.168.1.1", true},     // RFC1918
		{"127.0.0.1", true},       // loopback
		{"169.254.169.254", true}, // link-local / cloud metadata
		{"0.0.0.0", true},         // unspecified
		{"::1", true},             // IPv6 loopback
		{"fe80::1", true},         // IPv6 link-local
		{"fc00::1", true},         // IPv6 unique-local (private)
		{"8.8.8.8", false},        // public
		{"1.1.1.1", false},        // public
		{"203.0.113.10", false},   // public (TEST-NET-3, but not internal range)
		{"2606:4700::1", false},   // public IPv6
	}
	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if ip == nil {
			t.Fatalf("bad test IP %q", tt.ip)
		}
		if got := isInternalIP(ip); got != tt.want {
			t.Errorf("isInternalIP(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}
	if isInternalIP(nil) {
		t.Error("isInternalIP(nil) = true, want false")
	}
}

func TestInternalHostLiteralIP(t *testing.T) {
	// Literal IPs resolve deterministically without touching DNS.
	res := net.DefaultResolver
	ctx := context.Background()
	tests := []struct {
		host string
		want bool
	}{
		{"10.1.2.3", true},
		{"127.0.0.1", true},
		{"169.254.169.254", true},
		{"http://192.168.0.1:8080/path", true}, // scheme/port stripped by cleanHost
		{"[::1]:443", true},
		{"8.8.8.8", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := internalHost(ctx, res, tt.host); got != tt.want {
			t.Errorf("internalHost(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

func TestPublicHostsSplitsLiterals(t *testing.T) {
	in := []string{"8.8.8.8", "10.0.0.1", "1.1.1.1", "127.0.0.1"}
	kept, dropped := publicHosts(context.Background(), in)

	wantKept := []string{"8.8.8.8", "1.1.1.1"}
	wantDropped := []string{"10.0.0.1", "127.0.0.1"}

	if !equalStrings(kept, wantKept) {
		t.Errorf("kept = %v, want %v", kept, wantKept)
	}
	if !equalStrings(dropped, wantDropped) {
		t.Errorf("dropped = %v, want %v", dropped, wantDropped)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
