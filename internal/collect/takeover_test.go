package collect

import (
	"strings"
	"testing"
)

func TestParseTakeover(t *testing.T) {
	// Field tags match real httpx -json output: `cname`, `body`, `failed`.
	jsonl := `{"input":"blog.acme.com","url":"https://blog.acme.com","host":"203.0.113.9","status_code":404,"cname":["acme.ghost.io."],"body":"Site unavailable","failed":false}
{"input":"dead.acme.com","cname":["acme.azurewebsites.net."],"failed":true}
garbage line that is not json
{"input":"raw.acme.com","status_code":404,"response":"HTTP/1.1 404\r\n\r\nThe specified bucket does not exist"}
{"input":"","url":"https://www.acme.com","status_code":200,"body":"home"}`

	got := parseTakeover([]byte(jsonl))
	if len(got) != 4 {
		t.Fatalf("want 4 probes, got %d: %+v", len(got), got)
	}

	if got[0].Host != "blog.acme.com" {
		t.Errorf("host: got %q", got[0].Host)
	}
	if len(got[0].CNAMEs) != 1 || got[0].CNAMEs[0] != "acme.ghost.io" {
		t.Errorf("cname should be lowercased and trailing-dot trimmed, got %v", got[0].CNAMEs)
	}
	if got[0].Body != "Site unavailable" || got[0].Status != 404 {
		t.Errorf("body/status: got %q %d", got[0].Body, got[0].Status)
	}

	if !got[1].Failed || got[1].Host != "dead.acme.com" {
		t.Errorf("failed host not parsed: %+v", got[1])
	}
	if len(got[1].CNAMEs) != 1 || got[1].CNAMEs[0] != "acme.azurewebsites.net" {
		t.Errorf("failed host cname: got %v", got[1].CNAMEs)
	}

	// body absent -> fall back to the raw response field.
	if !strings.Contains(got[2].Body, "The specified bucket does not exist") {
		t.Errorf("response fallback not used: got %q", got[2].Body)
	}

	// input empty -> host derived from URL.
	if got[3].Host != "www.acme.com" {
		t.Errorf("host from url: got %q", got[3].Host)
	}
}

func TestParseTakeoverEmpty(t *testing.T) {
	if got := parseTakeover(nil); got != nil {
		t.Errorf("want nil for empty input, got %+v", got)
	}
}
