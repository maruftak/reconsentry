package collect

import "testing"

func TestParseTakeover(t *testing.T) {
	jsonl := `{"input":"blog.acme.com","url":"https://blog.acme.com","host":"203.0.113.9","status_code":404,"cnames":["acme.ghost.io."],"response_body":"Site unavailable","failed":false}
{"input":"dead.acme.com","cnames":["acme.azurewebsites.net."],"failed":true}
garbage line that is not json
{"input":"","url":"https://www.acme.com","status_code":200,"response_body":"home"}`

	got := parseTakeover([]byte(jsonl))
	if len(got) != 3 {
		t.Fatalf("want 3 probes, got %d: %+v", len(got), got)
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

	// input empty -> host derived from URL.
	if got[2].Host != "www.acme.com" {
		t.Errorf("host from url: got %q", got[2].Host)
	}
}

func TestParseTakeoverEmpty(t *testing.T) {
	if got := parseTakeover(nil); got != nil {
		t.Errorf("want nil for empty input, got %+v", got)
	}
}
