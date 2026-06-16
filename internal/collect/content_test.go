package collect

import (
	"math/bits"
	"strings"
	"testing"
)

func TestParseContent(t *testing.T) {
	// Field tags match real httpx -json output: status_code, body, favicon, title.
	jsonl := `{"input":"app.acme.com","url":"https://app.acme.com","status_code":200,"title":"Login","favicon":"-12345","body":"<html><head><title>Login</title></head><body>Sign in to Acme</body></html>"}
{"input":"dead.acme.com","failed":true}
not json at all
{"input":"raw.acme.com","status_code":403,"response":"HTTP/1.1 403\r\nServer: nginx\r\n\r\n<html><body>Forbidden</body></html>"}
{"input":"","url":"https://www.acme.com","status_code":200,"body":"<h1>Home</h1>"}`

	got := parseContent([]byte(jsonl))
	if len(got) != 4 {
		t.Fatalf("want 4 fingerprints, got %d: %+v", len(got), got)
	}
	byHost := map[string]int{}
	for i, f := range got {
		byHost[f.Host] = i
	}

	app := got[byHost["app.acme.com"]]
	if app.Status != 200 || app.FaviconHash != "-12345" {
		t.Errorf("app: status/favicon wrong: %+v", app)
	}
	if app.SimHash == 0 {
		t.Errorf("app: a non-empty body must produce a nonzero simhash, got 0")
	}
	if app.TitleHash == "" {
		t.Errorf("app: a non-empty title must produce a title hash, got empty")
	}

	// A failed host with no response is recorded as a zero-value fingerprint
	// (host only), so the runner can still see it without it tripping a change.
	dead := got[byHost["dead.acme.com"]]
	if dead.Status != 0 || dead.SimHash != 0 || dead.FaviconHash != "" {
		t.Errorf("failed host should be a zero-value fingerprint, got %+v", dead)
	}

	// body absent -> fall back to the raw response field for the simhash.
	raw := got[byHost["raw.acme.com"]]
	if raw.Status != 403 || raw.SimHash == 0 {
		t.Errorf("response fallback not used for simhash: %+v", raw)
	}

	// input empty -> host derived from URL.
	if _, ok := byHost["www.acme.com"]; !ok {
		t.Errorf("host should be derived from url when input empty, got hosts %v", byHost)
	}
}

func TestParseContentEmpty(t *testing.T) {
	if got := parseContent(nil); got != nil {
		t.Errorf("want nil for empty input, got %+v", got)
	}
}

func TestNormalizeBody(t *testing.T) {
	// HTML tags stripped, lowercased, whitespace collapsed.
	body := "<html><head><STYLE>.x{color:red}</STYLE></head><body>  Hello   World  </body></html>"
	got := normalizeBody(body)
	if strings.Contains(got, "<") || strings.Contains(got, ">") {
		t.Errorf("tags not stripped: %q", got)
	}
	if strings.Contains(got, "Hello") {
		t.Errorf("not lowercased: %q", got)
	}
	if !strings.Contains(got, "hello world") {
		t.Errorf("text/whitespace not normalized: %q", got)
	}

	// High-entropy noise must be dropped so cosmetic churn does not move the hash.
	noisy := []struct {
		name string
		in   string
	}{
		{"csrf token value", `<input name="csrf_token" value="9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c">`},
		{"hex run", "deadbeefdeadbeefdeadbeef0123"},
		{"iso timestamp", "generated at 2026-06-16T11:52:03Z"},
		{"epoch", "ts=1718539923"},
		{"nonce attr", `<script nonce="aGVsbG9ub25jZXZhbHVlMTIz"></script>`},
	}
	for _, n := range noisy {
		t.Run(n.name, func(t *testing.T) {
			out := normalizeBody(n.in)
			if hasLongToken(out) {
				t.Errorf("high-entropy noise survived normalization: %q -> %q", n.in, out)
			}
		})
	}
}

// hasLongToken reports whether any whitespace-separated token is a >=16-char
// hex/base64-ish run — the kind of value normalizeBody is meant to scrub.
func hasLongToken(s string) bool {
	for _, tok := range strings.Fields(s) {
		if len(tok) >= 16 && isHexOrBase64(tok) {
			return true
		}
	}
	return false
}

func isHexOrBase64(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '+' || r == '/' || r == '=' || r == '-' || r == '_':
		default:
			return false
		}
	}
	return true
}

func TestSimhashStability(t *testing.T) {
	// Two renders of the same page that differ ONLY in a rotated CSRF token and
	// a timestamp must hash within the diff threshold (read as "same page").
	pageA := `<html><body><h1>Account Settings</h1>
		<form action="/save"><input type="hidden" name="csrf" value="aaaa1111bbbb2222cccc3333dddd4444">
		<label>Email</label><input name="email"></form>
		<footer>rendered 2026-06-16T10:00:00Z</footer></body></html>`
	pageB := `<html><body><h1>Account Settings</h1>
		<form action="/save"><input type="hidden" name="csrf" value="9999zzzz8888yyyy7777xxxx6666wwww">
		<label>Email</label><input name="email"></form>
		<footer>rendered 2026-06-16T13:37:42Z</footer></body></html>`

	ha := simhash(shingles(normalizeBody(pageA)))
	hb := simhash(shingles(normalizeBody(pageB)))
	if d := bits.OnesCount64(ha ^ hb); d > 12 {
		t.Errorf("cosmetic-only change moved simhash too far: Δ%d/64 (want <= 12)", d)
	}

	// A genuinely different page (an app where an error page used to be) must
	// move the simhash well past the threshold.
	errPage := normalizeBody(`<html><body><h1>404 Not Found</h1><p>The requested URL was not found on this server.</p></body></html>`)
	appPage := normalizeBody(`<html><body><nav>Dashboard Reports Users Settings Billing</nav>
		<main><h1>Welcome back</h1><table><tr><td>Invoice</td><td>Amount</td></tr></table>
		<button>Create new project</button></main></body></html>`)
	he := simhash(shingles(errPage))
	hp := simhash(shingles(appPage))
	if d := bits.OnesCount64(he ^ hp); d <= 12 {
		t.Errorf("genuinely different pages should move simhash past threshold, got Δ%d/64", d)
	}
}

func TestSimhashEmptyIsZero(t *testing.T) {
	if h := simhash(nil); h != 0 {
		t.Errorf("simhash of no tokens must be 0 (so a failed fetch reads as empty), got %#x", h)
	}
	if h := simhash(shingles(normalizeBody("   <html></html>  "))); h != 0 {
		t.Errorf("simhash of an empty normalized body must be 0, got %#x", h)
	}
}
