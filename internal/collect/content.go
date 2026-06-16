package collect

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"hash/fnv"
	"regexp"
	"strings"

	"github.com/maruftak/reconsentry/internal/model"
)

// contentLine models the subset of `httpx -json` output the content
// fingerprinter consumes. Field tags match ProjectDiscovery httpx's Result
// struct: the response body is `body` (emitted with -include-response), the
// mmh3 favicon hash is `favicon` (emitted with -favicon), and `response` is the
// full raw response read as a body fallback across httpx versions.
type contentLine struct {
	Input      string `json:"input"`
	URL        string `json:"url"`
	Host       string `json:"host"`
	StatusCode int    `json:"status_code"`
	Title      string `json:"title"`
	Favicon    string `json:"favicon"`
	Body       string `json:"body"`
	Response   string `json:"response"`
	Failed     bool   `json:"failed"`
}

// ContentFingerprints probes live hosts and returns a stable fingerprint of the
// page each serves: HTTP status, the mmh3 favicon hash (when httpx supplies
// one), a 64-bit simhash of the normalized body, and a hash of the page title.
// It fetches response bodies, so it is active HTTP traffic — the runner only
// invokes it for non-passive scopes. A host that fails to serve is returned as
// a zero-value fingerprint (host only) so the runner still sees it without it
// tripping a spurious change.
func ContentFingerprints(ctx context.Context, hosts []string) ([]model.ContentFingerprint, error) {
	if len(hosts) == 0 {
		return nil, nil
	}
	if err := ensure("httpx"); err != nil {
		return nil, err
	}
	args := []string{
		"-json", "-silent", "-no-color",
		"-status-code", "-title", "-favicon", "-include-response",
	}
	out, err := runStdin(ctx, strings.Join(hosts, "\n"), "httpx", args...)
	if err != nil {
		return nil, err
	}
	return parseContent(out), nil
}

// parseContent converts httpx JSONL output into content fingerprints. Pure, so
// it is unit-tested without invoking httpx.
func parseContent(b []byte) []model.ContentFingerprint {
	var fps []model.ContentFingerprint
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var l contentLine
		if err := json.Unmarshal([]byte(line), &l); err != nil {
			continue
		}
		name := l.Input
		if name == "" {
			name = l.Host
		}
		if name == "" {
			name = hostFromURL(l.URL)
		}
		name = cleanHost(name)
		if name == "" {
			continue
		}
		// A host that did not serve is a zero-value fingerprint (host only):
		// the diff skips it, so a transient outage never clobbers the baseline.
		if l.Failed {
			fps = append(fps, model.ContentFingerprint{Host: name})
			continue
		}
		body := l.Body
		if body == "" {
			body = l.Response // fall back to the raw response when body isn't separate
		}
		fps = append(fps, model.ContentFingerprint{
			Host:        name,
			Status:      l.StatusCode,
			FaviconHash: strings.TrimSpace(l.Favicon),
			SimHash:     simhash(shingles(normalizeBody(body))),
			TitleHash:   titleHash(l.Title),
		})
	}
	return fps
}

// noise patterns scrubbed from the body before shingling so cosmetic, per-render
// values (CSRF tokens, nonces, timestamps, long hex/base64 runs, epoch seconds)
// do not move the simhash. Stripped to a single space so surrounding structure
// is preserved.
var (
	reTag       = regexp.MustCompile(`(?s)<[^>]*>`) // any HTML tag (incl. <script>...> open)
	reISOTime   = regexp.MustCompile(`\d{4}-\d{2}-\d{2}t?\d{0,2}:?\d{0,2}:?\d{0,2}z?`)
	reEpoch     = regexp.MustCompile(`\d{10,}`)            // unix epochs and other long digit runs
	reLongToken = regexp.MustCompile(`[a-z0-9+/=_-]{16,}`) // hex / base64 / token runs (>= 16 chars)
	reWS        = regexp.MustCompile(`\s+`)
)

// normalizeBody turns a raw HTML response into stable, lowercased plain text
// with high-entropy noise removed, ready for shingling. Pure and deterministic.
// Order matters: lowercase first (so the regexes are case-insensitive by
// construction), strip tags to text, scrub timestamps/epochs/long tokens, then
// collapse whitespace.
func normalizeBody(body string) string {
	s := strings.ToLower(body)
	s = reTag.ReplaceAllString(s, " ")
	s = reISOTime.ReplaceAllString(s, " ")
	s = reEpoch.ReplaceAllString(s, " ")
	s = reLongToken.ReplaceAllString(s, " ")
	s = reWS.ReplaceAllString(s, " ")
	return strings.TrimSpace(s)
}

// shingleSize is the word n-gram width used to build shingles. 3-grams capture
// local phrasing so reordered boilerplate does not collapse to the same set,
// while staying robust to a single inserted/removed word.
const shingleSize = 3

// shingles tokenizes normalized text into overlapping word 3-grams. A body with
// fewer than shingleSize words yields one shingle of all its words (so short
// pages still fingerprint); an empty body yields no shingles (simhash 0).
func shingles(text string) []string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return nil
	}
	if len(words) < shingleSize {
		return []string{strings.Join(words, " ")}
	}
	out := make([]string, 0, len(words)-shingleSize+1)
	for i := 0; i+shingleSize <= len(words); i++ {
		out = append(out, strings.Join(words[i:i+shingleSize], " "))
	}
	return out
}

// simhash computes the 64-bit Charikar simhash of the tokens: each token is
// hashed with 64-bit FNV-1a, and for every bit position a +1/-1 vote is summed
// across tokens; the output bit is set where the sum is positive. Near-identical
// token sets share most bits (small Hamming distance). Pure and deterministic;
// no tokens -> 0 (so a failed/empty fetch reads as "no fingerprint").
func simhash(tokens []string) uint64 {
	if len(tokens) == 0 {
		return 0
	}
	var vec [64]int
	for _, tok := range tokens {
		h := fnv.New64a()
		_, _ = h.Write([]byte(tok))
		sum := h.Sum64()
		for i := 0; i < 64; i++ {
			if sum&(1<<uint(i)) != 0 {
				vec[i]++
			} else {
				vec[i]--
			}
		}
	}
	var out uint64
	for i := 0; i < 64; i++ {
		if vec[i] > 0 {
			out |= 1 << uint(i)
		}
	}
	return out
}

// titleHash returns a short, stable hash of the trimmed/lowercased page title,
// or "" for an empty title. The title is a cheap corroborating signal; the full
// string is not stored.
func titleHash(title string) string {
	t := strings.ToLower(strings.TrimSpace(model.TrimInvisible(title)))
	if t == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:8]) // 16 hex chars is plenty to detect a flip
}
