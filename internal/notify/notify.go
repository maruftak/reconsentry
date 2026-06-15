// Package notify delivers change alerts to webhooks (generic, Slack, or Discord).
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/smtp"
	neturl "net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/maruftak/reconsentry/internal/diff"
)

// maxAttempts bounds delivery retries for transient failures.
const maxAttempts = 3

// Notifier delivers a batch of changes for a scope.
type Notifier interface {
	Notify(ctx context.Context, scope string, changes []diff.Change) error
}

// Webhook posts changes to a single webhook URL using the given format.
type Webhook struct {
	URL    string
	Format string // "generic" | "slack" | "discord"
	Client *http.Client
}

// NewWebhook builds a Webhook notifier. An empty format defaults to "generic".
func NewWebhook(url, format string) *Webhook {
	if format == "" {
		format = "generic"
	}
	return &Webhook{URL: url, Format: format, Client: &http.Client{Timeout: 15 * time.Second}}
}

// Notify posts the changes, retrying transient failures with backoff. It is a
// no-op when there are no changes.
func (w *Webhook) Notify(ctx context.Context, scope string, changes []diff.Change) error {
	if len(changes) == 0 {
		return nil
	}
	body, err := w.payload(scope, changes)
	if err != nil {
		return fmt.Errorf("build payload: %w", err)
	}
	return deliver(ctx, w.Client, w.URL, body)
}

// deliver posts a JSON body to url with bounded retries on transient failures.
func deliver(ctx context.Context, client *http.Client, url string, body []byte) error {
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		lastErr = postOnce(ctx, client, url, body)
		if lastErr == nil {
			return nil
		}
		if !retryable(lastErr) || attempt == maxAttempts {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(attempt) * 500 * time.Millisecond):
		}
	}
	return lastErr
}

// postOnce performs a single JSON POST.
func postOnce(ctx context.Context, client *http.Client, url string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		// Drop the URL from transport errors: it can embed a secret — a Telegram
		// bot token in the path, or a Slack/Discord webhook URL that is itself a
		// credential. The caller already knows which destination it targeted.
		var ue *neturl.Error
		if errors.As(err, &ue) {
			return fmt.Errorf("post failed: %w", ue.Err)
		}
		return fmt.Errorf("post failed: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body) // drain so the connection can be reused
	if resp.StatusCode >= 300 {
		return &httpError{status: resp.StatusCode}
	}
	return nil
}

// httpError carries a non-2xx response status so retryable can classify it.
type httpError struct{ status int }

func (e *httpError) Error() string { return fmt.Sprintf("webhook returned status %d", e.status) }

// retryable reports whether err is worth another attempt: transport errors and
// 429/5xx responses are; 4xx (bad URL, auth) are not.
func retryable(err error) bool {
	var he *httpError
	if errors.As(err, &he) {
		return he.status == http.StatusTooManyRequests || he.status >= 500
	}
	return true
}

func (w *Webhook) payload(scope string, changes []diff.Change) ([]byte, error) {
	switch w.Format {
	case "slack":
		return json.Marshal(renderSlack(scope, changes))
	case "discord":
		return json.Marshal(renderDiscord(scope, changes))
	default:
		return json.Marshal(map[string]any{
			"scope":   scope,
			"count":   len(changes),
			"changes": changes,
		})
	}
}

// Platform payload limits. Slack rejects a section whose mrkdwn text exceeds
// 3000 chars or a message with more than 50 blocks; Discord rejects an embed
// field value over 1024 chars or an embed with more than 25 fields. We render
// well under those caps and truncate gracefully so a large diff still delivers.
const (
	slackSectionLimit = 2900
	slackMaxBlocks    = 50
	discordFieldLimit = 1000
	discordMaxFields  = 25
)

// priorityGroup is a non-empty set of changes sharing a normalized priority.
type priorityGroup struct {
	priority int
	changes  []diff.Change
}

// groupByPriority buckets changes high → medium → low, preserving input order
// within each bucket and omitting empty buckets. Any unexpected priority value
// normalizes into the low bucket so no change is ever dropped.
func groupByPriority(changes []diff.Change) []priorityGroup {
	order := []int{diff.Critical, diff.High, diff.Medium, diff.Low}
	idx := map[int]int{diff.Critical: 0, diff.High: 1, diff.Medium: 2, diff.Low: 3}
	buckets := make([][]diff.Change, len(order))
	for _, c := range changes {
		buckets[idx[normalizePriority(c.Priority)]] = append(buckets[idx[normalizePriority(c.Priority)]], c)
	}
	var groups []priorityGroup
	for i, p := range order {
		if len(buckets[i]) > 0 {
			groups = append(groups, priorityGroup{priority: p, changes: buckets[i]})
		}
	}
	return groups
}

func normalizePriority(p int) int {
	switch p {
	case diff.Critical:
		return diff.Critical
	case diff.High:
		return diff.High
	case diff.Medium:
		return diff.Medium
	default:
		return diff.Low
	}
}

func priorityEmoji(p int) string {
	switch normalizePriority(p) {
	case diff.Critical:
		return "🚨"
	case diff.High:
		return "🔴"
	case diff.Medium:
		return "🟠"
	default:
		return "⚪"
	}
}

// chunkLines packs lines into chunks whose newline-joined length stays within
// limit. A single oversized line is rune-safely truncated rather than dropped.
func chunkLines(lines []string, limit int) []string {
	var chunks []string
	var b strings.Builder
	for _, ln := range lines {
		ln = truncate(ln, limit)
		if b.Len() > 0 && b.Len()+1+len(ln) > limit {
			chunks = append(chunks, b.String())
			b.Reset()
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(ln)
	}
	if b.Len() > 0 {
		chunks = append(chunks, b.String())
	}
	return chunks
}

// truncate shortens s to at most max bytes, ending on a rune boundary and
// appending an ellipsis when it cuts.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max - len("…")
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

func renderSlack(scope string, changes []diff.Change) map[string]any {
	blocks := []map[string]any{{
		"type": "header",
		"text": map[string]string{
			"type": "plain_text",
			"text": fmt.Sprintf("reconsentry: %d change(s) on %s", len(changes), scope),
		},
	}}
	blocks = append(blocks, slackChangeBlocks(changes)...)
	blocks = capSlackBlocks(blocks)
	return map[string]any{
		"text": RenderText(scope, changes),
		"attachments": []map[string]any{{
			"color":  priorityColor(maxPriority(changes)),
			"blocks": blocks,
		}},
	}
}

// slackChangeBlocks renders one or more mrkdwn section blocks per priority
// group, each capped to Slack's per-section character limit.
func slackChangeBlocks(changes []diff.Change) []map[string]any {
	var blocks []map[string]any
	for _, g := range groupByPriority(changes) {
		header := fmt.Sprintf("%s *%s priority — %d*", priorityEmoji(g.priority), priorityName(g.priority), len(g.changes))
		lines := []string{header}
		for _, c := range g.changes {
			lines = append(lines, slackLine(c))
		}
		for _, chunk := range chunkLines(lines, slackSectionLimit) {
			blocks = append(blocks, map[string]any{
				"type": "section",
				"text": map[string]string{"type": "mrkdwn", "text": chunk},
			})
		}
	}
	return blocks
}

func slackLine(c diff.Change) string {
	return fmt.Sprintf("• *%s* · %s — %s", c.Kind, slackHost(c.Host), c.Detail)
}

// capSlackBlocks keeps the block list within Slack's per-message limit,
// replacing the overflow tail with a context note.
func capSlackBlocks(blocks []map[string]any) []map[string]any {
	if len(blocks) <= slackMaxBlocks {
		return blocks
	}
	kept := blocks[:slackMaxBlocks-1]
	dropped := len(blocks) - (slackMaxBlocks - 1)
	note := map[string]any{
		"type": "context",
		"elements": []map[string]any{{
			"type": "mrkdwn",
			"text": fmt.Sprintf("_…and %d more block(s) truncated to fit Slack's limit_", dropped),
		}},
	}
	return append(kept, note)
}

func renderDiscord(scope string, changes []diff.Change) map[string]any {
	return map[string]any{
		"content": RenderText(scope, changes),
		"embeds": []map[string]any{{
			"title":  fmt.Sprintf("reconsentry: %d change(s) on %s", len(changes), scope),
			"color":  priorityColorInt(maxPriority(changes)),
			"fields": discordFields(changes),
		}},
	}
}

// discordFields renders one or more embed fields per priority group, each value
// capped to Discord's per-field limit, with the field count capped overall.
func discordFields(changes []diff.Change) []map[string]any {
	var fields []map[string]any
	for _, g := range groupByPriority(changes) {
		lines := make([]string, 0, len(g.changes))
		for _, c := range g.changes {
			lines = append(lines, discordLine(c))
		}
		for i, chunk := range chunkLines(lines, discordFieldLimit) {
			name := fmt.Sprintf("%s %s (%d)", priorityEmoji(g.priority), priorityName(g.priority), len(g.changes))
			if i > 0 {
				name = fmt.Sprintf("%s %s (cont.)", priorityEmoji(g.priority), priorityName(g.priority))
			}
			fields = append(fields, map[string]any{"name": name, "value": chunk, "inline": false})
		}
	}
	return capDiscordFields(fields)
}

func discordLine(c diff.Change) string {
	if c.Host == "" {
		return fmt.Sprintf("• **%s** — %s", c.Kind, c.Detail)
	}
	return fmt.Sprintf("• **%s** · %s — %s", c.Kind, discordHost(c.Host), c.Detail)
}

// capDiscordFields keeps the field list within Discord's per-embed limit,
// replacing the overflow tail with a summary field.
func capDiscordFields(fields []map[string]any) []map[string]any {
	if len(fields) <= discordMaxFields {
		return fields
	}
	kept := fields[:discordMaxFields-1]
	dropped := len(fields) - (discordMaxFields - 1)
	note := map[string]any{
		"name":   "…truncated",
		"value":  fmt.Sprintf("%d more field(s) omitted to fit Discord's 25-field limit", dropped),
		"inline": false,
	}
	return append(kept, note)
}

func slackHost(host string) string {
	if host == "" {
		return "unknown host"
	}
	return fmt.Sprintf("<https://%s|%s>", host, host)
}

func discordHost(host string) string {
	if host == "" {
		return "unknown host"
	}
	return fmt.Sprintf("[%s](https://%s)", host, host)
}

func maxPriority(changes []diff.Change) int {
	max := diff.Low
	for _, c := range changes {
		if c.Priority > max {
			max = c.Priority
		}
	}
	return max
}

func priorityName(p int) string {
	switch p {
	case diff.Critical:
		return "critical"
	case diff.High:
		return "high"
	case diff.Medium:
		return "medium"
	default:
		return "low"
	}
}

func priorityColor(p int) string {
	switch p {
	case diff.Critical:
		return "#b31d28"
	case diff.High:
		return "#d73a49"
	case diff.Medium:
		return "#d29922"
	default:
		return "#57606a"
	}
}

func priorityColorInt(p int) int {
	switch p {
	case diff.Critical:
		return 0xb31d28
	case diff.High:
		return 0xd73a49
	case diff.Medium:
		return 0xd29922
	default:
		return 0x57606a
	}
}

// Telegram delivers alerts via the Telegram Bot API (sendMessage).
type Telegram struct {
	Token   string
	ChatID  string
	BaseURL string // defaults to https://api.telegram.org; overridable for tests
	Client  *http.Client
}

// NewTelegram builds a Telegram notifier for a bot token and chat id.
func NewTelegram(token, chatID string) *Telegram {
	return &Telegram{
		Token:   token,
		ChatID:  chatID,
		BaseURL: "https://api.telegram.org",
		Client:  &http.Client{Timeout: 15 * time.Second},
	}
}

// Notify sends the changes as a Telegram message. It is a no-op when there are
// no changes.
func (t *Telegram) Notify(ctx context.Context, scope string, changes []diff.Change) error {
	if len(changes) == 0 {
		return nil
	}
	body, err := json.Marshal(map[string]string{
		"chat_id": t.ChatID,
		"text":    RenderText(scope, changes),
	})
	if err != nil {
		return fmt.Errorf("build payload: %w", err)
	}
	base := t.BaseURL
	if base == "" {
		base = "https://api.telegram.org"
	}
	return deliver(ctx, t.Client, base+"/bot"+t.Token+"/sendMessage", body)
}

// Email delivers alerts over SMTP.
type Email struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	To       []string
	send     func(addr string, a smtp.Auth, from string, to []string, msg []byte) error
}

// NewEmail builds an SMTP email notifier. Port defaults to 587 (submission).
func NewEmail(host string, port int, username, password, from string, to []string) *Email {
	if port == 0 {
		port = 587
	}
	return &Email{
		Host:     host,
		Port:     port,
		Username: username,
		Password: password,
		From:     from,
		To:       to,
		send:     smtp.SendMail,
	}
}

// Notify emails the changes. It is a no-op when there are no changes.
func (e *Email) Notify(ctx context.Context, scope string, changes []diff.Change) error {
	if len(changes) == 0 {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	subject := fmt.Sprintf("reconsentry: %d change(s) on %s", len(changes), scope)
	msg := buildEmail(e.From, e.To, subject, RenderText(scope, changes))

	var auth smtp.Auth
	if e.Username != "" {
		auth = smtp.PlainAuth("", e.Username, e.Password, e.Host)
	}
	send := e.send
	if send == nil {
		send = smtp.SendMail
	}
	if err := send(fmt.Sprintf("%s:%d", e.Host, e.Port), auth, e.From, e.To, msg); err != nil {
		return fmt.Errorf("send email: %w", err)
	}
	return nil
}

// buildEmail assembles a minimal RFC 5322 plain-text message.
func buildEmail(from string, to []string, subject, body string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)
	b.WriteString("\r\n")
	return []byte(b.String())
}

// RenderText builds a human-readable multi-line summary of the changes,
// appending a clickable URL per host so an alert is actionable at a glance.
func RenderText(scope string, changes []diff.Change) string {
	var b strings.Builder
	fmt.Fprintf(&b, "reconsentry: %d change(s) on %s", len(changes), scope)
	for _, c := range changes {
		fmt.Fprintf(&b, "\n• [%s] %s — %s", c.Kind, c.Host, c.Detail)
		if c.Host != "" {
			fmt.Fprintf(&b, " (https://%s)", c.Host)
		}
	}
	return b.String()
}
