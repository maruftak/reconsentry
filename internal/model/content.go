package model

// ContentFingerprint is a stable, noise-resistant summary of the page a host
// serves. It is collected on demand (the --content stage) and persisted per run
// so a *material* content change — a re-platform, a newly-exposed login/admin
// page, an error page replaced by a real app, a host coming online — can be
// diffed run-over-run without firing on cosmetic noise (CSRF tokens,
// timestamps, nonces).
//
// SimHash is a 64-bit simhash of the normalized body text: near-identical pages
// share most bits, so a small Hamming distance means "same page", a large one
// means the content genuinely moved. FaviconHash is httpx's mmh3 favicon hash
// when available (empty otherwise — a re-skin often swaps the favicon first).
// TitleHash corroborates a body move but never triggers a change on its own.
type ContentFingerprint struct {
	Target      string `json:"target,omitempty"`
	Host        string `json:"host"`
	Status      int    `json:"status,omitempty"`
	FaviconHash string `json:"favicon_hash,omitempty"`
	SimHash     uint64 `json:"simhash"`
	TitleHash   string `json:"title_hash,omitempty"`
}
