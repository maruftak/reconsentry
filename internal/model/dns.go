package model

// DNSRecord is a single DNS record observed for a host. It is collected on
// demand (the --dns stage) and persisted per run so record changes can be
// diffed run-over-run. Only security-relevant record types are tracked: CNAME
// (infra move / takeover precursor) and NS (zone-delegation change).
type DNSRecord struct {
	Host  string `json:"host"`
	Type  string `json:"type"`  // "CNAME" | "NS"
	Value string `json:"value"` // canonical target / nameserver, lowercased, no trailing dot
}
