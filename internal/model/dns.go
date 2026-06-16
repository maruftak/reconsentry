package model

// DNSRecord is a single DNS record observed for a host. It is collected on
// demand (the --dns stage) and persisted per run so record changes can be
// diffed run-over-run. Only security-relevant record types are tracked: CNAME
// (infra move / takeover precursor), NS (zone-delegation change), MX (mail-flow
// change), and TXT (SPF / DMARC / SaaS-verification posture). DMARC TXT records
// are stored under the "_dmarc.<host>" name so email-auth posture can be diffed.
type DNSRecord struct {
	Host  string `json:"host"`
	Type  string `json:"type"`  // "CNAME" | "NS" | "MX" | "TXT"
	Value string `json:"value"` // CNAME/NS/MX: host, lowercased, no trailing dot. TXT: verbatim string.
}
