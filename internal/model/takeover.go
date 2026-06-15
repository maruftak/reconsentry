package model

// HostProbe is the takeover-relevant view of a host: its CNAME chain and the
// HTTP signal used to match a service fingerprint. It is collected on demand
// (the --takeover stage) and never persisted — takeover risk is evaluated
// against the live response each run, like certificate expiry.
type HostProbe struct {
	Host   string   `json:"host"`
	CNAMEs []string `json:"cnames,omitempty"` // CNAME chain, if any
	Body   string   `json:"-"`                // response body preview; not serialized (can be large)
	Status int      `json:"status,omitempty"`
	Failed bool     `json:"failed,omitempty"` // host did not serve an HTTP response
}

// TakeoverFinding is a detected dangling-record risk for a host. It is a RISK
// indicator requiring manual confirmation, never an assertion of compromise —
// the phrasing in Detail reflects that.
type TakeoverFinding struct {
	Host       string `json:"host"`
	Service    string `json:"service"`         // matched third-party service, e.g. "GitHub Pages"
	CNAME      string `json:"cname,omitempty"` // the matched dangling CNAME
	Confidence string `json:"confidence"`      // "high" (cname + fingerprint) | "low" (fingerprint only)
	Vulnerable bool   `json:"vulnerable"`      // service is known to be claimable (vs. merely parked)
	Detail     string `json:"detail"`
}
