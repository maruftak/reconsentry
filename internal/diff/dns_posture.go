package diff

import "strings"

// txtPosture decides the priority of a TXT_CHANGE by inspecting email-auth
// posture. DMARC lives at the _dmarc.<host> name, so a change there is judged
// by DMARC policy; everything else is judged by SPF. A change that weakens
// authentication escalates Low → High and returns a human-readable note;
// otherwise it stays Low with an empty note. Pure function.
func txtPosture(host string, prevVals, currVals map[string]bool) (int, string) {
	if strings.HasPrefix(host, "_dmarc.") {
		if dmarcWeakened(prevVals, currVals) {
			return High, "DMARC weakened"
		}
		return Low, ""
	}
	if spfWeakened(prevVals, currVals) {
		return High, "SPF weakened"
	}
	return Low, ""
}

// spfWeakened reports whether the SPF posture in curr is weaker than in prev:
// a v=spf1 record present before is now gone, or its terminal `all` qualifier
// softened (strict → lax). A new SPF where there was none does not weaken.
func spfWeakened(prev, curr map[string]bool) bool {
	prevSPF, prevOK := findRecord(prev, "v=spf1")
	currSPF, currOK := findRecord(curr, "v=spf1")
	if !prevOK {
		return false // no SPF before, so nothing to weaken
	}
	if !currOK {
		return true // SPF removed
	}
	return spfAllRank(currSPF) < spfAllRank(prevSPF)
}

// dmarcWeakened reports whether the DMARC posture in curr is weaker than in
// prev: a v=DMARC1 record present before is now gone, or its p= policy softened
// (reject → quarantine → none). A new DMARC where there was none does not weaken.
func dmarcWeakened(prev, curr map[string]bool) bool {
	prevD, prevOK := findRecord(prev, "v=dmarc1")
	currD, currOK := findRecord(curr, "v=dmarc1")
	if !prevOK {
		return false // no DMARC before, so nothing to weaken
	}
	if !currOK {
		return true // DMARC removed
	}
	return dmarcPolicyRank(currD) < dmarcPolicyRank(prevD)
}

// findRecord returns the first value (and true) whose lowercased form starts
// with prefix. Used to locate the SPF / DMARC record within a TXT value set.
func findRecord(vals map[string]bool, prefix string) (string, bool) {
	for v := range vals {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(v)), prefix) {
			return v, true
		}
	}
	return "", false
}

// spfAllRank scores the terminal `all` mechanism's qualifier by strictness
// (higher = stricter): -all(4) > ~all(3) > ?all(2) > +all(1) > absent(0).
func spfAllRank(spf string) int {
	s := strings.ToLower(spf)
	switch {
	case strings.Contains(s, "-all"):
		return 4
	case strings.Contains(s, "~all"):
		return 3
	case strings.Contains(s, "?all"):
		return 2
	case strings.Contains(s, "+all"), strings.Contains(s, " all"):
		// `+all` is the explicit pass-everything qualifier; a bare `all` (no
		// leading qualifier) defaults to `+all` per RFC 7208.
		return 1
	default:
		return 0
	}
}

// dmarcPolicyRank scores the DMARC p= policy by strictness (higher = stricter):
// reject(3) > quarantine(2) > none(1) > absent(0).
func dmarcPolicyRank(dmarc string) int {
	switch dmarcPolicy(dmarc) {
	case "reject":
		return 3
	case "quarantine":
		return 2
	case "none":
		return 1
	default:
		return 0
	}
}

// dmarcPolicy extracts the p= tag value (lowercased) from a DMARC record, or ""
// when absent. DMARC tags are ';'-separated "name=value" pairs.
func dmarcPolicy(dmarc string) string {
	for _, part := range strings.Split(dmarc, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), "p=") {
			return strings.ToLower(strings.TrimSpace(part[len("p="):]))
		}
	}
	return ""
}
