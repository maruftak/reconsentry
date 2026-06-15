// Package report renders run results into machine-readable formats. SARIF lets
// reconsentry's change feed flow into CI code-scanning dashboards (e.g. GitHub
// Advanced Security) alongside other static-analysis tools.
package report

import (
	"encoding/json"

	"github.com/maruftak/reconsentry/internal/diff"
)

const (
	sarifSchema  = "https://json.schemastore.org/sarif-2.1.0.json"
	sarifVersion = "2.1.0"
	toolName     = "reconsentry"
	toolURI      = "https://github.com/maruftak/reconsentry"
)

// ScopeChanges pairs a scope name with its changes for one run cycle.
type ScopeChanges struct {
	Scope   string
	Changes []diff.Change
}

// SARIF renders the given scopes as a single SARIF 2.1.0 document with one run
// per scope. Each change becomes a result; its Kind is the ruleId and its
// priority maps to a SARIF level.
func SARIF(scopes []ScopeChanges) ([]byte, error) {
	runs := make([]sarifRun, 0, len(scopes))
	for _, sc := range scopes {
		runs = append(runs, buildRun(sc))
	}
	doc := sarifDoc{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs:    runs,
	}
	return json.MarshalIndent(doc, "", "  ")
}

func buildRun(sc ScopeChanges) sarifRun {
	rules := make([]sarifRule, 0)
	seenRule := map[string]bool{}
	results := make([]sarifResult, 0, len(sc.Changes))

	for _, c := range sc.Changes {
		ruleID := string(c.Kind)
		if !seenRule[ruleID] {
			seenRule[ruleID] = true
			rules = append(rules, sarifRule{ID: ruleID, Name: ruleID})
		}
		results = append(results, sarifResult{
			RuleID:  ruleID,
			Level:   levelFor(c.Priority),
			Message: sarifMessage{Text: messageText(c)},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: artifactURI(c)},
				},
			}},
			Properties: sarifResultProps{Scope: sc.Scope, Priority: c.Priority},
		})
	}

	return sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name:           toolName,
			InformationURI: toolURI,
			Rules:          rules,
		}},
		Results: results,
	}
}

// levelFor maps a reconsentry priority to a SARIF result level.
func levelFor(priority int) string {
	switch priority {
	case diff.Critical, diff.High:
		return "error"
	case diff.Medium:
		return "warning"
	default:
		return "note"
	}
}

func messageText(c diff.Change) string {
	if c.Host == "" {
		return c.Detail
	}
	if c.Detail == "" {
		return c.Host
	}
	return c.Host + " — " + c.Detail
}

// artifactURI gives each result a stable location. Host-bearing changes use an
// https URI; hostless ones fall back to the scope-relative tool name.
func artifactURI(c diff.Change) string {
	if c.Host == "" {
		return toolName
	}
	return "https://" + c.Host
}

type sarifDoc struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type sarifResult struct {
	RuleID     string           `json:"ruleId"`
	Level      string           `json:"level"`
	Message    sarifMessage     `json:"message"`
	Locations  []sarifLocation  `json:"locations"`
	Properties sarifResultProps `json:"properties"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifResultProps struct {
	Scope    string `json:"scope"`
	Priority int    `json:"priority"`
}
